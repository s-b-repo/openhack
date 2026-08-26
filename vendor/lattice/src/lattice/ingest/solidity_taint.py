"""TIER-3 ingest — ORACLE / SPOT-PRICE taint for the trust operator (lattice.taint).

The operator (`trust_obstructions` in lattice/taint.py) is a monotone taint fixpoint over a value
DEPENDENCY graph: a value is tainted if it derives from an attacker-controllable SOURCE and no
SANITIZER breaks the path; it FIRES when a tainted value reaches a trust-sensitive SINK. That operator
is built and unit-tested — this module is ONLY the per-function Solidity ingest that builds the graph
and classifies sources / sinks / sanitizers from a real solc-parsed AST, then calls the operator.

The bug class: a lending contract that prices collateral from a SPOT DEX read (`getReserves`,
`getAmountOut`, `balanceOf`, or arithmetic over reserve-named vars) and gates a loan/transfer on that
price is oracle-manipulable (flash-loan-skew the pool, get a bad valuation, drain). Reading the same
price from a TWAP / chainlink feed (`consult`, `latestRoundData`, ...) sanitizes the flow.

SCOPE (honest): INTRAPROCEDURAL. Dependencies, sources, sinks and sanitizers are all resolved within a
single function body. Cross-function / cross-contract price helpers are NOT followed — see module
docstring caveats and the limits reported by `oracle_taint_audit`'s callers.
"""
import pathlib

from lattice.ingest.solidity import _solc_ast, _iter, _base_names, _access_controlled, _sol_files
from lattice.taint import trust_obstructions, taint_propagate

# A member/function name whose call yields an attacker-movable SPOT read (no time-averaging).
# Extended in the accuracy sweep:
#   getPair    — Uniswap V2 factory call that returns the pool address (spot input if used
#                to read reserves that same block)
#   slot0      — Uniswap V3 pool state read; the sqrtPriceX96 in this struct is spot
#   observe    — a bare `observe(...)` on a V3 pool (raw cumulative ticks) is spot unless
#                paired with a time-window (`consult` normally does the time-weighting)
_SPOT_READS = ("getReserves", "getAmountOut", "getAmountsOut", "balanceOf",
               "getPair", "slot0", "observe")
# Substrings marking a TIME-AVERAGED / authenticated oracle read — these SANITIZE the flow.
# Extended:
#   getPriceFromSqrtRatio — helper that computes a price from a passed-in sqrt; if the sqrt
#                            itself came via a TWAP / observed accumulator it's sanitized
#   computeAmountOut       — canonical safe swap-quote helper that assumes reserves are OK
#   oracleObserve          — an explicit oracle-guarded observation wrapper
_SANITIZER_MARKS = ("twap", "consult", "latestRoundData", "chainlink", "getRoundData",
                    "getPriceFromSqrtRatio", "computeAmountOut", "oracleObserve")
# Substrings in a variable name that mark it as a raw-reserve quantity (a price computed from these
# without a TWAP is a spot price).
_RESERVE_MARKS = ("reserve", "reserves")
# Sink-defining value-moving primitives: a value used as an argument to one of these is a
# value-movement decision. `transferFrom` is included because the oracle-manipulation sink is often the
# COLLATERAL the borrower deposits — `weth.transferFrom(msg.sender, this, amount)` (a pull, not a push)
# — where a spot-tainted `amount` is exactly the bug (Damn-Vulnerable-DeFi `puppet-v2`). Recognition is
# TAINT-GATED: a transferFrom of a non-spot amount never fires, so this is not a blanket over-flag.
_TRANSFER_MEMBERS = ("transfer", "send", "transferFrom")
# Low-level call members that move value when given `{value: ...}`.
_VALUE_CALL_MEMBERS = ("call", "delegatecall")


def _names_in(expr) -> set:
    """Every Identifier `name` AND every called member/function name appearing anywhere in `expr`.

    This is the dependency footprint of a value: plain identifiers it reads, plus the NAMES of any
    member access or function it calls (so `pair.getReserves()` contributes both `pair` and
    `getReserves`, and a `twap()` call contributes `twap` — which lets sanitizer/source classification
    key off these names). Recurses through BinaryOperation, FunctionCall args + callee, casts, tuples,
    index/member access, and call-options uniformly via dict/list traversal.
    """
    out: set = set()
    if isinstance(expr, dict):
        nt = expr.get("nodeType")
        if nt == "Identifier":
            n = expr.get("name")
            if n:
                out.add(n)
        elif nt == "MemberAccess":
            mn = expr.get("memberName")
            if mn:
                out.add(mn)
        # Recurse into every child regardless of node type so nested calls/operands are all captured.
        for v in expr.values():
            out |= _names_in(v)
    elif isinstance(expr, list):
        for x in expr:
            out |= _names_in(x)
    return out


def _is_spot_priced(deps: set, fn_taint: dict | None = None) -> bool:
    """A value is a SPOT source if its dependency footprint names a spot DEX read OR a raw reserve var
    OR a call to an INTERNAL helper whose return value is spot-tainted (interprocedural)."""
    fn_taint = fn_taint or {}
    for d in deps:
        if d in _SPOT_READS:
            return True
        low = d.lower()
        if any(m in low for m in _RESERVE_MARKS):
            return True
        if fn_taint.get(d) == "tainted":     # value flows from a helper that returns a spot price
            return True
    return False


def _is_sanitized(deps: set, fn_taint: dict | None = None) -> bool:
    """A value is SANITIZED if it derives from a TWAP/chainlink/consult read OR from an INTERNAL
    helper whose return value is sanitized (interprocedural — a `getTwapPrice()` helper sanitizes)."""
    fn_taint = fn_taint or {}
    for d in deps:
        low = d.lower()
        if any(m.lower() in low for m in _SANITIZER_MARKS):
            return True
        if fn_taint.get(d) == "sanitized":
            return True
    return False


def _assigned_names(stmt) -> list:
    """The value name(s) a statement defines, or [] if it is not a definition.

    - VariableDeclarationStatement: each declared `name` (tuple decls declare several; `null` slots
      are unpacking holes and are skipped).
    - ExpressionStatement wrapping an Assignment `lhs = rhs`: the base identifier / member name of lhs.
    """
    nt = stmt.get("nodeType")
    if nt == "VariableDeclarationStatement":
        names = []
        for d in stmt.get("declarations") or []:
            if d and d.get("name"):
                names.append(d["name"])
        return names
    if nt == "ExpressionStatement":
        expr = stmt.get("expression") or {}
        if expr.get("nodeType") == "Assignment":
            lhs = expr.get("leftHandSide") or {}
            if lhs.get("nodeType") == "Identifier":
                return [lhs.get("name")] if lhs.get("name") else []
            if lhs.get("nodeType") == "MemberAccess":
                return [lhs.get("memberName")] if lhs.get("memberName") else []
    return []


def _defined_value_expr(stmt):
    """The RHS expression a definition statement assigns, else None."""
    nt = stmt.get("nodeType")
    if nt == "VariableDeclarationStatement":
        return stmt.get("initialValue")
    if nt == "ExpressionStatement":
        expr = stmt.get("expression") or {}
        if expr.get("nodeType") == "Assignment":
            return expr.get("rightHandSide")
    return None


def _start(node) -> int:
    return int((node.get("src") or "0:0:0").split(":")[0])


def _payout_positions(fn_node) -> list:
    """Source-start offsets of value-moving primitives (transfer/send/.call{value:}). A require/if is
    only a loan-decision SINK if a payout FOLLOWS it (it plausibly guards that payout) — a partial,
    document-order path-sensitivity that drops the unrelated-guarded-refund over-flag. A FULLY sound
    version (which `require` guards which transfer across branches) needs a control-flow graph."""
    out: list = []
    for fc in _iter(fn_node, "FunctionCall"):
        callee = fc.get("expression") or {}
        if callee.get("nodeType") == "MemberAccess" and callee.get("memberName") in _TRANSFER_MEMBERS:
            out.append(_start(fc))
        elif callee.get("nodeType") == "FunctionCallOptions":
            inner = callee.get("expression") or {}
            if (inner.get("nodeType") == "MemberAccess"
                    and inner.get("memberName") in _VALUE_CALL_MEMBERS
                    and "value" in (callee.get("names") or [])):
                out.append(_start(fc))
    return out


def _collect_sinks(fn_node, payout_pos: list) -> set:
    """Value names that reach a trust-sensitive SINK:
      - identifiers in a require/if condition, but ONLY when a payout follows the gate (it guards it);
      - identifiers passed to .transfer/.send or as the `{value:}` of a low-level call (the payout).
    """
    sinks: set = set()

    def _payout_after(guard) -> bool:
        g = _start(guard)
        return any(p > g for p in payout_pos)

    # (a) require / if condition gates — only when a payout FOLLOWS the gate.
    for ifs in _iter(fn_node, "IfStatement"):
        if _payout_after(ifs):
            sinks |= _names_in(ifs.get("condition"))
    for fc in _iter(fn_node, "FunctionCall"):
        callee = fc.get("expression") or {}
        if callee.get("nodeType") == "Identifier" and callee.get("name") in ("require", "assert"):
            args = fc.get("arguments") or []
            if args and _payout_after(fc):
                sinks |= _names_in(args[0])
    # (b) value-moving arguments — always a sink (the payout amount itself).
    for fc in _iter(fn_node, "FunctionCall"):
        callee = fc.get("expression") or {}
        if callee.get("nodeType") == "MemberAccess" and callee.get("memberName") in _TRANSFER_MEMBERS:
            for a in fc.get("arguments") or []:
                sinks |= _names_in(a)
        if callee.get("nodeType") == "FunctionCallOptions":
            inner = callee.get("expression") or {}
            if (inner.get("nodeType") == "MemberAccess"
                    and inner.get("memberName") in _VALUE_CALL_MEMBERS):
                for opt in callee.get("options") or []:
                    sinks |= _names_in(opt)
                for a in fc.get("arguments") or []:
                    sinks |= _names_in(a)
    return sinks


def _footprint(name, deps: dict, memo: dict) -> set:
    """Transitive dependency footprint of a value (all names it derives from, recursively)."""
    if name in memo:
        return memo[name]
    memo[name] = {name}                     # cycle guard
    acc = {name}
    for d in deps.get(name, ()):  # type: ignore[arg-type]
        acc.add(d)
        acc |= _footprint(d, deps, memo)
    memo[name] = acc
    return acc


def _graph(fn_node, fn_taint: dict):
    """Build one function's dependency graph, then classify by TRANSITIVE footprint: a value is a
    SOURCE if its footprint reaches a spot read (so `min(spot, twap)` — whose footprint reaches
    getReserves — is tainted, not wrongly sanitized by the `twap` name in it); a SANITIZER only if
    its footprint reaches a sanitizer read and NO spot read (the common external-TWAP `consult()`,
    whose footprint never touches this function's reserves). Interprocedural via fn_taint."""
    body = fn_node.get("body")
    deps: dict = {}
    sources: set = set()
    sanitizers: set = set()
    if not body:
        return deps, sources, sanitizers
    fn_taint = fn_taint or {}
    # pass 1 — build the dependency graph (no classification yet)
    stmts = list(_iter(body, "VariableDeclarationStatement"))
    stmts += [s for s in _iter(body, "ExpressionStatement")
              if (s.get("expression") or {}).get("nodeType") == "Assignment"]
    for stmt in stmts:
        names = _assigned_names(stmt)
        if not names:
            continue
        rhs = _defined_value_expr(stmt)
        d = _names_in(rhs) if rhs is not None else set()
        for n in names:
            deps[n] = set(deps.get(n, set())) | d
    # pass 2 — classify each value by its transitive footprint (spot wins over sanitizer)
    memo: dict = {}
    for n in deps:
        fp = _footprint(n, deps, memo)
        if _is_spot_priced(fp, fn_taint):
            sources.add(n)
        elif _is_sanitized(fp, fn_taint):
            sanitizers.add(n)
    return deps, sources, sanitizers


def _references_this(node) -> bool:
    """True if `this` appears anywhere under `node` (so `balanceOf(address(this))` is an OWN-balance read)."""
    if isinstance(node, dict):
        if node.get("nodeType") == "Identifier" and node.get("name") == "this":
            return True
        return any(_references_this(v) for v in node.values())
    if isinstance(node, list):
        return any(_references_this(x) for x in node)
    return False


def _has_non_self_spot(fn_node) -> bool:
    """Does the function contain a spot read that is a MANIPULABLE PRICE — a DEX read (getReserves/
    getAmountOut), a balanceOf of ANOTHER address (the pool), or a reserve-named var? `balanceOf(this)`
    alone is the contract's OWN amount, not a price (a price reads someone else's balance / a reserve)."""
    for fc in _iter(fn_node, "FunctionCall"):
        callee = fc.get("expression") or {}
        if callee.get("nodeType") == "MemberAccess":
            mn = callee.get("memberName")
            if mn in ("getReserves", "getAmountOut", "getAmountsOut"):
                return True
            if mn == "balanceOf" and not _references_this(fc.get("arguments")):
                return True                 # balanceOf of ANOTHER address = a manipulable spot read
    for idn in _iter(fn_node, "Identifier"):
        if any(m in (idn.get("name") or "").lower() for m in _RESERVE_MARKS):
            return True
    return False


def _analyze_function(fn_node, fn_taint: dict | None = None, downgrade_own_balance: bool = False) -> list[dict]:
    """Build the dependency graph for one function, classify S/S/S, run the operator.

    `downgrade_own_balance` (computed by the caller over the whole CONTRACT closure — interprocedural, so
    a spot read in a price HELPER still counts): when the contract has NO manipulable spot read anywhere
    (only balanceOf(address(this)) own-amount reads, the dominant Fei FP class), the finding is kept (no
    silent-FN — a donation/inflation vector may exist) but marked LOW confidence so the adjudicator
    deprioritizes it vs a real other-address/reserve oracle read."""
    fn_taint = fn_taint or {}
    dependencies, sources, sanitizers = _graph(fn_node, fn_taint)

    payout_pos = _payout_positions(fn_node)
    if not payout_pos:
        return []                       # no value-moving primitive — no trust sink to reach
    sinks = _collect_sinks(fn_node, payout_pos)
    if not sinks:
        return []

    findings = trust_obstructions(dependencies, sources, sinks, sanitizers)
    name = fn_node.get("name") or "<fallback>"
    ac = _access_controlled(fn_node)                # only a privileged caller can manipulate the price
    for f in findings:
        f["function"] = name
        if downgrade_own_balance:
            f["confidence"] = "low"
            f["severity"] = "low"
            f["detail"] = ("own balance (balanceOf(address(this))) flows to a value movement — the "
                           "contract's OWN amount, NOT a manipulable spot price; likely accounting. "
                           "Verify separately for donation/inflation. " + f.get("detail", ""))
        elif ac:
            f["confidence"] = "low"
            f["severity"] = "low"
            f["detail"] = (f"[access-controlled by '{ac}': only a privileged caller reaches this price "
                           f"path — lower exploitability] " + f.get("detail", ""))
    return findings


def _return_taint_of(fn_node, fn_taint: dict) -> str | None:
    """Classify a function's RETURN value: 'tainted' if a spot source reaches it (unsanitized),
    'sanitized' if it derives from a TWAP/oracle read, else None. Used to make taint INTERPROCEDURAL —
    a caller that does `p = getPrice(...)` then taints/sanitizes `p` by this verdict."""
    body = fn_node.get("body")
    if not body:
        return None
    deps, sources, sanitizers = _graph(fn_node, fn_taint)
    ret: set = set()
    for r in _iter(body, "Return"):
        ret |= _names_in(r.get("expression"))
    if not ret:
        return None
    # Classify the return by the TRANSITIVE FOOTPRINT of everything it reads, through the dep graph —
    # then apply the SAME rule _graph uses for an assigned value (spot wins over sanitizer). This is the
    # load-bearing fix for the real idiom: a price helper that RETURNS A SPOT READ INLINE
    # (`return pair.getReserves();` / `return a.balance/token.balanceOf(a);` — Damn-Vulnerable-DeFi
    # `puppet`) binds no intermediate local, so deps is empty and the OLD check (which only looked for a
    # tainted *local name* in the return) saw nothing and reported the helper clean — a silent FN that
    # cascaded up the whole call chain. The footprint of the return names themselves reaches the spot
    # read directly, so it is now correctly tainted.
    memo: dict = {}
    fp = set(ret)
    for n in ret:
        fp |= _footprint(n, deps, memo)
    if _is_spot_priced(fp, fn_taint):
        return "tainted"
    if _is_sanitized(fp, fn_taint):
        return "sanitized"
    return None


def _compute_return_taint(named: dict) -> dict:
    """Fixpoint over a {fn_name -> resolved FunctionDefinition} map: name -> 'tainted'/'sanitized'/None
    for its return value. `named` is the override-resolved set of functions VISIBLE to a contract."""
    taint: dict = {}
    for _ in range(len(named) + 2):
        changed = False
        for name, fn in named.items():
            verdict = _return_taint_of(fn, taint)
            if verdict != taint.get(name):
                taint[name] = verdict
                changed = True
        if not changed:
            break
    return taint


def _udt_in(node) -> set:
    """UserDefinedTypeName names anywhere under `node` (a typeName subtree), bare-name normalised."""
    out: set = set()
    if isinstance(node, dict):
        if node.get("nodeType") == "UserDefinedTypeName":
            n = node.get("name") or (node.get("pathNode") or {}).get("name")
            if n:
                out.add(n.split(".")[-1])
        for v in node.values():
            out |= _udt_in(v)
    elif isinstance(node, list):
        for x in node:
            out |= _udt_in(x)
    return out


def _referenced_types(contract) -> set:
    """The contract types this contract COMPOSES — declared as a state var or a function parameter
    (e.g. `IPriceModule priceModule;`). These are the external modules whose methods it calls."""
    out: set = set()
    for node in contract.get("nodes") or []:
        if node.get("nodeType") == "VariableDeclaration":
            out |= _udt_in(node.get("typeName"))
        elif node.get("nodeType") == "FunctionDefinition":
            for p in ((node.get("parameters") or {}).get("parameters") or []):
                out |= _udt_in(p.get("typeName"))
    return out


def _c3(cname: str, contracts: dict, cache: dict) -> list:
    """C3 linearization (the MRO Solidity uses) — most-derived first. Override resolution: the FIRST
    contract in this order that defines a method is the one that runs."""
    if cname in cache:
        return cache[cname]
    cache[cname] = [cname]  # break cycles defensively
    bases = [b for b in contracts.get(cname, {}).get("bases", []) if b in contracts]
    seqs = [_c3(b, contracts, cache) for b in bases] + ([list(bases)] if bases else [])
    res = [cname]
    while True:
        seqs = [s for s in seqs if s]
        if not seqs:
            break
        head = None
        for s in seqs:
            cand = s[0]
            if not any(cand in t[1:] for t in seqs):
                head = cand
                break
        if head is None:                       # inconsistent hierarchy — fall back to order seen
            head = seqs[0][0]
        res.append(head)
        seqs = [[x for x in s if x != head] for s in seqs]
    out = list(dict.fromkeys(res))
    cache[cname] = out
    return out


def _resolve_fns(cname: str, contracts: dict) -> dict:
    """The {name -> FunctionDefinition} a contract sees: inheritance via C3 (most-derived override
    wins), then COMPOSED modules (the contracts its state-var/param types resolve to)."""
    name_to_fn: dict = {}
    for c in _c3(cname, contracts, {}):                       # most-derived first → override wins
        for fn in contracts.get(c, {}).get("fns", []):
            fname = fn.get("name")
            if fname and fname not in name_to_fn:
                name_to_fn[fname] = fn
    for t in contracts.get(cname, {}).get("types", set()):    # composed external modules
        impls = [c for c in contracts if c == t or t in contracts[c].get("bases", [])]
        for impl in impls:
            for fn in contracts.get(impl, {}).get("fns", []):
                fname = fn.get("name")
                if fname and fname not in name_to_fn:
                    name_to_fn[fname] = fn
    return name_to_fn


def oracle_taint_audit(source_root) -> list[dict]:
    """Audit every `.sol` under `source_root` for oracle / spot-price manipulation.

    Emits the operator's 'untrusted_flow' findings: a trust-sensitive SINK (collateral valuation / loan
    require-gate / payout amount) reached by a SPOT DEX read with no TWAP/chainlink sanitizer on the
    path. SILENT when the same price comes through a sanitizing oracle read.
    """
    root = pathlib.Path(source_root)
    files = _sol_files(root)
    # PROJECT-WIDE pre-pass: a base contract (whose price helper a derived loan function calls) may
    # live in another file, so build the global contract -> (own functions, base names, file) map
    # first, then run the return-taint fixpoint over each contract's INHERITANCE CLOSURE of functions.
    contracts: dict = {}
    for path in files:
        ast = _solc_ast(path)
        if ast is None:
            continue
        for c in _iter(ast, "ContractDefinition"):
            contracts[c.get("name")] = {
                "fns": [n for n in (c.get("nodes") or []) if n.get("nodeType") == "FunctionDefinition"],
                "bases": _base_names(c),
                "types": _referenced_types(c),
                "file": str(path),
            }

    out: list[dict] = []
    for cname, info in contracts.items():
        # return-taint over the override-resolved (C3) inheritance + composition closure of visible fns
        resolved = _resolve_fns(cname, contracts)
        fn_taint = _compute_return_taint(resolved)
        # INTERPROCEDURAL own-balance check: downgrade only when NO function in the contract's whole
        # visible closure has a manipulable spot read (DEX read / another-address balanceOf / reserve) —
        # so a price HELPER like puppet's _computeOraclePrice (balanceOf(uniswapPair)) keeps borrow HIGH.
        downgrade = not any(_has_non_self_spot(fn) for fn in resolved.values())
        for fn in info["fns"]:
            for f in _analyze_function(fn, fn_taint, downgrade_own_balance=downgrade):
                f["file"] = info["file"]
                out.append(f)
    return out
