"""DONATION / EXTERNAL-BALANCE griefing detector — the Tier-3 external-manipulation slice the
economic-invariant-probe named but had not yet built ("donation-inflation via direct transfer;
token.balanceOf(this) is externally writable").

THE BUG CLASS (Damn-Vulnerable-DeFi `unstoppable`, and the general ERC4626 donation/inflation attack):
a contract treats `token.balanceOf(address(this))` — a value ANYONE can change with a 1-wei direct
transfer — as accounting truth, ASSERTING it equals (or comparing it against) an INTERNAL supply
variable (`totalSupply` / `totalShares`). A donation breaks the equality, so the invariant assertion
either DoS-reverts every subsequent call (`unstoppable`) or inflates the share price (first-depositor
attack). The dominant modern DeFi-loss class lives in this external-mutability space — see the
economic-invariant-probe: this is conservation's invariant broken NOT by an internal op but by EXTERNAL
writability, so it is neither linear- nor symbolic-conservation; it is the trust/external slice.

WHY IT IS A SEPARATE DETECTOR FROM THE ORACLE-SPOT TAINT (solidity_taint): both read `balanceOf`, but
oracle-spot reads ANOTHER address's balance as a PRICE (`balanceOf(pair)`, attacker moves it via a swap)
and sinks to a PAYOUT, whereas donation-grief reads its OWN balance as ACCOUNTING (`balanceOf(this)`,
attacker moves it via a direct transfer) and sinks to an EQUALITY ASSERTION. Same opcode, opposite
argument, different sink.

THE STRUCTURAL SIGNATURE: a require/if comparison with OWN-BALANCE on one side and INTERNAL accounting
on the other. OWN-BALANCE is detected STRUCTURALLY (the side's transitive footprint reaches a
`balanceOf(address(this))` / `address(this).balance` read, directly or via a helper like `totalAssets`);
INTERNAL is a name-heuristic supply marker (`totalSupply`, ...) or a contract state variable that is NOT
own-balance-derived. FIRE=lead / SILENCE≠proof, as with every Footings leg.
"""
import pathlib

from lattice.ingest.solidity import _solc_ast, _iter, _sol_files
from lattice.ingest.solidity_taint import (
    _names_in, _footprint, _assigned_names, _defined_value_expr,
)

# Supply-like accounting names = the INTERNAL side of the invariant. `totalAssets` is DELIBERATELY
# EXCLUDED — in ERC4626 it returns balanceOf(this) (the OWN-BALANCE side), detected structurally.
_SUPPLY_MARKS = ("totalsupply", "totalshares", "totaldebt", "totalborrow",
                 "totaldeposit", "totalliquidity", "totalstaked", "totalminted")
_CMP_OPS = ("==", "!=", "<", ">", "<=", ">=")


def _references_this(node) -> bool:
    """True if `this` (the contract's own address) appears anywhere under `node`."""
    if isinstance(node, dict):
        if node.get("nodeType") == "Identifier" and node.get("name") == "this":
            return True
        return any(_references_this(v) for v in node.values())
    if isinstance(node, list):
        return any(_references_this(x) for x in node)
    return False


def _own_balance_in(expr) -> bool:
    """True if `expr`'s subtree reads the contract's OWN externally-writable balance:
    `token.balanceOf(address(this))` / `balanceOf(this)`, or `address(this).balance`."""
    if isinstance(expr, dict):
        nt = expr.get("nodeType")
        if nt == "FunctionCall":
            callee = expr.get("expression") or {}
            if (callee.get("nodeType") == "MemberAccess" and callee.get("memberName") == "balanceOf"
                    and _references_this(expr.get("arguments"))):
                return True
        if nt == "MemberAccess" and expr.get("memberName") == "balance" and _references_this(expr.get("expression")):
            return True
        return any(_own_balance_in(v) for v in expr.values())
    if isinstance(expr, list):
        return any(_own_balance_in(x) for x in expr)
    return False


def _state_vars(contract) -> set:
    return {n.get("name") for n in contract.get("nodes", [])
            if n.get("nodeType") == "VariableDeclaration" and n.get("name")}


def _def_stmts(body):
    """Definition statements (var-decls + assignments) of a function body, in any order."""
    stmts = list(_iter(body, "VariableDeclarationStatement"))
    stmts += [s for s in _iter(body, "ExpressionStatement")
              if (s.get("expression") or {}).get("nodeType") == "Assignment"]
    return stmts


def _fn_deps(fn_node) -> dict:
    """Per-function value dependency graph: name -> set(names in its defining RHS)."""
    body = fn_node.get("body")
    deps: dict = {}
    if not body:
        return deps
    for stmt in _def_stmts(body):
        names = _assigned_names(stmt)
        if not names:
            continue
        rhs = _defined_value_expr(stmt)
        d = _names_in(rhs) if rhs is not None else set()
        for n in names:
            deps[n] = set(deps.get(n, set())) | d
    return deps


def _own_names(fn_node, own_fns: set) -> set:
    """Value names DIRECTLY defined from an own-balance read or a call to an own-balance helper fn.
    (Transitive own-ness is then recovered via the footprint at the comparison.)"""
    body = fn_node.get("body")
    out: set = set()
    if not body:
        return out
    for stmt in _def_stmts(body):
        rhs = _defined_value_expr(stmt)
        if rhs is None:
            continue
        if _own_balance_in(rhs) or (_names_in(rhs) & own_fns):
            out |= set(_assigned_names(stmt))
    return out


def _return_reads_own(fn_node, own_fns: set) -> bool:
    """Does this function's RETURN value read own-balance (directly, via a local, or via an own fn)?"""
    body = fn_node.get("body")
    if not body:
        return False
    deps = _fn_deps(fn_node)
    onames = _own_names(fn_node, own_fns)
    memo: dict = {}
    for r in _iter(body, "Return"):
        e = r.get("expression")
        if e is None:
            continue
        if _own_balance_in(e):
            return True
        names = _names_in(e)
        if names & own_fns:
            return True
        fp = set(names)
        for nm in names:
            fp |= _footprint(nm, deps, memo)
        if fp & onames:
            return True
    return False


def _own_balance_fns(contract) -> set:
    """Fixpoint: the contract's functions whose RETURN value reads own-balance (e.g. `totalAssets`)."""
    fns = {n.get("name"): n for n in contract.get("nodes", [])
           if n.get("nodeType") == "FunctionDefinition" and n.get("name")}
    own: set = set()
    for _ in range(len(fns) + 2):
        changed = False
        for name, fn in fns.items():
            if name not in own and _return_reads_own(fn, own):
                own.add(name)
                changed = True
        if not changed:
            break
    return own


def _side_class(expr, deps: dict, onames: set, own_fns: set, internal_names: set) -> str | None:
    """Classify one side of a comparison: 'own' (reaches an own-balance read), 'internal' (reaches a
    supply marker / contract state var and is NOT own), else None. 'own' wins over 'internal'."""
    if _own_balance_in(expr):
        return "own"
    names = _names_in(expr)
    memo: dict = {}
    fp = set(names)
    for nm in names:
        fp |= _footprint(nm, deps, memo)
    if fp & (onames | own_fns):
        return "own"
    for nm in fp:
        low = nm.lower()
        if any(m in low for m in _SUPPLY_MARKS) or nm in internal_names:
            return "internal"
    return None


def _comparisons(cond):
    """Every comparison BinaryOperation in a condition (the condition itself if it is one)."""
    return [n for n in _iter(cond, "BinaryOperation") if n.get("operator") in _CMP_OPS]


def _conditions(body):
    """Comparison-bearing conditions: every if-statement condition and every require/assert 1st arg."""
    conds = [ifs.get("condition") for ifs in _iter(body, "IfStatement") if ifs.get("condition")]
    for fc in _iter(body, "FunctionCall"):
        callee = fc.get("expression") or {}
        if callee.get("nodeType") == "Identifier" and callee.get("name") in ("require", "assert"):
            args = fc.get("arguments") or []
            if args:
                conds.append(args[0])
    return conds


def _analyze_fn(fn_node, own_fns: set, internal_names: set) -> list[dict]:
    body = fn_node.get("body")
    if not body:
        return []
    deps = _fn_deps(fn_node)
    onames = _own_names(fn_node, own_fns)
    name = fn_node.get("name") or fn_node.get("kind", "function")
    for cond in _conditions(body):
        for cmp_node in _comparisons(cond):
            cl = _side_class(cmp_node.get("leftExpression"), deps, onames, own_fns, internal_names)
            cr = _side_class(cmp_node.get("rightExpression"), deps, onames, own_fns, internal_names)
            if {cl, cr} == {"own", "internal"}:
                return [{
                    "kind": "balance_invariant_griefable",
                    "severity": "high",
                    "function": name,
                    "operator": cmp_node.get("operator"),
                    "detail": ("an invariant compares the contract's OWN balance "
                               "(balanceOf(address(this)) — anyone can change it by a direct transfer) "
                               "against an internal supply variable; a 1-wei donation breaks the "
                               "assertion (DoS) or inflates the share price (ERC4626 donation attack)"),
                }]
    return []


def donation_griefing_audit(source_root) -> list[dict]:
    """Audit every `.sol` under `source_root` for the donation / external-balance griefing pattern:
    an invariant assertion comparing `balanceOf(address(this))` (externally donation-writable) against
    an internal supply variable. Emits 'balance_invariant_griefable' per offending function."""
    root = pathlib.Path(source_root)
    files = _sol_files(root)
    out: list[dict] = []
    for path in files:
        ast = _solc_ast(path)
        if ast is None:
            continue
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        for contract in _iter(ast, "ContractDefinition"):
            own_fns = _own_balance_fns(contract)
            internal_names = _state_vars(contract)
            for fn in contract.get("nodes", []):
                if fn.get("nodeType") != "FunctionDefinition":
                    continue
                for f in _analyze_fn(fn, own_fns, internal_names):
                    f["contract"] = contract.get("name", "")
                    f["file"] = rel
                    out.append(f)
    return out
