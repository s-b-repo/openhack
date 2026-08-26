"""ARBITRARY-EXTERNAL-CALL detector — the trust/taint OPERATOR (lattice.taint.trust_obstructions) with a
new ingest classification. SOURCE = untrusted address PARAMETERS; SINK = the callee-address of an
external call (`X.call / .delegatecall / .functionCall / .functionDelegateCall(...)`). When the address
being CALLED derives from a function parameter, the attacker chooses what the contract calls on its
behalf — they pass target=token, data=approve(attacker, balance) and drain it (Damn-Vulnerable-DeFi
`truster`). delegatecall to a parameter is the most severe (attacker code runs in this contract's
storage).

This is the SAME fifth operator (trust/taint) the oracle and donation legs use — only the source and
sink classification differ. The engine is general; the ingest does the language work, as always.
FIRE=lead / SILENCE≠proof: a router/multicall that arbitrarily calls a param address legitimately will
fire — that IS the dangerous pattern, and the agent triages whether it is intended.
"""
import pathlib

from lattice.ingest.solidity import _solc_ast, _iter, _base_names, _sol_files
from lattice.ingest.solidity_taint import (_names_in, _assigned_names, _defined_value_expr,
                                           _c3, _resolve_fns, _referenced_types)
from lattice.taint import trust_obstructions, taint_propagate

# Member names whose receiver is the ADDRESS being called externally.
_CALL_MEMBERS = ("call", "delegatecall", "staticcall", "functionCall", "functionCallWithValue",
                 "functionDelegateCall", "functionStaticCall", "sendValue")
_DELEGATE = ("delegatecall", "functionDelegateCall")
# Substrings marking an ACCESS-CONTROL modifier — an arbitrary call gated by one of these is a
# TRUSTED admin/owner escape hatch (DVD `unstoppable`'s onlyOwner `execute`), not the truster bug
# (callable by ANYONE). `whenPaused` / `nonReentrant` are deliberately NOT here — they are not auth.
_ACCESS_MARKS = ("owner", "admin", "auth", "role", "governance", "gov", "restricted",
                 "operator", "manager", "guardian", "keeper", "onlyself", "permission")


def _checks_sender(cond) -> bool:
    """True if `cond` is (or contains) an equality involving `msg.sender` — a sender-authorization
    gate like `require(msg.sender == owner)`."""
    for b in _iter(cond, "BinaryOperation"):
        if b.get("operator") in ("==", "!="):
            names = _names_in(b)
            if "sender" in names:
                return True
    return False


def _is_access_controlled(fn_node) -> bool:
    """The function is gated by an access-control modifier (onlyOwner/onlyRole/...) or a body-level
    `require(msg.sender == owner)` — so an arbitrary call inside it is owner-trusted, not attacker-callable."""
    for m in (fn_node.get("modifiers") or []):
        mn = ((m.get("modifierName") or {}).get("name") or "").lower()
        if any(a in mn for a in _ACCESS_MARKS):
            return True
    body = fn_node.get("body")
    if body:
        for fc in _iter(body, "FunctionCall"):
            callee = fc.get("expression") or {}
            if callee.get("nodeType") == "Identifier" and callee.get("name") in ("require", "assert"):
                args = fc.get("arguments") or []
                if args and _checks_sender(args[0]):
                    return True
    return False


def _address_params(fn_node) -> set:
    """Names of the function's `address` / `address payable` parameters AND contract/interface-typed
    parameters (the untrusted callees). A contract handle (`IERC20 token`, `IFoo target`) IS an
    address-valued callee — the DVD `truster` natural form `flashLoan(IERC20 token, bytes data)`.
    Under `solc --stop-after parsing` a contract/interface/struct/enum/value-type param is a
    `UserDefinedTypeName` with `typeName.name`/`typeString` == None (type resolution does not run in
    parse mode), so the 'address' substring test alone misses it. We add every `UserDefinedTypeName`
    param: a struct/enum/value-type one is harmless here — it cannot be the receiver of `.call`/
    `.functionCall`, so it never reaches a sink in `_call_targets` and never fires."""
    out: set = set()
    for p in ((fn_node.get("parameters") or {}).get("parameters") or []):
        if not p.get("name"):
            continue
        tn = p.get("typeName") or {}
        name = tn.get("name") or ""
        tstr = (tn.get("typeDescriptions") or {}).get("typeString") or ""
        if (tn.get("nodeType") == "UserDefinedTypeName"
                or "address" in str(name) or "address" in str(tstr)):
            out.add(p["name"])
    return out


def _callee_base(callee):
    """The receiver expression X of an external-call member access X.<call>(...), unwrapping the
    `X.call{value:..}(..)` FunctionCallOptions form; None if `callee` is not such a call."""
    if callee.get("nodeType") == "MemberAccess" and callee.get("memberName") in _CALL_MEMBERS:
        return callee.get("expression"), callee.get("memberName")
    if callee.get("nodeType") == "FunctionCallOptions":
        inner = callee.get("expression") or {}
        if inner.get("nodeType") == "MemberAccess" and inner.get("memberName") in _CALL_MEMBERS:
            return inner.get("expression"), inner.get("memberName")
    return None, None


def _empty_calldata(fc) -> bool:
    """True if a low-level call carries NO calldata: `to.call{value:x}("")` / `to.call{value:x}()` —
    an ETH PAYMENT to a recipient, not a coercible arbitrary call (empty calldata = no function selector
    can be forced). The Fei PSMRouter._redeem FP."""
    args = fc.get("arguments") or []
    if not args:
        return True
    return all(a.get("nodeType") == "Literal" and str(a.get("value") or "") in ("", "0x") for a in args)


_BUILTIN_NS = ("msg", "tx", "block", "abi", "type", "this", "super", "address")
_HIGHLEVEL = "<highlevel>"


def _interface_cast(recv: dict):
    """If `recv` is an explicit interface/contract CAST `IFace(addr)` — a FunctionCall whose callee is a
    PascalCase type identifier (Solidity convention for contracts/interfaces; value-type casts like
    address(x)/uint256(x)/payable(x) are lowercase and excluded) — return the names in its ARGUMENT(S)
    (the address being wrapped). Else None. This is the discriminator that keeps `IRouter(target).swap(d)`
    firing while a struct/library/value-type method call (`map.get(k)`, a bare-identifier or storage
    receiver) does NOT — those are INTERNAL, not external arbitrary calls (the OZ struct-method FP flood)."""
    if recv.get("nodeType") != "FunctionCall":
        return None
    ctype = recv.get("expression") or {}
    name = ctype.get("name") or "" if ctype.get("nodeType") == "Identifier" else ""
    if not name or not name[0].isupper() or name in _BUILTIN_NS:
        return None
    if any(a.get("nodeType") == "Identifier" and a.get("name") in ("this", "super")
           for a in (recv.get("arguments") or [])):
        return None                                         # IFace(this) — calling oneself, not external
    out: set = set()
    for a in recv.get("arguments") or []:
        out |= _names_in(a)
    return out


def _call_targets(body):
    """Map: name in a callee-address position -> set of call-member kinds used there (delegatecall flagged
    critical). A low-level `.call`/`.staticcall`/`.delegatecall` with EMPTY calldata is a value transfer,
    skipped. A HIGH-LEVEL interface method call `IFace(target).method(args)` / `contractParam.method(args)`
    on a non-builtin, non-self receiver also lets the attacker pick the callee — recorded under the
    `<highlevel>` member so _analyze_fn DOWNGRADES it (the selector is fixed and param method calls are
    common, so it is a dismissible lead, not a high-severity truster). (deep-sweep wk01jvye5)"""
    targets: dict = {}
    for fc in _iter(body, "FunctionCall"):
        callee = fc.get("expression") or {}
        base, member = _callee_base(callee)
        if base is not None:
            if member in ("call", "staticcall", "delegatecall") and _empty_calldata(fc):
                continue                            # payment / no-op — no function is invoked
            for n in _names_in(base):
                targets.setdefault(n, set()).add(member)
            continue
        if callee.get("nodeType") == "MemberAccess" and callee.get("memberName") not in _CALL_MEMBERS:
            cast = _interface_cast(callee.get("expression") or {})   # only IFace(target).method(...)
            if cast is not None:
                for n in cast:
                    targets.setdefault(n, set()).add(_HIGHLEVEL)
    return targets


def _base_identifier(node):
    """Root identifier name of an lvalue chain: `store` for `store[id]`, `s` for `s.field[k]`; None if
    the base is not a plain Identifier."""
    while isinstance(node, dict):
        nt = node.get("nodeType")
        if nt == "IndexAccess":
            node = node.get("baseExpression") or {}
        elif nt == "MemberAccess":
            node = node.get("expression") or {}
        else:
            break
    return node.get("name") if isinstance(node, dict) and node.get("nodeType") == "Identifier" else None


def _deps(body) -> dict:
    """name -> names in its defining RHS (so `address t = target; t.call()` still taints t). Also harvests
    CONTAINER writes — `store[id]=target`, `s.addr=target`, `targets.push(target)` — by tainting the base
    container NAME, so a later read of the container into a call target propagates the source (a write into
    an IndexAccess/MemberAccess LHS or a .push() was previously dropped entirely). (deep-sweep wk01jvye5)"""
    deps: dict = {}
    if not body:
        return deps
    stmts = list(_iter(body, "VariableDeclarationStatement"))
    stmts += [s for s in _iter(body, "ExpressionStatement")
              if (s.get("expression") or {}).get("nodeType") == "Assignment"]
    for stmt in stmts:
        rhs = _defined_value_expr(stmt)
        d = _names_in(rhs) if rhs is not None else set()
        for n in _assigned_names(stmt):
            deps[n] = set(deps.get(n, set())) | d
        expr = stmt.get("expression") or {}
        if expr.get("nodeType") == "Assignment":            # container index/member WRITE -> taint base
            lhs = expr.get("leftHandSide") or {}
            if lhs.get("nodeType") in ("IndexAccess", "MemberAccess"):
                base = _base_identifier(lhs)
                if base:
                    deps[base] = set(deps.get(base, set())) | _names_in(expr.get("rightHandSide") or {})
    for fc in _iter(body, "FunctionCall"):                   # container.push(arg) / .add(arg) -> taint base
        callee = fc.get("expression") or {}
        if callee.get("nodeType") == "MemberAccess" and callee.get("memberName") in ("push", "add"):
            base = _base_identifier(callee.get("expression") or {})
            if base:
                for a in fc.get("arguments") or []:
                    deps[base] = set(deps.get(base, set())) | _names_in(a)
    return deps


# Membership-test names: `require(allowed[t])` / `require(set.contains(t))` / `require(isWhitelisted(t))`
# validate the target against an allow-list — the caller cannot choose an ARBITRARY callee, only a
# governance-curated one (Fei PCVSentinel). Downgrade (not suppress: the allow-list itself is a trust
# assumption, and an over-broad list is still a finding).
_ALLOWLIST_FNS = ("contains", "isallowed", "iswhitelisted", "whitelisted", "allowed",
                  "isregistered", "ismember", "isvalidtarget", "exists")


def _target_allowlisted(fn_node, source_names: set) -> bool:
    """True if a `require`/`assert` validates a source param against an allow-list — a mapping index
    `allowed[t]` keyed by it, or a membership call `set.contains(t)` / `isAllowed(t)`."""
    body = fn_node.get("body")
    if not body:
        return False
    for fc in _iter(body, "FunctionCall"):
        callee = fc.get("expression") or {}
        if not (callee.get("nodeType") == "Identifier" and callee.get("name") in ("require", "assert")):
            continue
        cond = (fc.get("arguments") or [None])[0]
        if cond is None:
            continue
        for ix in _iter(cond, "IndexAccess"):                      # allowed[target]
            idx = ix.get("indexExpression") or {}
            if idx.get("nodeType") == "Identifier" and idx.get("name") in source_names:
                return True
        for call in _iter(cond, "FunctionCall"):                   # set.contains(target) / isAllowed(target)
            cc = call.get("expression") or {}
            nm = (cc.get("memberName") if cc.get("nodeType") == "MemberAccess"
                  else (cc.get("name") if cc.get("nodeType") == "Identifier" else "")) or ""
            if nm.lower() in _ALLOWLIST_FNS and any(
                    a.get("nodeType") == "Identifier" and a.get("name") in source_names
                    for a in (call.get("arguments") or [])):
                return True
    return False


def _analyze_fn(fn_node, extra_sources: set | None = None) -> list[dict]:
    body = fn_node.get("body")
    if not body:
        return []
    if _is_access_controlled(fn_node):
        return []                       # owner/admin-trusted arbitrary call — not attacker-callable
    # sources = the function's own untrusted address params PLUS any tainted STATE VARS visible to it (the
    # cross-function build: an attacker addr stored in a state var by another function reaches this sink).
    sources = _address_params(fn_node) | (extra_sources or set())
    if not sources:
        return []
    targets = _call_targets(body)
    if not targets:
        return []
    deps = _deps(body)
    sinks = set(targets)
    findings = trust_obstructions(deps, sources, sinks, set())
    if not findings:
        return []
    name = fn_node.get("name") or fn_node.get("kind", "function")
    fired = {f.get("sink") for f in findings}
    # severity: delegatecall to an attacker address runs their code in THIS contract's storage
    is_delegate = any(set(_DELEGATE) & targets.get(s, set()) for s in fired)
    # a HIGH-LEVEL-only call (IFace(target).method) is a downgraded lead — the selector is fixed and
    # param method calls are common; the low-level truster (.call/.functionCall) stays high/critical.
    highlevel_only = bool(fired) and all(targets.get(s, set()) <= {_HIGHLEVEL} for s in fired)
    allowlisted = _target_allowlisted(fn_node, sources)            # target validated against an allow-list
    downgraded = allowlisted or (highlevel_only and not is_delegate)
    sev = ("critical" if is_delegate else "low" if downgraded else "high")
    return [{
        "kind": "arbitrary_external_call",
        "severity": sev,
        "function": name,
        **({"confidence": "low"} if downgraded else {}),
        "detail": (("[target is ALLOW-LIST validated (require(allowed[target])/contains) — the caller "
                    "cannot pick an arbitrary callee, only a curated one; lower exploitability] "
                    if allowlisted else "")
                   + ("[HIGH-LEVEL interface call IFace(target).method(...) — attacker picks the callee but "
                      "the selector is fixed; common pattern, dismissible lead] " if highlevel_only and not allowlisted else "")
                   + "an external call's TARGET ADDRESS derives from an untrusted function parameter — the "
                   "caller chooses what this contract calls on its behalf (pass target=token, "
                   "data=approve(attacker,bal) to drain it; DVD `truster`)"
                   + (" — via DELEGATECALL: attacker code runs in this contract's storage" if is_delegate else "")),
    }]


def _state_var_names(contract) -> set:
    """Contract-level state variable names (a VariableDeclaration directly in the contract body)."""
    out: set = set()
    for node in contract.get("nodes") or []:
        if node.get("nodeType") == "VariableDeclaration" and node.get("name"):
            out.add(node["name"])
    return out


def _state_var_writes(fn_node, sv_names: set) -> list:
    """(state-var name, RHS footprint) for each assignment whose LHS base is a state variable —
    `impl = newImpl`, `registry[k] = target`, `s.addr = target`."""
    body = fn_node.get("body")
    out: list = []
    if not body:
        return out
    for stmt in _iter(body, "ExpressionStatement"):
        expr = stmt.get("expression") or {}
        if expr.get("nodeType") == "Assignment":
            base = _base_identifier(expr.get("leftHandSide") or {})
            if base in sv_names:
                out.append((base, _names_in(expr.get("rightHandSide") or {})))
    return out


def _tainted_state_vars(cname: str, contracts: dict, resolved: dict) -> set:
    """State variables tainted across `cname`'s inheritance+composition closure: a state var assigned from
    an untrusted address PARAM (or from an already-tainted state var) in a NON-access-controlled function.
    A write gated by onlyOwner is owner-trusted (consistent with _is_access_controlled in the intra pass),
    so it is skipped. Fixpoint for chains (sv2 = sv1). Monotone — only adds sources (FN-safe). (wk01jvye5)"""
    sv_names: set = set()
    for c in _c3(cname, contracts, {}):
        sv_names |= contracts.get(c, {}).get("statevars", set())
    if not sv_names:
        return set()
    tainted: set = set()
    fns = list(resolved.values())
    for _ in range(len(sv_names) + 2):
        changed = False
        for fn in fns:
            if _is_access_controlled(fn):
                continue                                   # owner-set state var is trusted
            local_sources = _address_params(fn) | tainted
            if not local_sources:
                continue
            reach = taint_propagate(_deps(fn.get("body")), local_sources, set())
            for sv, rhs_fp in _state_var_writes(fn, sv_names):
                if sv not in tainted and rhs_fp & reach:
                    tainted.add(sv)
                    changed = True
        if not changed:
            break
    return tainted


def arbitrary_call_audit(source_root) -> list[dict]:
    """Audit every `.sol` under `source_root` for an external call whose target address is an untrusted
    function parameter OR a state variable tainted by an attacker elsewhere in the inheritance closure.
    Emits 'arbitrary_external_call' per offending function."""
    root = pathlib.Path(source_root)
    files = _sol_files(root)
    out: list[dict] = []
    seen: set = set()

    def _emit(f):
        key = (f.get("file"), f.get("function"), f.get("severity"))
        if key not in seen:
            seen.add(key)
            out.append(f)

    # PASS 1 — build the project-wide contract model AND run the existing INTRA-function analysis unchanged.
    contracts: dict = {}
    for path in files:
        ast = _solc_ast(path)
        if ast is None:
            continue
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        for contract in _iter(ast, "ContractDefinition"):
            cname = contract.get("name", "")
            fns = [n for n in (contract.get("nodes") or []) if n.get("nodeType") == "FunctionDefinition"]
            for fn in fns:
                fn["__file"] = rel                         # remember the defining file for cross-fn attribution
            contracts[cname] = {"fns": fns, "bases": _base_names(contract),
                                "types": _referenced_types(contract),
                                "statevars": _state_var_names(contract), "rel": rel}
            for fn in fns:
                for f in _analyze_fn(fn):
                    f["contract"] = cname
                    f["file"] = rel
                    _emit(f)

    # PASS 2 — ADDITIVE cross-function / state-var taint over each contract's inheritance closure: a state
    # var tainted by an attacker in one function reaches a call/delegatecall on it in another (even a
    # base-contract helper in another file). Re-analyze the closure's functions with the tainted state vars
    # as extra sources; dedup against PASS 1.
    for cname, info in contracts.items():
        resolved = _resolve_fns(cname, contracts)
        tainted = _tainted_state_vars(cname, contracts, resolved)
        if not tainted:
            continue
        for fn in resolved.values():
            for f in _analyze_fn(fn, extra_sources=tainted):
                f["contract"] = cname
                f["file"] = fn.get("__file", info["rel"])
                _emit(f)
    return out
