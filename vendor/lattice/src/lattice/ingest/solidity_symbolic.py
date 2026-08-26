"""TIER-2 INGEST — symbolic-execution-lite that produces the per-operation symbolic update the
constant-product (x·y=k) invariant operator consumes.

The operator (`lattice.symbolic_conservation.symbolic_conservation`) is general: given an invariant
expression and a list of {op, update: {symbol -> new symbolic value}}, it fires on any op whose net
symbolic drift is nonzero. The hard, language-specific part — and the reason this is a separate
ingest, not part of the operator — is turning a REAL Solidity function body into that symbolic
update. That is what this module does.

How (per contract, per swap-like function):
  1. Identify the two reserves x,y: a function that updates EXACTLY two numeric state vars in
     OPPOSITE directions (one '+=' and one '-='). Those two state vars are the reserves.
  2. Symbolically execute the body IN ORDER with an env {local_name -> sympy expr}. A
     VariableDeclarationStatement binds env[name] = translate(initialValue). translate() maps
     BinaryOperation(+,-,*,/) recursively, an Identifier to env[name] or a fresh Symbol (reserve /
     parameter), a Literal to an Integer — so a local's value is always expressed in terms of the
     ORIGINAL reserve symbols. (Parenthesised subexpressions are TupleExpression wrappers in the
     solc AST; a single-component tuple is unwrapped.)
  3. The two compound assignments become the update: '+=' on x -> x_sym + translate(rhs);
     '-=' on y -> y_sym - translate(rhs). Both rhs are resolved through env, so they are in terms
     of the original reserve symbols.
  4. Call symbolic_conservation(invariant=x_sym*y_sym, operations=[{op, update}]). A nonzero drift
     becomes an {kind:'invariant_break', function, detail} finding.

This is symbolic-execution-LITE on purpose: straight-line bodies, the four arithmetic operators,
local var declarations, and the two reserve compound-assignments. It does not model branches, loops,
mappings, casts, or mutation of a local after its declaration. Anything it cannot translate is
skipped (no symbolic update built) rather than guessed — an honest miss, not a false all-clear.
"""
from __future__ import annotations
import pathlib

import sympy as sp

from lattice.ingest.solidity import _solc_ast, _iter, _sol_files
from lattice.symbolic_conservation import symbolic_conservation

_ARITH = {"+": lambda a, b: a + b, "-": lambda a, b: a - b,
          "*": lambda a, b: a * b, "/": lambda a, b: a / b}


def _state_vars(contract: dict) -> set[str]:
    """Names of the contract's directly-declared state variables (direct VariableDeclaration
    children of the ContractDefinition)."""
    return {n.get("name") for n in contract.get("nodes", [])
            if n.get("nodeType") == "VariableDeclaration" and n.get("name")}


def _unwrap_tuple(node: dict) -> dict:
    """A parenthesised expression `(e)` is a single-component TupleExpression in the solc AST —
    unwrap it (repeatedly) to the inner expression. A multi-component tuple is left as-is (it is
    not a scalar arithmetic value this lite executor models)."""
    while (isinstance(node, dict) and node.get("nodeType") == "TupleExpression"
           and not node.get("isInlineArray")):
        comps = node.get("components") or []
        if len(comps) == 1 and comps[0] is not None:
            node = comps[0]
        else:
            break
    return node


class _Untranslatable(Exception):
    """A node shape this lite executor does not model — caller skips (does NOT guess)."""


def _translate(node: dict, env: dict, symbols: dict, allowed: set | None = None):
    """Map an expression AST node to a sympy expression. Identifiers resolve through `env`
    (locals, already in terms of original reserve symbols) first, else become / reuse a Symbol in
    `symbols` (a reserve or a parameter). Raises _Untranslatable for any shape outside the lite
    grammar (so the caller skips rather than building a wrong update)."""
    node = _unwrap_tuple(node)
    nt = node.get("nodeType")
    if nt == "BinaryOperation":
        op = node.get("operator")
        fn = _ARITH.get(op)
        if fn is None:
            raise _Untranslatable(f"operator {op}")
        return fn(_translate(node["leftExpression"], env, symbols, allowed),
                  _translate(node["rightExpression"], env, symbols, allowed))
    if nt == "Identifier":
        name = node.get("name")
        if name in env:
            return env[name]
        # allowed=None ⇒ standalone translator (any free identifier becomes a symbol). The AUDIT
        # passes an explicit allowed = {reserves ∪ params}: then an identifier that is neither a
        # translated local nor a reserve/param is a local whose value we could NOT model (cast,
        # oracle/TWAP call, min/clamp). Do NOT invent a free symbol there — that spurious drift
        # flagged a CORRECT swap — raise so the update is skipped instead.
        if allowed is None or name in allowed:
            return symbols.setdefault(name, sp.Symbol(name, positive=True))
        raise _Untranslatable(f"identifier {name!r} (local with an unmodelled value)")
    if nt == "Literal":
        val = node.get("value")
        try:
            return sp.Integer(int(str(val)))
        except (TypeError, ValueError):
            raise _Untranslatable(f"literal {val!r}")
    raise _Untranslatable(f"node {nt}")


def _find_reserve_updates(fn: dict, state_vars: set[str]):
    """Scan the top-level statements for compound assignments ('+='/'-=') whose LHS is a state var.
    Return (plus_var, plus_rhs_node, minus_var, minus_rhs_node) iff EXACTLY one '+=' and one '-='
    on two DISTINCT state vars exist (the opposite-direction reserve pair); else None."""
    plus: list = []   # (var, rhs_node)
    minus: list = []
    for stmt in (fn.get("body") or {}).get("statements", []) or []:
        if stmt.get("nodeType") != "ExpressionStatement":
            continue
        a = stmt.get("expression") or {}
        if a.get("nodeType") != "Assignment":
            continue
        op = a.get("operator")
        lhs = a.get("leftHandSide") or {}
        # only a plain state-var identifier on the LHS (not balances[x] etc.) is a reserve update
        if lhs.get("nodeType") != "Identifier":
            continue
        name = lhs.get("name")
        if name not in state_vars:
            continue
        if op == "+=":
            plus.append((name, a.get("rightHandSide") or {}))
        elif op == "-=":
            minus.append((name, a.get("rightHandSide") or {}))
        elif op == "=":
            # `reserve = reserve + expr` / `reserve = reserve - expr` — the plain-assignment form,
            # equivalent to += / -= expr. (Only when the LHS var is the left operand.)
            rhs = a.get("rightHandSide") or {}
            le = rhs.get("leftExpression") or {}
            if (rhs.get("nodeType") == "BinaryOperation" and rhs.get("operator") in ("+", "-")
                    and le.get("nodeType") == "Identifier" and le.get("name") == name):
                target = plus if rhs["operator"] == "+" else minus
                target.append((name, rhs.get("rightExpression") or {}))
    if len(plus) == 1 and len(minus) == 1 and plus[0][0] != minus[0][0]:
        return plus[0][0], plus[0][1], minus[0][0], minus[0][1]
    return None


def _build_env(fn: dict, symbols: dict, allowed: set) -> dict:
    """Execute the body's VariableDeclarationStatements IN ORDER, binding each single-named local to
    translate(initialValue) in terms of the original reserve symbols. Decls that don't translate are
    skipped (the local stays a free Symbol if later referenced)."""
    env: dict = {}
    for stmt in (fn.get("body") or {}).get("statements", []) or []:
        if stmt.get("nodeType") != "VariableDeclarationStatement":
            continue
        decls = [d for d in (stmt.get("declarations") or []) if d]
        init = stmt.get("initialValue")
        if len(decls) != 1 or not init:
            continue
        name = decls[0].get("name")
        if not name:
            continue
        try:
            env[name] = _translate(init, env, symbols, allowed)
        except _Untranslatable:
            continue   # leave unbound; a later reference now RAISES (not in env/allowed), so the
            #            update is skipped — never a guessed free symbol that flags a correct swap
    return env


def amm_invariant_audit(source_root) -> list[dict]:
    """For every contract under `source_root`, find a swap-like function (two state vars updated in
    opposite directions = the reserves x,y), symbolically execute it, and check the constant-product
    invariant x·y via `symbolic_conservation`. Emit an {kind:'invariant_break', ...} finding per
    function whose net symbolic drift in x·y is nonzero (value created/destroyed)."""
    root = pathlib.Path(source_root)
    out: list[dict] = []
    for path in _sol_files(root):
        ast = _solc_ast(path)
        if ast is None:
            continue
        rel = path.relative_to(root).as_posix()
        for contract in _iter(ast, "ContractDefinition"):
            cname = contract.get("name", "")
            state_vars = _state_vars(contract)
            if len(state_vars) < 2:
                continue
            for fn in contract.get("nodes", []):
                if fn.get("nodeType") != "FunctionDefinition":
                    continue
                fname = fn.get("name") or fn.get("kind", "function")
                pair = _find_reserve_updates(fn, state_vars)
                if pair is None:
                    continue
                plus_var, plus_rhs, minus_var, minus_rhs = pair
                # fresh reserve symbols x (the '+=' var) and y (the '-=' var)
                symbols: dict = {}
                x_sym = symbols.setdefault(plus_var, sp.Symbol(plus_var, positive=True))
                y_sym = symbols.setdefault(minus_var, sp.Symbol(minus_var, positive=True))
                # the ONLY legitimate free symbols are the reserves and the function's parameters;
                # any other bare identifier is a local whose value we couldn't model -> skip, don't guess.
                params = {p.get("name") for p in ((fn.get("parameters") or {}).get("parameters") or [])
                          if p.get("name")}
                allowed = {plus_var, minus_var} | params
                # locals resolved through the in-order env, in terms of original reserve symbols
                env = _build_env(fn, symbols, allowed)
                try:
                    add = _translate(plus_rhs, env, symbols, allowed)
                    sub = _translate(minus_rhs, env, symbols, allowed)
                except _Untranslatable:
                    # could not symbolically model the update — skip rather than guess. (An honest
                    # miss; the function is simply not covered, never reported clean.)
                    continue
                invariant = x_sym * y_sym
                update = {x_sym: x_sym + add, y_sym: y_sym - sub}
                op = {"op": fname, "update": update}
                # the AMM invariant is x·y NON-DECREASING: a correct swap (with or without a fee)
                # keeps or grows k; only a DRAIN makes it decrease. Exact equality would false-fire on
                # every real fee-bearing swap.
                for r in symbolic_conservation(invariant, [op], mode="non_decreasing"):
                    out.append({
                        "kind": "invariant_break",
                        "severity": "high",
                        "contract": cname,
                        "function": fname,
                        "file": rel,
                        "reserves": [plus_var, minus_var],
                        "drift": r["drift"],
                        "witness": r.get("witness"),
                        "detail": (f"constant-product invariant {plus_var}*{minus_var} can DECREASE under "
                                   f"'{fname}' (drift {r['drift']} < 0 at {r.get('witness')}) — the pool can "
                                   f"be drained; a correct swap keeps or grows x*y (a fee only grows it)"),
                    })
    return out
