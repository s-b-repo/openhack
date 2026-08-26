"""TIER-2 economic invariants — NONLINEAR conserved functionals via symbolic algebra.

The linear conservation leg (typed_chain.conservation_obstructions) handles q = Σ wᵢ·cellᵢ and is
blind to a product: a constant-product AMM invariant x·y=k cannot be a linear functional. This
operator handles q = ANY sympy expression (x*y, share price totalAssets/totalShares, …). An
operation is a SIMULTANEOUS symbolic substitution of cells; drift = simplify(q[after] − q[before]);
nonzero ⟹ the invariant is broken. The cost (and the reason it is a SEPARATE operator, not an
extension of the linear leg): it leaves the linear-localizable regime — q is no longer additive
over composition, so we need symbolic algebra (sympy / SMT), a different computational tool.

Scope: this is the OPERATOR. Producing the symbolic per-operation update from a real Solidity AST
(symbolic-execution-lite) is the per-language ingest — the larger remaining piece, as with every
other leg (the engine is general; the ingest does the language work).
"""
import random
import sympy as sp


def _can_be_negative(expr, symbols) -> dict | None:
    """Witness that `expr` can be < 0 over POSITIVE inputs (a drain), or None. Deterministic
    positive sampling — sound for FIRE (a witness is a real draining input), a screen for SILENCE."""
    simplified = sp.simplify(expr)
    syms = sorted(simplified.free_symbols, key=str)
    if not syms:
        return {} if simplified.is_negative else None
    rng = random.Random(1234567)
    for _ in range(600):
        pt = {s: rng.randint(1, 10 ** 6) for s in syms}
        if simplified.subs(pt).is_negative:
            return {str(s): v for s, v in pt.items()}
    return None


def symbolic_conservation(invariant, operations: list[dict], mode: str = "conserved") -> list[dict]:
    """invariant: a sympy expression in the cell symbols. operations: [{op, update: {sym: new_value}}].
    mode='conserved'      → fire if the net drift ≠ 0 (an exact equality invariant, e.g. token supply);
    mode='non_decreasing' → fire if the drift can be NEGATIVE for some positive input (a monotone
                            invariant that may only GROW, e.g. a fee-bearing AMM's x·y — a correct
                            swap keeps or grows k, only a DRAIN decreases it). This is the second
                            economic-invariant flavour: inequality, not equality."""
    out: list[dict] = []
    for o in operations:
        after = invariant.subs(o["update"], simultaneous=True)
        drift = sp.simplify(after - invariant)
        if mode == "non_decreasing":
            witness = _can_be_negative(drift, drift.free_symbols)
            if witness is not None:
                out.append({
                    "kind": "invariant_break", "op": o.get("op"), "mode": mode,
                    "invariant": str(invariant), "drift": str(drift), "witness": witness,
                    "detail": (f"operation '{o.get('op')}' can DECREASE the invariant {invariant} "
                               f"(drift {drift} < 0 at {witness}) — the pool can be drained"),
                })
        elif drift != 0:
            out.append({
                "kind": "invariant_break", "op": o.get("op"), "mode": mode,
                "invariant": str(invariant), "drift": str(drift),
                "detail": (f"operation '{o.get('op')}' breaks the invariant {invariant} "
                           f"(net symbolic drift {drift}) — value created or destroyed"),
            })
    return out
