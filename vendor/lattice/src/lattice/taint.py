"""TIER-3 — the TRUST / TAINT operator: the FIFTH structure, distinct from the four obstruction
operators (homology-2cycle, reachability/SCC, collision, conservation).

Oracle manipulation, donation/external-mutation, and tx.origin-auth all break a security decision
via an ATTACKER-CONTROLLABLE value flowing into a trust-sensitive sink. That is neither a homology
class, nor reachability, nor a type collision, nor a conservation drift — it is an information-flow
property over a trust LATTICE: a value is tainted if it derives from an untrusted SOURCE
(msg.sender, a call parameter, a miner-/attacker-movable external read like a spot AMM price or
`token.balanceOf(this)`) and is not SANITIZED (a TWAP, a bounds check, an access guard). The
obstruction is a tainted value reaching a SINK (auth check, transfer amount, collateral valuation).

This module is the OPERATOR (monotone taint propagation to fixpoint over a dependency graph). The
per-language ingest — extracting the dependency graph + classifying sources/sinks/sanitizers from
an AST — is the larger remaining work, exactly as for the other legs.
"""


def taint_propagate(dependencies: dict, sources, sanitizers=()) -> set:
    """Least fixpoint of taint over a value-dependency graph. `dependencies[value]` = the values it
    derives from. A value is tainted if it IS a source, or derives from a tainted value and is not a
    sanitizer (a sanitizer breaks the flow — TWAP, require-bounds, access guard)."""
    sanitizers = set(sanitizers)
    tainted = {s for s in sources if s not in sanitizers}
    changed = True
    while changed:
        changed = False
        for value, inputs in dependencies.items():
            if value in tainted or value in sanitizers:
                continue
            if any(i in tainted for i in inputs):
                tainted.add(value)
                changed = True
    return tainted


def trust_obstructions(dependencies: dict, sources, sinks, sanitizers=()) -> list[dict]:
    """Fire for every SINK reached by an untrusted SOURCE through the (unsanitized) dependency flow."""
    tainted = taint_propagate(dependencies, sources, sanitizers)
    out: list[dict] = []
    for sink in sinks:
        if sink in tainted:
            out.append({
                "kind": "untrusted_flow", "sink": sink,
                "detail": (f"a trust-sensitive sink '{sink}' depends on an attacker-controllable source "
                           f"with no sanitizer on the path — e.g. a manipulable price/balance reaching a "
                           f"valuation or auth decision (oracle manipulation / external-mutation class)"),
            })
    return out
