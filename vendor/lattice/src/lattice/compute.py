# src/lattice/compute.py
"""Compute seam — gives heavy computations 'the right legs'.

Each operation has a correct local implementation and a hook to route to the
validated `solver` suite (skim/triage for ranking, deadbolt/lockout QUBO for
min-feedback-arc-set) when a bridge is wired. The solver is an agent-side MCP and
may be offline, so local is the default and always correct; the solver path, when
enabled, swaps in validated/gated compute without changing callers.

Every result records `provenance` ("local" | "solver:<name>") so downstream
reporting can see which legs ran — consistent with the system-wide envelope.
"""
from __future__ import annotations

# When a solver bridge is installed it sets this callable: solve(op, params) -> result|None.
# Returning None (or being None) means "fall back to local".
SOLVER = None


def _try_solver(op: str, params: dict):
    if SOLVER is None:
        return None
    try:
        return SOLVER(op, params)
    except Exception:
        return None   # solver offline / errored -> local fallback, never fatal


def rank_desc(items: list, score) -> tuple[list, str]:
    """Rank items by descending score. Solver leg: `triage`/`skim`."""
    out = _try_solver("rank_desc", {"n": len(items)})
    if out is None:
        return sorted(items, key=lambda x: (-score(x), str(x))), "local"
    return out, "solver:skim"


def min_feedback_arc_set(scc_nodes: set, edges: list, edge_weight) -> tuple[list, str]:
    """Pick edges to remove to break all cycles in an SCC. NP-hard in general;
    local leg is the greedy hub-edge heuristic, solver leg is QUBO (deadbolt/lockout).

    edges: list of (a, b) within the SCC.  edge_weight: (a,b) -> float (cut priority).
    Returns (edges_to_cut, provenance).
    """
    # Solver leg: route to the z6 QUBO solver over SSH (verified before trusted).
    from lattice import solver_bridge
    out = solver_bridge.min_feedback_arc_set(set(scc_nodes), list(edges))
    if out is not None:
        return out, "solver:deadbolt"

    # local greedy: cut the heaviest edge that still lies ON a cycle, until acyclic.
    # Restricting candidates to cycle-edges (target can still reach source) stops the heuristic
    # from spending cuts on collateral edges that sit on no remaining cycle — near-optimal here.
    remaining = list(edges)
    cut: list = []
    while _has_cycle(scc_nodes, remaining):
        radj: dict = {}
        for a, b in remaining:
            radj.setdefault(a, []).append(b)
        on_cycle = [(u, v) for (u, v) in remaining if _reaches(radj, v, u)]
        if not on_cycle:                       # safety: shouldn't happen if _has_cycle is true
            break
        e = max(on_cycle, key=lambda x: edge_weight(x))
        remaining.remove(e)
        cut.append(e)
    return cut, "local"


def _reaches(adj: dict, src, dst) -> bool:
    """Is dst reachable from src in the directed graph `adj`? (edge (u,v) is on a cycle iff
    v reaches u)."""
    if src == dst:
        return True
    seen = {src}
    stack = [src]
    while stack:
        n = stack.pop()
        for m in adj.get(n, ()):
            if m == dst:
                return True
            if m not in seen:
                seen.add(m)
                stack.append(m)
    return False


def _has_cycle(nodes: set, edges: list) -> bool:
    adj: dict = {n: [] for n in nodes}
    for a, b in edges:
        if a in adj:
            adj[a].append(b)
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in nodes}

    def dfs(u) -> bool:
        color[u] = GRAY
        for v in adj.get(u, ()):
            if v not in color:
                continue
            if color[v] == GRAY:
                return True
            if color[v] == WHITE and dfs(v):
                return True
        color[u] = BLACK
        return False

    return any(color[n] == WHITE and dfs(n) for n in nodes)
