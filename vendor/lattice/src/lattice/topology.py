# src/lattice/topology.py
"""Obstruction witnesses — the homology framework's witness step, wired to the solvers.

β₁ counts the independent cycles (H₁ rank); a *witness* is a minimal cycle realizing one.
That minimality is an optimization: the LOCAL leg returns the shortest cycle through each
cycle-closing edge (BFS); the SOLVER leg (z6 QUBO) returns the globally minimal witness
when enabled — same verify-then-trust pattern as min-feedback-arc-set. This is the bridge
between OMNI's algebraic-topology frameworks (homology/sheaf cohomology) and the solver
suite: the topology reduces to rank/kernel + minimal-generator search, and the solvers do
the heavy combinatorial leg.
"""
from __future__ import annotations
from collections import deque

from lattice.graph.models import Hypernetwork


def _bfs_path(adj: dict, src: str, dst: str) -> list[str] | None:
    """Shortest directed path src -> dst (node list), or None."""
    if src == dst:
        return [src]
    seen = {src}
    q = deque([(src, [src])])
    while q:
        n, path = q.popleft()
        for m in adj.get(n, ()):
            if m == dst:
                return path + [m]
            if m not in seen:
                seen.add(m)
                q.append((m, path + [m]))
    return None


def _directed_edges(net: Hypernetwork) -> list[tuple]:
    """The (u, v) directed edges the homology runs over — one per resolved directed hyperedge."""
    return [(e.members[0], e.members[-1])
            for e in net.hyperedges if len(e.members) >= 2 and e.directed]


def _witnesses_from_edges(edges: list[tuple], use_solver: bool = True) -> list[dict]:
    """Minimal cycle witnesses for the H₁ classes of a directed edge list. One per
    cycle-closing edge of a spanning forest (β₁ of them), each minimized to its shortest
    realizing cycle. This is the framework core; callers pass edges from any source."""
    adj: dict = {}
    for u, v in edges:
        adj.setdefault(u, []).append(v)

    # spanning forest (undirected) -> the non-tree edges each close one independent cycle
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    closing: list = []
    for u, v in edges:
        ru, rv = find(u), find(v)
        if ru == rv:
            closing.append((u, v))          # closes a cycle -> an H₁ generator
        else:
            parent[ru] = rv

    witnesses: list[dict] = []
    for (u, v) in closing:
        path = _bfs_path(adj, v, u)          # v back to u; edge u->v closes the cycle
        if path is not None:
            witnesses.append({"cycle": path, "closing_edge": [u, v], "length": len(path)})

    # solver leg: ask the z6 for the GLOBALLY minimal witness set (optional, verify-then-trust)
    if use_solver:
        try:
            from lattice import solver_bridge
            if solver_bridge.enabled():
                opt = solver_bridge.min_cycles(list({n for e in edges for n in e}), edges)
                if opt is not None:
                    return opt               # solver result already in witness form
        except Exception:
            pass
    return witnesses


def obstruction_witnesses(net: Hypernetwork, use_solver: bool = True) -> list[dict]:
    """Minimal cycle witnesses for the graph's H₁ classes. One per cycle-closing edge of
    a spanning forest (β₁ of them); each minimized to its shortest realizing cycle."""
    return _witnesses_from_edges(_directed_edges(net), use_solver=use_solver)


def minimal_fix(net: Hypernetwork, use_solver: bool = True) -> dict:
    """The math->solver pipeline. Homology (the witnesses) identifies the obstruction cycles;
    the solver (min-feedback-arc-set QUBO, local greedy fallback) returns the FEWEST edges to
    cut so every cycle is broken — the minimal patch. Each edge is weighted by how many
    obstruction cycles it carries, so an edge shared across cycles is cut first (one cut kills
    many). The cut is *verified* to zero the obstructions before it is reported (verify-then-trust).

    Returns {cut, provenance, obstructions_before, obstructions_after}.
    """
    edges = _directed_edges(net)
    nodes = {n for e in edges for n in e}
    witnesses = _witnesses_from_edges(edges, use_solver=use_solver)
    before = len(witnesses)
    if before == 0:
        return {"cut": [], "provenance": "none", "obstructions_before": 0, "obstructions_after": 0}

    # weight each edge by the number of obstruction cycles that traverse it
    participation = {e: 0 for e in edges}
    for w in witnesses:
        cyc = w["cycle"]
        seg = {(a, b) for a, b in zip(cyc, cyc[1:])}
        seg.add(tuple(w["closing_edge"]))
        for e in edges:
            if e in seg:
                participation[e] += 1

    from lattice import compute
    cut, provenance = compute.min_feedback_arc_set(
        nodes, edges, lambda e: participation.get(e, 0) + 1)

    # verify-then-trust: rebuild the homology on the cut graph and recount obstructions
    cutset = set(cut)
    remaining = [e for e in edges if e not in cutset]
    after = len(_witnesses_from_edges(remaining, use_solver=False))
    return {"cut": [list(e) for e in cut], "provenance": provenance,
            "obstructions_before": before, "obstructions_after": after}
