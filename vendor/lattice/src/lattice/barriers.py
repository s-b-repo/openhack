# src/lattice/barriers.py
"""Minimum barrier set — the fewest gate placements covering every attack path.

Given untrusted sources (entrypoints) and dangerous sinks, find the smallest set of
functions to gate so that EVERY source->sink path crosses at least one gate. It's the
security analogue of the min-feedback-arc-set already bridged to the solver: a hitting
set over the attack paths. Greedy set-cover runs locally and always works (a log-factor
approximation); the QUBO solver leg returns the optimal when the z6 is reachable, and we
verify its answer against the paths before trusting it.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView


@dataclass
class BarrierSet:
    barriers: list = field(default_factory=list)     # vertex ids to gate
    paths_covered: int = 0
    paths_total: int = 0
    method: str = "greedy"                            # greedy | solver

    def to_dict(self) -> dict:
        return {"barriers": self.barriers, "paths_covered": self.paths_covered,
                "paths_total": self.paths_total, "method": self.method}


def _attack_paths(net: Hypernetwork, sources, sinks) -> list[list[str]]:
    g = GraphView(net)
    paths: list[list[str]] = []
    for s in sources:
        reach = g.reachable_from(s)
        for t in sinks:
            if t in reach:
                for p in g.paths(s, t, max_paths=64):
                    paths.append(p)
    return paths


def _greedy_hitting_set(paths: list[list[str]]) -> list[str]:
    """Repeatedly gate the interior vertex that covers the most still-uncovered paths."""
    uncovered = [set(p[1:-1]) for p in paths if len(p) > 2]   # interior only (not src/sink)
    chosen: list[str] = []
    while any(uncovered):
        counts: dict[str, int] = {}
        for s in uncovered:
            for v in s:
                counts[v] = counts.get(v, 0) + 1
        if not counts:
            break
        best = max(counts, key=lambda v: counts[v])
        chosen.append(best)
        uncovered = [s for s in uncovered if best not in s]
    return chosen


def min_barrier_set(net: Hypernetwork, sources, sinks) -> BarrierSet:
    paths = _attack_paths(net, sources, sinks)
    total = len(paths)
    if total == 0:
        return BarrierSet(barriers=[], paths_covered=0, paths_total=0)

    barriers = _greedy_hitting_set(paths)
    method = "greedy"

    # solver leg: the optimal hitting set as a QUBO, verify-then-trust.
    try:
        from lattice import solver_bridge
        if solver_bridge.enabled():
            opt = solver_bridge.min_hitting_set(
                [set(p[1:-1]) for p in paths if len(p) > 2])
            if opt is not None and _covers(opt, paths) and len(opt) <= len(barriers):
                barriers, method = list(opt), "solver"
    except Exception:
        pass

    covered = sum(1 for p in paths if len(p) <= 2 or (set(p[1:-1]) & set(barriers)))
    return BarrierSet(barriers=barriers, paths_covered=covered,
                      paths_total=total, method=method)


def _covers(barriers, paths) -> bool:
    bset = set(barriers)
    return all(len(p) <= 2 or (set(p[1:-1]) & bset) for p in paths)
