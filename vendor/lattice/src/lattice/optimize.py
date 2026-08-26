# src/lattice/optimize.py
"""Optimize — structural improvement suggestions.

Two levers the graph can justify:
  - break_cycle:    minimal edges to remove to make a dependency cycle acyclic
                    (min feedback arc set — routed through the compute seam; the
                    solver QUBO leg gives the optimal cut, local gives a greedy one)
  - reduce_coupling: high-degree (fan_in + fan_out) hotspots worth splitting

Each suggestion is scored and carries provenance (which legs computed it).
"""
from __future__ import annotations
from dataclasses import dataclass, asdict

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView
from lattice.compute import min_feedback_arc_set


@dataclass
class Optimization:
    kind: str           # break_cycle | reduce_coupling
    action: str
    targets: list
    rationale: str
    score: float
    provenance: str = "local"

    def to_dict(self) -> dict:
        return asdict(self)


def _directed_edges(net: Hypernetwork) -> list[tuple[str, str]]:
    out = []
    for e in net.hyperedges:
        if len(e.members) < 2:
            continue
        a, b = e.members[0], e.members[-1]
        if a != b:
            out.append((a, b))
    return out


def optimize(net: Hypernetwork, hotspot_threshold: int = 8) -> list[Optimization]:
    g = GraphView(net)
    dedges = _directed_edges(net)
    suggestions: list[Optimization] = []

    # --- break cycles: minimal feedback arc set per strongly-connected component ---
    for scc in (c for c in g.find_cycles() if len(c) > 1):
        internal = [(a, b) for (a, b) in dedges if a in scc and b in scc]

        def weight(edge):
            a, b = edge
            return g.fan_out(a) + g.fan_in(b)

        cut, prov = min_feedback_arc_set(set(scc), internal, weight)
        for a, b in cut:
            suggestions.append(Optimization(
                kind="break_cycle",
                action=f"remove dependency {a} -> {b}",
                targets=[a, b],
                rationale=f"breaks a dependency cycle over {sorted(scc)}",
                score=float(weight((a, b))),
                provenance=prov,
            ))

    # --- reduce coupling: high-degree hotspots ---
    for v in net.vertices:
        if v.kind in ("external", "module"):
            continue
        deg = g.fan_in(v.id) + g.fan_out(v.id)
        if deg >= hotspot_threshold:
            suggestions.append(Optimization(
                kind="reduce_coupling",
                action=f"split or decouple {v.id}",
                targets=[v.id],
                rationale=f"high coupling: fan_in={g.fan_in(v.id)}, fan_out={g.fan_out(v.id)}",
                score=float(deg),
            ))

    suggestions.sort(key=lambda o: -o.score)
    return suggestions
