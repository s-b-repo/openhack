# src/lattice/diagnose.py
"""Footings diagnostics — the microscope.

Runs every structural signal the query lens can compute over a (possibly polyglot)
hypernetwork and surfaces them as one report: circular dependencies, dead code,
unimplemented stubs, coupling hotspots, broken/dangling edges, and cross-language
reconciliation candidates. This is the layer that turns the graph from a map into
an instrument you point at a codebase.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView
from lattice.complete.gate import check
from lattice.reconcile.engine import reconcile
from lattice.obstruction.homology import betti
from lattice.obstruction.witness import extract_witnesses

# A vertex is "real code" for hotspot/dead-code purposes if it's not a synthetic
# module node or an external placeholder.
_REAL = lambda v: v.kind not in ("external", "module")


@dataclass
class Diagnostics:
    cycles: list[list[str]] = field(default_factory=list)
    dead_code: list[str] = field(default_factory=list)
    stubs: list[str] = field(default_factory=list)
    hotspots: list[dict] = field(default_factory=list)
    dangling_edges: list[str] = field(default_factory=list)
    unresolved_imports: list[str] = field(default_factory=list)
    reconciliation_candidates: list[dict] = field(default_factory=list)
    obstructions: list[dict] = field(default_factory=list)   # RRT H1 contradiction witnesses
    betti: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def diagnose(net: Hypernetwork, hotspot_top: int = 10) -> Diagnostics:
    g = GraphView(net)
    report = check(net)

    cycles = [sorted(c) for c in g.find_cycles()]
    dead_code = sorted(g.dead_code())
    stubs = sorted(v.id for v in net.vertices if v.stub)

    # Coupling hotspots: real-code vertices ranked by total degree (fan_in + fan_out).
    real = [v for v in net.vertices if _REAL(v)]
    ranked = sorted(real, key=lambda v: g.fan_in(v.id) + g.fan_out(v.id), reverse=True)
    hotspots = [
        {"id": v.id, "fan_in": g.fan_in(v.id), "fan_out": g.fan_out(v.id)}
        for v in ranked
        if g.fan_in(v.id) + g.fan_out(v.id) > 0
    ][:hotspot_top]

    candidates = [
        {"members": e.members, "confidence": e.confidence, "provenance": e.provenance}
        for e in reconcile(net)
    ]

    # RRT obstruction layer: minimal H1 contradiction witnesses + Betti numbers.
    obstructions = [w.to_dict() for w in extract_witnesses(net)]
    b = betti(net)

    issues = bool(cycles or dead_code or stubs or report.dangling_edges
                  or report.unresolved_imports or obstructions)
    summary = {
        "verdict": "issues" if issues else "clean",
        "vertices": len(net.vertices),
        "cycles": len(cycles),
        "dead_code": len(dead_code),
        "stubs": len(stubs),
        "dangling_edges": len(report.dangling_edges),
        "unresolved_imports": len(report.unresolved_imports),
        "reconciliation_candidates": len(candidates),
        "obstructions": len(obstructions),
        "b1": b["b1"],
        "resolution": report.resolution,
    }

    return Diagnostics(
        cycles=cycles,
        dead_code=dead_code,
        stubs=stubs,
        hotspots=hotspots,
        dangling_edges=list(report.dangling_edges),
        unresolved_imports=list(report.unresolved_imports),
        reconciliation_candidates=candidates,
        obstructions=obstructions,
        betti=b,
        summary=summary,
    )
