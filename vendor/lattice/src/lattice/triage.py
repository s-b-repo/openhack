# src/lattice/triage.py
"""Triage — turn the bug hunt into a prioritized worklist.

priority = severity_weight x (1 + blast_radius). Severity says how bad, blast
radius (impact analysis) says how far it reaches. Their product is what you fix
first. The ranking step routes through the compute seam (solver `triage`/`skim`
when wired, local sort otherwise).
"""
from __future__ import annotations
from dataclasses import dataclass, asdict

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView
from lattice.hunt import hunt
from lattice.impact import impact
from lattice.compute import rank_desc

_WEIGHT = {"critical": 8, "high": 4, "medium": 2, "low": 1}


@dataclass
class TriagedItem:
    kind: str
    severity: str
    symbol: str
    detail: str
    blast_radius: int
    priority: int
    provenance: str = "local"

    def to_dict(self) -> dict:
        return asdict(self)


def triage(net: Hypernetwork) -> list[TriagedItem]:
    vids = {v.id for v in net.vertices}
    g = GraphView(net)                 # ONE adjacency index for every impact() call
    items: list[TriagedItem] = []
    for b in hunt(net):
        blast = impact(net, b.symbol, g=g).blast_radius if b.symbol in vids else 0
        priority = _WEIGHT[b.severity] * (1 + blast)
        items.append(TriagedItem(
            kind=b.kind, severity=b.severity, symbol=b.symbol, detail=b.detail,
            blast_radius=blast, priority=priority,
        ))

    ranked, prov = rank_desc(items, score=lambda t: t.priority)
    for t in ranked:
        t.provenance = prov
    return ranked
