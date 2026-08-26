# src/lattice/blindspots.py
"""The keystone — surface where path-following goes dark, as loudly as the findings.

Perfect completeness is impossible (dynamic dispatch, reflection, runtime config, code
the tool can't see). So "complete" means: follow what's followable, and explicitly flag
every place the map ends. A tool that silently stops at an unfollowable path is the
silently-wrong failure; a tool that says "here are the N places the trail went cold, by
category" is honestly complete — and only that version lets an agent judge, because it
knows exactly where to trust the map and where to go look itself.

Three categories of darkness, all graph-facts (no guessing):
  - leaves_to_unmapped: paths that exit into code we don't have a graph for (libraries,
    externals) — handoffs, not dead ends; map the other side to follow them through.
  - unresolved: paths that point at nothing — a broken/dangling reference.
  - unreached: code no followed path reaches — EITHER dead, OR reached by a path type the
    tool doesn't yet follow (dynamic dispatch, JSX render, reflection). A known-unknown,
    not a verdict.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView
from lattice.hunt import _is_test, _is_runtime_callback, INBOUND_FLOW_KINDS


@dataclass
class BlindSpots:
    leaves_to_unmapped: list = field(default_factory=list)   # exits to code we don't have
    unresolved: list = field(default_factory=list)           # references that point at nothing
    unreached: list = field(default_factory=list)            # code no followed path reaches
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"leaves_to_unmapped": self.leaves_to_unmapped, "unresolved": self.unresolved,
                "unreached": self.unreached, "summary": self.summary}


def blindspots(net: Hypernetwork, source_root=None) -> BlindSpots:
    g = GraphView(net)
    external_ids = {v.id for v in net.vertices if v.kind == "external"}

    # 1. paths that leave into code we don't have a graph for. With source, name the real
    #    libraries (exposure) — the graph alone collapses every external to one coarse
    #    "unknown" placeholder, which silently under-reports the boundaries that matter.
    leaves: list[str] = []
    if source_root is not None:
        try:
            from lattice.exposure import library_exposure
            leaves = sorted({e.library for e in library_exposure(net, source_root)})
        except Exception:
            leaves = []
    if not leaves:
        # no TS library handoffs resolved (or a non-TS graph, e.g. Solidity) — fall back
        # to the graph's external endpoints: every place a path leaves to code we lack.
        leaves = sorted({v.name for v in net.vertices if v.kind == "external"})

    # 2. paths that point at nothing — dangling/broken internal references (external
    #    targets are expected-unknown, not broken, so they belong to category 1)
    unresolved = sorted(
        f"{e.kind}: {e.members[0]} -> {e.members[-1]}"
        for e in net.hyperedges
        if not e.resolved and e.members and e.members[-1] not in external_ids)

    # 3. code no followed path reaches — dead, OR reached via a path type we don't follow
    entry = {s.vertex_id for s in net.surfaces if s.kind in ("entrypoint", "public_api")}
    unreached = sorted(
        v.id for v in net.vertices
        if v.kind in ("function", "method") and not v.exported and v.id not in entry
        and not _is_test(v.file) and not _is_runtime_callback(v.name)
        and g.fan_in(v.id, kinds=INBOUND_FLOW_KINDS) == 0)

    summary = {"leaves_to_unmapped": len(leaves), "unresolved": len(unresolved),
               "unreached": len(unreached),
               "total_dark": len(leaves) + len(unresolved) + len(unreached)}
    return BlindSpots(leaves, unresolved, unreached, summary)
