# src/lattice/impact.py
"""Impact analysis — the change blast radius.

Given a target symbol, report everything that transitively depends on it: the set
of symbols, files, and public-API surfaces that a change to (or deletion of) the
target could affect. This is reverse-reachability over the graph — the query an
agent should run *before* editing anything.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView


@dataclass
class ImpactReport:
    target: str
    direct_dependents: list[str] = field(default_factory=list)
    transitive_dependents: list[str] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    affected_public_api: list[str] = field(default_factory=list)
    blast_radius: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def resolve_targets(net: Hypernetwork, query: str) -> list[str]:
    """Resolve a user query to vertex ids. Exact id/name matches win; if there are
    none, fall back to substring matches on the id."""
    exact = [v.id for v in net.vertices if v.id == query or v.name == query]
    if exact:
        return exact
    return [v.id for v in net.vertices if query in v.id]


def follow(net: Hypernetwork, vid: str, max_paths: int = 100, max_len: int = 16) -> list[tuple]:
    """Trace the impact *chains*: paths from `vid` outward through its dependents to
    each top-level caller (a dependent nothing else depends on). Shows *how* a change
    propagates, not just the set it reaches."""
    g = GraphView(net)
    paths: list[tuple] = []

    def dfs(node: str, trail: list[str]):
        if len(paths) >= max_paths:
            return
        nexts = [r for r in g.references_to(node) if r not in trail]
        if not nexts or len(trail) >= max_len:
            if len(trail) > 1:
                paths.append(tuple(trail))
            return
        for r in nexts:
            dfs(r, trail + [r])

    dfs(vid, [vid])
    return paths


def impact(net: Hypernetwork, vid: str, g: GraphView | None = None) -> ImpactReport:
    g = g if g is not None else GraphView(net)
    vmap = {v.id: v for v in net.vertices}

    direct = sorted(g.references_to(vid))
    transitive = g.dependents(vid)
    files = sorted({vmap[d].file for d in transitive if d in vmap})
    public_ids = {s.vertex_id for s in net.surfaces if s.kind == "public_api"}
    affected_public_api = sorted(d for d in transitive if d in public_ids)

    return ImpactReport(
        target=vid,
        direct_dependents=direct,
        transitive_dependents=sorted(transitive),
        affected_files=files,
        affected_public_api=affected_public_api,
        blast_radius=len(transitive),
    )
