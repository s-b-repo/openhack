# src/lattice/reconcile/engine.py
"""Cross-language reconciliation engine.

Runs over a merged (polyglot) hypernetwork and proposes `reconciles` edges linking
the same logical entity expressed in different languages — a TS `interface User`
and a Python `class User`, a TS API client and a Python route handler, etc.

These are PROPOSALS, not facts: each edge carries a confidence (< 1.0) and a
provenance naming the matcher that produced it. The tool surfaces them; an agent
(or human) confirms or rejects against the source before they become trusted
structure. Matchers are pluggable — `nominal` (name-based heuristic) is the first
tier; contract-anchored matchers (OpenAPI / protobuf / GraphQL) and structural
field-shape matchers plug into the same engine with higher / different confidence.
"""
from __future__ import annotations
from itertools import combinations

from lattice.graph.models import Hypernetwork, Hyperedge, Vertex

# Symbol kinds collapsed into reconciliation categories. Only same-category
# vertices reconcile: a `class User` is a data type, a `function user()` is not.
_CATEGORY = {
    "class": "type", "interface": "type", "type": "type", "struct": "type",
    "function": "callable", "method": "callable",
}


def _lang(vid: str) -> str:
    """Language prefix of a vertex id, e.g. 'ts' from 'ts-sym:a.ts#User'."""
    return vid.split("-sym:", 1)[0]


def nominal(vertices: list[Vertex]) -> list[tuple[str, str, float, str]]:
    """Heuristic tier: exported symbols with the same name + same category in
    DIFFERENT languages are candidate reconciliations. Name-only evidence -> 0.5."""
    eligible = [v for v in vertices
                if v.exported and v.kind in _CATEGORY and v.kind != "external"]
    out: list[tuple[str, str, float, str]] = []
    for a, b in combinations(eligible, 2):
        if _lang(a.id) == _lang(b.id):
            continue                       # same language is not cross-language
        if a.name != b.name:
            continue
        if _CATEGORY[a.kind] != _CATEGORY[b.kind]:
            continue
        out.append((a.id, b.id, 0.5, "nominal"))
    return out


DEFAULT_MATCHERS = [nominal]


def reconcile(net: Hypernetwork, matchers=DEFAULT_MATCHERS) -> list[Hyperedge]:
    """Produce candidate `reconciles` edges from all matchers, de-duplicated by
    member pair (keeping the highest-confidence provenance for each pair)."""
    best: dict[frozenset, tuple[str, str, float, str]] = {}
    for matcher in matchers:
        for a, b, conf, prov in matcher(net.vertices):
            key = frozenset((a, b))
            if key not in best or conf > best[key][2]:
                best[key] = (a, b, conf, prov)

    edges: list[Hyperedge] = []
    for i, (a, b, conf, prov) in enumerate(sorted(best.values()), start=1):
        edges.append(Hyperedge(
            id=f"reconcile-{i}",
            kind="reconciles",
            members=[a, b],
            directed=False,
            resolved=False,           # candidate until confirmed
            confidence=conf,
            provenance=prov,
        ))
    return edges
