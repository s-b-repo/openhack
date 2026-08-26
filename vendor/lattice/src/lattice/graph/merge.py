# src/lattice/graph/merge.py
"""Merge per-language hypernetworks into one polyglot graph.

Vertex ids are already language-namespaced (`ts-sym:...`, `py-sym:...`), so the
union is collision-free. This is the easy half of multi-language support; the
hard half — linking the same entity ACROSS languages — is the reconcile pass,
which runs on the merged graph this produces.
"""
from __future__ import annotations
from lattice.graph.models import Hypernetwork, Vertex


def merge(nets: list[Hypernetwork], root: str = "<multi>") -> Hypernetwork:
    vertices: dict[str, Vertex] = {}
    hyperedges = []
    surfaces = []
    diagnostics = []
    for net in nets:
        for v in net.vertices:
            vertices.setdefault(v.id, v)
        hyperedges.extend(net.hyperedges)
        surfaces.extend(net.surfaces)
        diagnostics.extend(net.diagnostics)
    return Hypernetwork(language="multi", root=root,
                        vertices=list(vertices.values()),
                        hyperedges=hyperedges, surfaces=surfaces,
                        diagnostics=diagnostics)
