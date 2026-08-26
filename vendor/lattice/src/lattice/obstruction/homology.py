# src/lattice/obstruction/homology.py
"""First homology of the dependency 1-complex (RRT 01a/01b).

The hypernetwork is a 1-complex: vertices are 0-cells, edges are 1-cells. For a
graph the Betti numbers are exact and cheap:
    b0 = number of connected components
    b1 = E - V + b0      (number of independent cycles / cycle-space rank)

b1 > 0 is the *necessary* condition for an H1 obstruction; whether a cycle actually
obstructs depends on the constraint chain (see witness.py).
"""
from __future__ import annotations

from lattice.graph.models import Hypernetwork


def _undirected_edges(net: Hypernetwork) -> list[tuple[str, str]]:
    out = []
    for e in net.hyperedges:
        if len(e.members) < 2:
            continue
        a, b = e.members[0], e.members[-1]
        if a != b:
            out.append((a, b))
    return out


def betti(net: Hypernetwork) -> dict:
    verts = [v.id for v in net.vertices]
    idx = {vid: i for i, vid in enumerate(verts)}
    parent = list(range(len(verts)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    edges = _undirected_edges(net)
    for a, b in edges:
        if a in idx and b in idx:
            union(idx[a], idx[b])

    V = len(verts)
    E = len(edges)
    b0 = len({find(i) for i in range(V)}) if V else 0
    return {"b0": b0, "b1": E - V + b0, "V": V, "E": E}
