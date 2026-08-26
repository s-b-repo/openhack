# src/lattice/obstruction/witness.py
"""Minimal contradiction witnesses (RRT 01b obstruction theorem, sec. 5).

An obstruction exists where a cycle CARRIES a broken constraint. The witness is the
*minimal* such subnetwork: the shortest cycle through a broken edge. We find it by
removing the broken edge and BFS-ing the shortest alternate path between its
endpoints — if one exists, that path plus the broken edge is the minimal cycle that
cannot be consistently resolved (a `contradiction`, in RRT regression terms). If no
alternate path exists, the broken edge is a bridge: a beta_0 `destruction`, not an
H1 contradiction, so it is NOT reported here (the completeness gate handles those).
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, asdict

from lattice.graph.models import Hypernetwork


@dataclass
class Witness:
    kind: str                 # "contradiction"
    broken_edge: tuple        # (src, tgt) of the unsatisfied constraint
    cycle: list               # vertex ids forming the minimal inconsistent cycle
    cycle_len: int
    energy: float             # how "stuck": tighter cycle -> higher energy

    def to_dict(self) -> dict:
        return asdict(self)


def _adjacency(net: Hypernetwork, exclude: tuple | None = None):
    adj: dict[str, set] = {}
    skipped = False
    for e in net.hyperedges:
        if len(e.members) < 2:
            continue
        a, b = e.members[0], e.members[-1]
        if a == b:
            continue
        if exclude is not None and not skipped and {a, b} == set(exclude):
            skipped = True            # drop exactly one instance of the broken edge
            continue
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)
    return adj


def _shortest_path(adj, src, dst):
    if src not in adj or dst not in adj:
        return None
    prev = {src: None}
    q = deque([src])
    while q:
        n = q.popleft()
        if n == dst:
            path = []
            while n is not None:
                path.append(n)
                n = prev[n]
            return path[::-1]
        for nb in adj.get(n, ()):
            if nb not in prev:
                prev[nb] = n
                q.append(nb)
    return None


def extract_witnesses(net: Hypernetwork) -> list[Witness]:
    external = {v.id for v in net.vertices if v.kind == "external"}
    seen: set = set()
    witnesses: list[Witness] = []

    for e in net.hyperedges:
        if e.resolved or len(e.members) < 2:
            continue
        a, b = e.members[0], e.members[-1]
        if a == b or a in external or b in external:
            continue            # external (npm) breaks aren't internal obstructions
        key = frozenset((a, b))
        if key in seen:
            continue

        # shortest alternate path b<-...->a with the broken edge removed
        alt = _shortest_path(_adjacency(net, exclude=(a, b)), a, b)
        if alt is None:
            continue            # bridge -> destruction, not an H1 contradiction
        seen.add(key)
        witnesses.append(Witness(
            kind="contradiction",
            broken_edge=(a, b),
            cycle=alt,
            cycle_len=len(alt),
            energy=1.0 / len(alt),
        ))
    return witnesses
