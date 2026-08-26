# src/lattice/graph/query.py
"""GraphView — the query lens over a Hypernetwork.

The hypernetwork is a map; GraphView is what lets you point at things. It builds
forward/reverse adjacency indices over the existing directed hyperedges and
exposes the primitives every 'microscope mode' is built from:

  refactor    -> references_to(vid)            (safe-rename impact set)
  audit       -> surfaces(kind)                (inventory the attack/api surface)
  security    -> surfaces_reaching(sink, kind) (which entrypoints reach a sink)
  bug-hunt    -> find_cycles(), dead_code()    (structural defects)

It is pure (no LSP, no IO) and operates on whatever edges exist — it gets sharper
automatically as edge ingestion is enriched, with no change here.
"""
from __future__ import annotations
from collections import defaultdict

from lattice.graph.models import Hypernetwork, Surface


def _src_tgt(members: list[str]) -> tuple[str, str] | None:
    if len(members) < 2:
        return None
    return members[0], members[-1]


class GraphView:
    def __init__(self, net: Hypernetwork):
        self._v = {v.id: v for v in net.vertices}
        self._surfaces = list(net.surfaces)
        self._out: dict[str, list[tuple[str, str]]] = defaultdict(list)  # src -> [(kind, tgt)]
        self._in: dict[str, list[tuple[str, str]]] = defaultdict(list)   # tgt -> [(kind, src)]
        for e in net.hyperedges:
            st = _src_tgt(e.members)
            if st is None:
                continue
            src, tgt = st
            self._out[src].append((e.kind, tgt))
            self._in[tgt].append((e.kind, src))

    # --- vertex access ---
    def vertex(self, vid: str):
        return self._v.get(vid)

    def _filter(self, pairs, kinds):
        if kinds is None:
            return [t for _, t in pairs]
        ks = {kinds} if isinstance(kinds, str) else set(kinds)
        return [t for k, t in pairs if k in ks]

    # --- adjacency (refactor: who uses X / what does X use) ---
    def references_to(self, vid: str, kinds=None) -> list[str]:
        """Inbound: every vertex that points at `vid`. The rename/delete blast radius."""
        return self._filter(self._in.get(vid, []), kinds)

    def out_neighbors(self, vid: str, kinds=None) -> list[str]:
        return self._filter(self._out.get(vid, []), kinds)

    def fan_in(self, vid: str, kinds=None) -> int:
        return len(self.references_to(vid, kinds))

    def fan_out(self, vid: str, kinds=None) -> int:
        return len(self.out_neighbors(vid, kinds))

    # --- reachability (triage: what can this entrypoint touch) ---
    def reachable_from(self, vid: str, kinds=None, avoid=None) -> set[str]:
        """Forward transitive closure, excluding the seed (set of descendants).
        `avoid` removes those nodes from the graph — used to test whether a sink is
        reachable WITHOUT crossing a gate (guarded reachability)."""
        avoid = avoid or frozenset()
        seen: set[str] = set()
        stack = [n for n in self.out_neighbors(vid, kinds) if n not in avoid]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(x for x in self.out_neighbors(n, kinds) if x not in avoid)
        seen.discard(vid)   # descendants only; cycle membership belongs to find_cycles()
        return seen

    def reaches(self, src: str, dst: str, kinds=None) -> bool:
        return dst in self.reachable_from(src, kinds)

    def dependents(self, vid: str, kinds=None) -> set[str]:
        """Transitive reverse reachability — everything that depends on `vid`,
        directly or indirectly. The change/delete blast radius. Mirror of
        reachable_from over the reverse graph; excludes the seed."""
        seen: set[str] = set()
        stack = list(self.references_to(vid, kinds))
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(self.references_to(n, kinds))
        seen.discard(vid)
        return seen

    def paths(self, src: str, dst: str, kinds=None, max_len: int = 12,
              max_paths: int = 256) -> list[tuple[str, ...]]:
        """Simple paths src->dst up to max_len hops. Capped at max_paths — simple-path
        enumeration is exponential, so an uncapped call on a dense graph never returns."""
        out: list[tuple[str, ...]] = []

        def dfs(node: str, trail: tuple[str, ...]):
            if len(out) >= max_paths or len(trail) > max_len:
                return
            for nxt in self.out_neighbors(node, kinds):
                if nxt in trail:
                    continue
                if nxt == dst:
                    out.append(trail + (nxt,))
                else:
                    dfs(nxt, trail + (nxt,))
                if len(out) >= max_paths:
                    return

        dfs(src, (src,))
        return out

    def shortest_path(self, src: str, dst: str, kinds=None, avoid=None) -> list[str] | None:
        """One shortest path src->dst via BFS — O(V+E). Use this instead of paths()
        when a single example route suffices (e.g. source->sink in a security audit).
        `avoid` removes nodes — used to exhibit an *ungated* route to a sink."""
        if src == dst:
            return [src]
        avoid = avoid or frozenset()
        from collections import deque
        prev = {src: None}
        q = deque([src])
        while q:
            n = q.popleft()
            for nb in self.out_neighbors(n, kinds):
                if nb in prev or nb in avoid:
                    continue
                prev[nb] = n
                if nb == dst:
                    path = [dst]
                    cur = n
                    while cur is not None:
                        path.append(cur)
                        cur = prev[cur]
                    return path[::-1]
                q.append(nb)
        return None

    # --- surfaces (audit + security) ---
    def surfaces(self, kind: str | None = None) -> list[Surface]:
        if kind is None:
            return list(self._surfaces)
        return [s for s in self._surfaces if s.kind == kind]

    def surfaces_reaching(self, target: str, surface_kind: str | None = None) -> list[str]:
        """Which surface-backed vertices can reach `target` — e.g. which public_api
        entrypoints flow into a given sink. The core security-triage query."""
        out: list[str] = []
        for s in self.surfaces(surface_kind):
            if s.vertex_id == target or self.reaches(s.vertex_id, target):
                out.append(s.vertex_id)
        return out

    # --- structural defects (bug-hunt) ---
    def find_cycles(self) -> list[frozenset[str]]:
        """Strongly-connected components of size > 1 (plus self-loops) — import or
        call cycles. Tarjan's algorithm over all directed edges, iterative so a
        deep dependency chain can't blow the recursion limit."""
        index: dict[str, int] = {}
        low: dict[str, int] = {}
        on_stack: set[str] = set()
        stack: list[str] = []
        counter = 0
        sccs: list[frozenset[str]] = []

        for root in list(self._v):
            if root in index:
                continue
            index[root] = low[root] = counter
            counter += 1
            stack.append(root)
            on_stack.add(root)
            work = [(root, iter(self.out_neighbors(root)))]
            while work:
                v, neighbors = work[-1]
                descended = False
                for w in neighbors:
                    if w not in index:
                        index[w] = low[w] = counter
                        counter += 1
                        stack.append(w)
                        on_stack.add(w)
                        work.append((w, iter(self.out_neighbors(w))))
                        descended = True
                        break
                    if w in on_stack:
                        low[v] = min(low[v], index[w])
                if descended:
                    continue
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[v])
                if low[v] == index[v]:
                    comp = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp.append(w)
                        if w == v:
                            break
                    if len(comp) > 1:
                        sccs.append(frozenset(comp))
        # self-loops (a vertex that calls itself)
        for v in self._v:
            if v in self.out_neighbors(v):
                sccs.append(frozenset({v}))
        return sccs

    def dead_code(self, roots: list[str] | None = None) -> list[str]:
        """Symbol vertices unreachable from any root. Roots default to the vertices
        backing public_api / entrypoint surfaces (the legitimate ways in).
        External and module vertices are never reported."""
        if roots is None:
            roots = [s.vertex_id for s in self._surfaces
                     if s.kind in ("public_api", "entrypoint")]
        live: set[str] = set(roots)
        for r in roots:
            live |= self.reachable_from(r)
        dead = []
        for vid, v in self._v.items():
            if v.kind in ("external", "module"):
                continue
            if vid not in live:
                dead.append(vid)
        return dead
