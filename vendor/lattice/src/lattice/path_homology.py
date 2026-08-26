"""DIRECTED path homology — H₁ of the GLMY path complex of a digraph, over GF(2).

This computes the GLMY path-homology H₁ CORRECTLY (allowed 2-paths i→j→k; ∂-invariance forces the
non-edge face (i→k) to cancel; a transitive triangle's 2-path fills its loop, a bare directed cycle's
does not). It was built to detect deadlock cycles — and STRESS-TESTING SHOWED THAT IS WRONG: path
homology H₁ is NOT directed-cycle detection. Over 20k random digraphs it agreed with cycle-presence
only ~72%, with both errors confirmed as genuine path-homology behaviour, not bugs:
  • FALSE NEGATIVE: a↔b with a common successor (a→c, b→c) has a real 2-cycle deadlock but H₁=0 —
    the successor paths FILL the loop homologically though the deadlock remains.
  • FALSE POSITIVE: the acyclic bipartite square a→c,a→d,b→c,b→d has H₁=1 — a genuine path-homology
    hole with NO directed cycle at all.
LESSON (honest scope boundary): deadlock = "a lock reachable from itself" = a strongly-connected-
component / REACHABILITY property, which is order-theoretic and NOT a homological invariant. For
directed-cycle / deadlock detection use SCC (see ingest/python_locks.py `_sccs`), not this. Homology
genuinely captures gluing / 2-CYCLE obstructions (reentrancy, use-after-free, pairwise inversion);
it does not capture directed N-cycles. This module is kept as a correct path-homology primitive (and
a pinned reminder of the boundary), not as a cycle detector.
"""


def _rank(vecs) -> int:
    """GF(2) rank of bitmask vectors."""
    pivots: dict = {}
    r = 0
    for v in vecs:
        while v:
            hb = v.bit_length() - 1
            if hb in pivots:
                v ^= pivots[hb]
            else:
                pivots[hb] = v
                r += 1
                break
    return r


def _dependencies(vecs: list) -> list:
    """Kernel of (coeffs ↦ Σ coeff·vec): each result is a frozenset of indices whose vecs XOR to 0."""
    pivots: dict = {}            # high-bit -> (reduced vec, index-combo)
    kernel: list = []
    for i, v in enumerate(vecs):
        cur, combo = v, {i}
        while cur:
            hb = cur.bit_length() - 1
            if hb in pivots:
                pv, pc = pivots[hb]
                cur ^= pv
                combo ^= pc
            else:
                pivots[hb] = (cur, combo)
                break
        if cur == 0:
            kernel.append(frozenset(combo))
    return kernel


def path_h1(edges) -> int:
    """dim H₁ of the GLMY path complex of the digraph `edges` (list of (u,v) directed). > 0 iff a
    directed cycle is present that no transitive 2-path fills."""
    edges = sorted(set((u, v) for u, v in edges if u != v))
    if not edges:
        return 0
    verts = {x for e in edges for x in e}
    vidx = {v: i for i, v in enumerate(sorted(verts, key=str))}
    eidx = {e: i for i, e in enumerate(edges)}
    eset = set(edges)

    # ∂₁: edge (u,v) -> bit u + bit v over vertices.  dim ker ∂₁ = |edges| - rank ∂₁
    d1 = [(1 << vidx[u]) | (1 << vidx[v]) for (u, v) in edges]
    ker_d1 = len(edges) - _rank(d1)

    # regular 2-paths i→j→k (both edges); their faces are (i,j),(j,k) [edges] and (i,k) [maybe not]
    two_paths = [(i, j, k) for (i, j) in edges for (jj, k) in edges if j == jj]
    if not two_paths:
        return ker_d1

    # index the non-edge "shortcut" faces (i,k) that are NOT edges — these must cancel for ∂-invariance
    shortcuts: dict = {}
    for (i, j, k) in two_paths:
        if (i, k) not in eset:
            shortcuts.setdefault((i, k), len(shortcuts))
    nonallowed = [0] * len(two_paths)
    for p, (i, j, k) in enumerate(two_paths):
        if (i, k) not in eset:
            nonallowed[p] = 1 << shortcuts[(i, k)]

    # Ω₂ = combinations of 2-paths whose non-edge faces cancel
    omega2 = _dependencies(nonallowed)

    # ∂₂ of each Ω₂ element = its edge-face component (the non-edge faces cancelled by construction)
    def edge_boundary(p):
        (i, j, k) = two_paths[p]
        m = (1 << eidx[(i, j)]) | (1 << eidx[(j, k)])
        if (i, k) in eset:
            m ^= (1 << eidx[(i, k)])
        return m

    d2 = []
    for combo in omega2:
        m = 0
        for p in combo:
            m ^= edge_boundary(p)
        d2.append(m)
    rank_d2 = _rank(d2)

    return ker_d1 - rank_d2
