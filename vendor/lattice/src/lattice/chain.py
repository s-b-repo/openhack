# src/lattice/chain.py
"""GF(2) chain complex — the foundation every OMNI topology framework bottoms out at.

Ported from OMNI's matrix.ts: homology over Z₂ from boundary matrices ∂ₙ, where
Hₙ = ker(∂ₙ)/im(∂ₙ₊₁) and βₙ = nullity(∂ₙ) − rank(∂ₙ₊₁). The key the synthesis surfaced:
a graph alone is only a 1-complex (β₁ = raw cycle rank). It's the 2-CELLS — supplied by
the typed constraint algebra (which edges co-satisfy / contradict) — that make a cycle
BOUND, separating a real obstruction from a benign loop. Homology, sheaf, persistent,
spectral, and Morse all consume this same complex; build it once.
"""
from __future__ import annotations


def gf2_rank(rows: list[list[int]]) -> int:
    """Rank of a {0,1} matrix over Z₂ (Gaussian elimination)."""
    rows = [r[:] for r in rows]
    if not rows:
        return 0
    ncols = len(rows[0])
    r = 0
    for c in range(ncols):
        piv = next((i for i in range(r, len(rows)) if rows[i][c]), None)
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for i in range(len(rows)):
            if i != r and rows[i][c]:
                rows[i] = [a ^ b for a, b in zip(rows[i], rows[r])]
        r += 1
        if r == len(rows):
            break
    return r


def gf2_kernel(rows: list[list[int]], ncols: int) -> list[list[int]]:
    """Null-space basis over Z₂ of a matrix with `ncols` columns."""
    rows = [r[:] for r in rows]
    pivots: dict[int, int] = {}
    r = 0
    for c in range(ncols):
        piv = next((i for i in range(r, len(rows)) if rows[i][c]), None)
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for i in range(len(rows)):
            if i != r and rows[i][c]:
                rows[i] = [a ^ b for a, b in zip(rows[i], rows[r])]
        pivots[c] = r
        r += 1
    basis = []
    for f in (c for c in range(ncols) if c not in pivots):
        vec = [0] * ncols
        vec[f] = 1
        for c, rr in pivots.items():
            vec[c] = rows[rr][f]
        basis.append(vec)
    return basis


def transpose(m: list[list[int]]) -> list[list[int]]:
    """mᵀ. gf2_kernel(transpose(D)) computes coker(D) = H¹ — the only primitive the
    sheaf-coboundary leg was missing."""
    if not m:
        return []
    return [list(col) for col in zip(*m)]


def _echelon_pivots(rows: list[list[int]], ncols: int) -> list[list[int]]:
    """Reduced pivot rows of a {0,1} matrix over Z₂ (each pivot column unique)."""
    rows = [r[:] for r in rows]
    out: list[list[int]] = []
    r = 0
    for c in range(ncols):
        piv = next((i for i in range(r, len(rows)) if c < len(rows[i]) and rows[i][c]), None)
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for i in range(len(rows)):
            if i != r and c < len(rows[i]) and rows[i][c]:
                rows[i] = [a ^ b for a, b in zip(rows[i], rows[r])]
        out.append(rows[r])
        r += 1
        if r == len(rows):
            break
    return out


def is_in_span(vec: list[int], basis: list[list[int]]) -> bool:
    """Is `vec` in the Z₂-span of `basis`? Reduce vec by the basis's pivot rows; in span iff
    it reduces to zero. (Port of matrix.ts isInSpan — the membership test the H₁ quotient needs.)"""
    if not any(vec):
        return True
    ncols = len(vec)
    v = vec[:]
    for row in _echelon_pivots(basis, ncols):
        c = next((j for j in range(ncols) if row[j]), None)   # this row's pivot column
        if c is not None and v[c]:
            v = [a ^ b for a, b in zip(v, row)]
    return not any(v)


def homology_representatives(ker_basis: list[list[int]], im_basis: list[list[int]]) -> list[list[int]]:
    """A basis of H₁ = ker(∂₁)/im(∂₂): keep each kernel cycle only if it is NOT already in the
    span of im(∂₂) together with the cycles kept so far. These are the genuine, non-bounding
    obstruction representatives — the ones a 2-cell does not kill."""
    kept: list[list[int]] = []
    span = [r[:] for r in im_basis]
    for vec in ker_basis:
        if not is_in_span(vec, span):
            kept.append(vec)
            span = span + [vec]
    return kept


def _image_columns(mat: list[list[int]], nrows: int) -> list[list[int]]:
    """Column vectors of `mat` (each of length nrows) — a spanning set of its image."""
    if not mat or not mat[0]:
        return []
    ncols = len(mat[0])
    return [[mat[r][c] for r in range(nrows)] for c in range(ncols)]


def _boundary_1(verts: list[str], edges: list[tuple]) -> list[list[int]]:
    """∂₁ : C₁ → C₀ over Z₂ — rows = vertices, cols = edges (incidence)."""
    vidx = {v: i for i, v in enumerate(verts)}
    m = [[0] * len(edges) for _ in verts]
    for j, (u, v) in enumerate(edges):
        if u in vidx:
            m[vidx[u]][j] ^= 1
        if v in vidx:
            m[vidx[v]][j] ^= 1
    return m


def _boundary_2(num_edges: int, two_cells: list[list[int]]) -> list[list[int]]:
    """∂₂ : C₂ → C₁ over Z₂ — rows = edges, cols = 2-cells (each = its boundary edge ids)."""
    m = [[0] * len(two_cells) for _ in range(num_edges)]
    for j, cell in enumerate(two_cells):
        for e in cell:
            m[e][j] ^= 1
    return m


def betti_1(verts: list[str], edges: list[tuple], two_cells: list[list[int]] | None = None) -> int:
    """β₁ = nullity(∂₁) − rank(∂₂). With 2-cells from the constraint algebra, benign cycles
    bound and drop out; only genuine obstructions remain."""
    two_cells = two_cells or []
    rank1 = gf2_rank(_boundary_1(verts, edges))
    nullity1 = len(edges) - rank1
    rank2 = gf2_rank(_boundary_2(len(edges), two_cells)) if two_cells else 0
    return nullity1 - rank2


def h1_representatives(verts: list[str], edges: list[tuple],
                      two_cells: list[list[int]] | None = None) -> list[list[tuple]]:
    """H₁ generators as edge cycles — the obstruction witnesses. A representative is a cycle in
    ker(∂₁) that is NOT in im(∂₂): the constraint 2-cells make benign cycles bound, and those
    are quotiented out here so only genuine obstructions remain. (Agrees with betti_1.)"""
    two_cells = two_cells or []
    ker = gf2_kernel(_boundary_1(verts, edges), len(edges))
    im = _image_columns(_boundary_2(len(edges), two_cells), len(edges)) if two_cells else []
    out = []
    for vec in homology_representatives(ker, im):
        cyc = [edges[i] for i in range(len(edges)) if vec[i]]
        if cyc:
            out.append(cyc)
    return out
