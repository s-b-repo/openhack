from lattice.chain import gf2_rank, betti_1, h1_representatives, transpose, is_in_span


def test_gf2_rank():
    assert gf2_rank([[1,0,1],[0,1,1],[1,1,0]]) == 2   # third row = sum of first two over Z2


def test_triangle_has_one_loop_filling_it_kills_the_loop():
    """The chain-complex foundation: β₁ = nullity(∂₁) − rank(∂₂). A triangle (3 edges,
    no 2-cell) has β₁=1; adding the 2-cell that fills it drops β₁ to 0 — a cycle that
    BOUNDS. This is the structure that separates a real obstruction from a benign loop."""
    verts = ["a", "b", "c"]
    edges = [("a","b"), ("b","c"), ("c","a")]      # a triangle = one 1-cycle
    assert betti_1(verts, edges, two_cells=[]) == 1
    # one 2-cell whose boundary is the 3 edges -> the loop now bounds
    assert betti_1(verts, edges, two_cells=[[0,1,2]]) == 0


def test_h1_representative_is_the_cycle():
    verts = ["a","b","c"]; edges = [("a","b"),("b","c"),("c","a")]
    reps = h1_representatives(verts, edges, two_cells=[])
    assert len(reps) == 1 and len(reps[0]) == 3     # one generator, the 3-edge cycle


def test_h1_representatives_quotient_by_two_cells_a_filled_loop_has_no_witness():
    """THE load-bearing fix: a representative must be a NON-bounding cycle. A filled triangle
    has β₁=0, so it must yield ZERO representatives — not the cycle that the 2-cell bounds.
    Without this quotient, sharing storage cells makes every benign guarded loop fire once."""
    verts = ["a","b","c"]; edges = [("a","b"),("b","c"),("c","a")]
    assert betti_1(verts, edges, two_cells=[[0,1,2]]) == 0
    reps = h1_representatives(verts, edges, two_cells=[[0,1,2]])
    assert reps == [], f"filled loop bounds -> no witness, got {len(reps)}"


def test_transpose():
    assert transpose([[1,0,1],[0,1,0]]) == [[1,0],[0,1],[1,0]]
    assert transpose([]) == []


def test_is_in_span_over_gf2():
    basis = [[1,0,1],[0,1,1]]
    assert is_in_span([1,1,0], basis)        # = row0 ^ row1
    assert is_in_span([0,0,0], basis)        # zero is always in span
    assert not is_in_span([1,0,0], basis)    # not reachable from the basis
