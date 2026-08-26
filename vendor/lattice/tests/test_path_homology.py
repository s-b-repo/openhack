"""Pins the DIRECTED-homology variant (GLMY path complex, GF(2)): directed cycles are non-trivial,
transitive/consistent orders bound to zero — the distinction undirected GF(2) homology can't make."""
from lattice.path_homology import path_h1


def test_directed_2cycle_nonzero():        # reentrancy / pairwise inversion
    assert path_h1([("a", "b"), ("b", "a")]) == 1


def test_directed_3cycle_nonzero():        # the N>=3 deadlock that was a blind spot
    assert path_h1([("a", "b"), ("b", "c"), ("c", "a")]) == 1


def test_consistent_order_is_zero():       # the false positive undirected homology produced
    assert path_h1([("a", "b"), ("b", "c"), ("a", "c")]) == 0


def test_acyclic_is_zero():
    assert path_h1([("a", "b"), ("b", "c")]) == 0


def test_counts_independent_cycles():      # two disjoint directed cycles
    assert path_h1([("a", "b"), ("b", "a"), ("x", "y"), ("y", "z"), ("z", "x")]) == 2


# ── HONEST characterization: path homology is NOT cycle detection (pinned so no one repeats it) ──
def test_path_homology_fires_on_acyclic_square():
    """FALSE POSITIVE for cycles: the acyclic bipartite square has a genuine path-homology hole."""
    assert path_h1([("a", "c"), ("a", "d"), ("b", "c"), ("b", "d")]) == 1  # acyclic, yet H1=1


def test_path_homology_misses_filled_cycle():
    """FALSE NEGATIVE for cycles: a real a<->b 2-cycle is FILLED by a common successor -> H1=0."""
    assert path_h1([("a", "b"), ("b", "a"), ("a", "c"), ("b", "c")]) == 0  # cyclic, yet H1=0
