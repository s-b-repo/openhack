from lattice.topology import minimal_fix, obstruction_witnesses
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork


def _v(i): return Vertex(id=i, kind="function", name=i, file="a", start_line=1, end_line=1)
def _e(a, b): return Hyperedge(id=a+b, kind="references", members=[a, b], directed=True, resolved=True)


def test_minimal_fix_breaks_every_obstruction_with_fewest_cuts():
    """The math->solver pipeline: homology finds the obstruction cycles, the solver
    (min-feedback-arc-set QUBO, local greedy fallback) returns the FEWEST edges to cut
    so that every cycle is broken. Two cycles share edge a->b, so one cut suffices."""
    net = Hypernetwork(language="x", root="/", vertices=[_v(x) for x in "abcd"],
                       hyperedges=[_e("a","b"),_e("b","c"),_e("c","a"),   # a->b->c->a
                                   _e("b","d"),_e("d","a")],              # a->b->d->a (shares a->b)
                       surfaces=[])
    assert obstruction_witnesses(net), "precondition: graph must carry obstructions"
    fix = minimal_fix(net)
    assert fix["cut"], "no fix produced"
    assert fix["obstructions_after"] == 0, fix          # every cycle broken
    assert len(fix["cut"]) == 1, fix                    # the shared edge alone suffices
    assert fix["provenance"] in ("local", "solver:deadbolt")


def test_minimal_fix_does_not_overcut_disjoint_and_shared_cycles():
    """Three cycles: a-b-c-a and a-b-d-a share edge a->b; c-e-f-c is disjoint. The minimal
    fix is 2 cuts (a->b kills the first two, one edge of c-e-f kills the third), NOT one cut
    per cycle and NOT collateral edges that sit on no remaining cycle."""
    net = Hypernetwork(language="x", root="/", vertices=[_v(x) for x in "abcdef"],
                       hyperedges=[_e("a","b"),_e("b","c"),_e("c","a"),
                                   _e("b","d"),_e("d","a"),
                                   _e("c","e"),_e("e","f"),_e("f","c")], surfaces=[])
    fix = minimal_fix(net)
    assert fix["obstructions_after"] == 0, fix
    assert len(fix["cut"]) == 2, fix                 # not 3 (per-cycle), not 6 (blind greedy)
    assert ["a", "b"] in fix["cut"], fix             # the shared edge must be chosen


def test_acyclic_graph_needs_no_fix():
    net = Hypernetwork(language="x", root="/", vertices=[_v(x) for x in "ab"],
                       hyperedges=[_e("a","b")], surfaces=[])
    fix = minimal_fix(net)
    assert fix["cut"] == []
    assert fix["obstructions_after"] == 0
