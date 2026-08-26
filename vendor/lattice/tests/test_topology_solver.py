from lattice.topology import obstruction_witnesses
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork


def _v(i): return Vertex(id=i, kind="function", name=i, file="a", start_line=1, end_line=1)
def _e(a, b): return Hyperedge(id=a+b, kind="references", members=[a, b], directed=True, resolved=True)


def test_minimal_obstruction_witness_is_the_smallest_cycle():
    """An H1 obstruction witness = a minimal cycle realizing an independent loop. The
    homology framework's witness step — solver leg optimal, local leg the shortest cycle."""
    # one tight triangle a->b->c->a, plus a long detour a->d->e->f->c (same cycle space)
    net = Hypernetwork(language="x", root="/", vertices=[_v(x) for x in "abcdef"],
                       hyperedges=[_e("a","b"),_e("b","c"),_e("c","a"),
                                   _e("a","d"),_e("d","e"),_e("e","f"),_e("f","c")], surfaces=[])
    w = obstruction_witnesses(net)
    assert w, "no obstruction witness produced (homology not firing)"
    # the minimal witness is the 3-cycle a-b-c, not the long detour
    shortest = min(w, key=lambda x: len(x["cycle"]))
    assert len(shortest["cycle"]) == 3, [x["cycle"] for x in w]
    assert set(shortest["cycle"]) == {"a", "b", "c"}, shortest


def test_acyclic_graph_has_no_obstruction():
    net = Hypernetwork(language="x", root="/", vertices=[_v(x) for x in "ab"],
                       hyperedges=[_e("a","b")], surfaces=[])
    assert obstruction_witnesses(net) == []
