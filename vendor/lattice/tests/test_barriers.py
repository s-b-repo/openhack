from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.barriers import min_barrier_set


def _v(vid):
    return Vertex(id=vid, kind="function", name=vid, file="a.ts", start_line=1, end_line=2)


def _e(a, b):
    return Hyperedge(id=a + b, kind="references", members=[a, b], directed=True, resolved=True)


def test_min_barrier_set_finds_the_chokepoint():
    """Two attack paths from src to sink both pass through 'choke' — the minimum barrier
    set is {choke}: gate that one function and every path to the sink is covered."""
    net = Hypernetwork(language="ts", root="/x",
                       vertices=[_v(x) for x in ("src", "a", "c", "choke", "sink")],
                       hyperedges=[_e("src", "a"), _e("a", "choke"),
                                   _e("src", "c"), _e("c", "choke"),
                                   _e("choke", "sink")], surfaces=[])
    res = min_barrier_set(net, sources=["src"], sinks=["sink"])
    assert "choke" in res.barriers, res.barriers
    assert len(res.barriers) == 1, res.barriers          # one gate covers everything
