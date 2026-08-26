# tests/test_optimize.py
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.optimize import optimize
from lattice.compute import _has_cycle


def _v(vid):
    return Vertex(id=vid, kind="function", name=vid, file="f", start_line=1, end_line=2)


def _e(a, b):
    return Hyperedge(id=a + b, kind="calls", members=[a, b], resolved=True)


def _net(vs, es):
    return Hypernetwork(language="ts", root="/x",
                        vertices=[_v(v) for v in vs], hyperedges=es)


def test_break_cycle_suggestion_actually_breaks_the_cycle():
    net = _net(["a", "b", "c"], [_e("a", "b"), _e("b", "c"), _e("c", "a")])
    opt = optimize(net)
    cuts = {tuple(o.targets) for o in opt if o.kind == "break_cycle"}
    assert cuts                                   # at least one edge to cut
    remaining = [e for e in [("a", "b"), ("b", "c"), ("c", "a")] if e not in cuts]
    assert not _has_cycle({"a", "b", "c"}, remaining)   # cutting them makes it acyclic


def test_acyclic_graph_has_no_break_cycle():
    net = _net(["a", "b", "c"], [_e("a", "b"), _e("b", "c")])
    assert not any(o.kind == "break_cycle" for o in optimize(net))


def test_reduce_coupling_flags_hotspot():
    net = _net(["x", "y", "hub", "p", "q"],
               [_e("x", "hub"), _e("y", "hub"), _e("hub", "p"), _e("hub", "q")])
    opt = optimize(net, hotspot_threshold=3)       # hub degree = 4
    hubs = [o for o in opt if o.kind == "reduce_coupling" and o.targets == ["hub"]]
    assert hubs


def test_optimize_records_provenance():
    net = _net(["a", "b", "c"], [_e("a", "b"), _e("b", "c"), _e("c", "a")])
    bc = [o for o in optimize(net) if o.kind == "break_cycle"][0]
    assert bc.provenance in ("local", "solver:deadbolt")
