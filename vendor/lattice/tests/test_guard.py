# tests/test_guard.py
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.graph.query import GraphView
from lattice.guard import guarded_reachability


def _v(vid):
    return Vertex(id=vid, kind="function", name=vid, file="f", start_line=1, end_line=2)


def _e(a, b):
    return Hyperedge(id=a + b, kind="calls", members=[a, b], resolved=True)


def _net(vs, es):
    return Hypernetwork(language="ts", root="/x", vertices=[_v(v) for v in vs], hyperedges=es)


# --- the avoid primitive on the lens ---

def test_reachable_from_avoiding_a_node():
    g = GraphView(_net(["entry", "gate", "sink"], [_e("entry", "gate"), _e("gate", "sink")]))
    assert "sink" in g.reachable_from("entry")
    assert "sink" not in g.reachable_from("entry", avoid={"gate"})   # removing gate disconnects


# --- touchpoints (sink reachable from source) ---

def test_touchpoint_finding():
    fs = guarded_reachability(_net(["entry", "sink"], [_e("entry", "sink")]),
                              sources={"entry"},
                              sinks={"command_exec": ({"sink"}, "critical")}, gates={})
    f = [x for x in fs if x.kind == "command_exec"]
    assert f and f[0].source == "entry" and f[0].sink == "sink"
    assert f[0].path == ["entry", "sink"]


# --- gates: present (all paths cross it) vs bypassed (an ungated path exists) ---

def test_gate_present_yields_no_missing_finding():
    # entry -> gate -> sink ; the only path crosses the gate -> guarded
    net = _net(["entry", "gate", "sink"], [_e("entry", "gate"), _e("gate", "sink")])
    fs = guarded_reachability(net, sources={"entry"},
                              sinks={"command_exec": ({"sink"}, "critical")},
                              gates={"authorization": {"gate"}})
    assert not any(x.kind == "missing_authorization" for x in fs)


def test_gate_bypassed_yields_missing_finding():
    # entry -> gate -> sink  AND  entry -> sink (bypass) -> an ungated path exists
    net = _net(["entry", "gate", "sink"],
               [_e("entry", "gate"), _e("gate", "sink"), _e("entry", "sink")])
    fs = guarded_reachability(net, sources={"entry"},
                              sinks={"command_exec": ({"sink"}, "critical")},
                              gates={"authorization": {"gate"}})
    miss = [x for x in fs if x.kind == "missing_authorization"]
    assert miss and miss[0].sink == "sink" and miss[0].gate == "authorization"


def test_no_source_no_findings():
    net = _net(["a", "sink"], [_e("a", "sink")])
    assert guarded_reachability(net, sources=set(),
                                sinks={"command_exec": ({"sink"}, "critical")}, gates={}) == []
