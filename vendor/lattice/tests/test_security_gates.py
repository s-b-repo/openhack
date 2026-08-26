# tests/test_security_gates.py
# The access-control capability that falls out of the guarded_reachability refactor.
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.security import audit


def _v(vid, name):
    return Vertex(id=vid, kind="function", name=name, file="f", start_line=1, end_line=2)


def _e(a, b):
    return Hyperedge(id=a + b, kind="calls", members=[a, b], resolved=True)


def _net(vs, es):
    return Hypernetwork(language="ts", root="/x", vertices=vs, hyperedges=es,
                        surfaces=[Surface(id="s", vertex_id="h", kind="public_api")])


def test_missing_authorization_is_flagged():
    # the codebase HAS authorization (it's a real concept here), but THIS sink's path
    # bypasses it entirely -> inconsistent enforcement -> flagged.
    net = _net([_v("h", "handler"), _v("x", "spawnProcess"), _v("g", "authorize")],
               [_e("h", "x")])               # g exists; h->x never crosses it
    r = audit(net)
    assert any(f.kind == "missing_authorization" for f in r.findings)
    assert any(f.kind == "command_exec" for f in r.findings)   # touchpoint still found


def test_authorization_gate_on_the_path_suppresses_the_finding():
    # handler -> authorize -> spawnProcess : the only path crosses the gate -> guarded
    net = _net([_v("h", "handler"), _v("g", "authorize"), _v("x", "spawnProcess")],
               [_e("h", "g"), _e("g", "x")])
    r = audit(net)
    assert not any(f.kind == "missing_authorization" for f in r.findings)
    assert any(f.kind == "command_exec" for f in r.findings)


def test_bypassed_gate_is_still_flagged():
    # gate exists on one path but a second path bypasses it -> ungated route -> flagged
    net = _net([_v("h", "handler"), _v("g", "authorize"), _v("x", "spawnProcess")],
               [_e("h", "g"), _e("g", "x"), _e("h", "x")])
    assert any(f.kind == "missing_authorization" for f in audit(net).findings)
