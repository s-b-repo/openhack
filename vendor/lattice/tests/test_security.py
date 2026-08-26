# tests/test_security.py
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.security import audit


def _v(vid, name, exported=False, stub=False):
    return Vertex(id=vid, kind="function", name=name, file="f", start_line=1, end_line=2,
                  exported=exported, stub=stub)


def _e(a, b):
    return Hyperedge(id=a + b, kind="references", members=[a, b], resolved=True)


def _net(vs, es, surfaces=None):
    return Hypernetwork(language="ts", root="/x", vertices=vs, hyperedges=es,
                        surfaces=surfaces or [])


def test_audit_source_to_sink_reachability_with_path():
    net = _net([_v("api", "apiHandler", exported=True), _v("val", "validate"),
                _v("q", "rawSqlQuery")],
               [_e("api", "val"), _e("val", "q")],
               surfaces=[Surface(id="s", vertex_id="api", kind="public_api")])
    r = audit(net)
    sql = [f for f in r.findings if f.kind == "sql_injection"]
    assert sql and sql[0].source == "api" and sql[0].sink == "q"
    assert tuple(sql[0].path) == ("api", "val", "q")    # how input reaches the sink


def test_audit_honest_contract():
    net = _net([_v("api", "apiHandler", exported=True), _v("q", "rawSqlQuery")],
               [_e("api", "q")],
               surfaces=[Surface(id="s", vertex_id="api", kind="public_api")])
    r = audit(net)
    assert "call_reachability" in r.verified
    assert "data_flow" in r.not_verified and "exploitability" in r.not_verified


def test_audit_command_exec_is_critical():
    net = _net([_v("h", "handler", exported=True), _v("s", "spawnProcess")],
               [_e("h", "s")],
               surfaces=[Surface(id="s1", vertex_id="h", kind="public_api")])
    assert any(f.kind == "command_exec" and f.severity == "critical" for f in audit(net).findings)


def test_audit_sink_without_entrypoint_is_listed_not_flagged():
    net = _net([_v("q", "rawSqlQuery")], [])     # no public surface -> no source reaches it
    r = audit(net)
    assert all(f.kind != "sql_injection" for f in r.findings)
    assert "q" in r.sinks


def test_audit_stub_on_public_path():
    net = _net([_v("api", "apiHandler", exported=True), _v("todo", "processPayment", stub=True)],
               [_e("api", "todo")],
               surfaces=[Surface(id="s", vertex_id="api", kind="public_api")])
    assert any(f.kind == "incomplete_handler" for f in audit(net).findings)


def test_audit_clean():
    net = _net([_v("api", "apiHandler", exported=True), _v("h", "formatName")],
               [_e("api", "h")],
               surfaces=[Surface(id="s", vertex_id="api", kind="public_api")])
    assert audit(net).summary["verdict"] == "clean"
