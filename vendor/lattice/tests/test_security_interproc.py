# tests/test_security_interproc.py
# Tier-2 final: interprocedural taint — propagate tainted args across call edges.
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.security import audit


def _v(vid, name, start, end, exported=False):
    return Vertex(id=vid, kind="function", name=name, file="a.ts",
                  start_line=start, end_line=end, exported=exported)


def _net(tmp_path, vertices, edges, source, entry_ids):
    (tmp_path / "a.ts").write_text(source)
    surfaces = [Surface(id=f"s{i}", vertex_id=e, kind="public_api")
                for i, e in enumerate(entry_ids)]
    return Hypernetwork(language="ts", root=str(tmp_path), vertices=vertices,
                        hyperedges=edges, surfaces=surfaces)


_CALL = [Hyperedge(id="e", kind="references", members=["h", "helper"], resolved=True)]


def test_taint_crosses_call_edge(tmp_path):
    # h(req) -> helper(req.body.id) -> db.query(x):  req flows through helper's param x
    src = ("export function h(req: any): void {\n"
           "  return helper(req.body.id);\n"
           "}\n"
           "function helper(x: string): void {\n"
           "  return db.query(x);\n"
           "}\n")
    net = _net(tmp_path, [_v("h", "h", 1, 3, exported=True), _v("helper", "helper", 4, 6)],
               _CALL, src, ["h"])
    f = [x for x in audit(net, source_root=tmp_path).findings if x.kind == "sql_injection"]
    assert f and f[0].taint == "argument_flow"


def test_constant_across_call_edge_is_not_tainted(tmp_path):
    # h() -> helper("constant") -> db.query(x):  only a literal crosses -> x not tainted
    src = ('export function h(): void {\n'
           '  return helper("constant");\n'
           '}\n'
           'function helper(x: string): void {\n'
           '  return db.query(x);\n'
           '}\n')
    net = _net(tmp_path, [_v("h", "h", 1, 3, exported=True), _v("helper", "helper", 4, 6)],
               _CALL, src, ["h"])
    f = [x for x in audit(net, source_root=tmp_path).findings if x.kind == "sql_injection"]
    assert f and f[0].taint == "reachable"


def test_interprocedural_contract(tmp_path):
    src = ("export function h(req: any): void {\n"
           "  return helper(req.id);\n"
           "}\n"
           "function helper(x: string): void {\n"
           "  return db.query(x);\n"
           "}\n")
    net = _net(tmp_path, [_v("h", "h", 1, 3, exported=True), _v("helper", "helper", 4, 6)],
               _CALL, src, ["h"])
    r = audit(net, source_root=tmp_path)
    assert "interprocedural_taint" in r.verified
    assert "exploitability" in r.not_verified
