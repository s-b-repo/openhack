# tests/test_security_precision.py
# Taint precision fixes: provenance-not-name, sanitizers, return-value taint.
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.security import audit


def _v(vid, name, start, end, exported=False):
    return Vertex(id=vid, kind="function", name=name, file="a.ts",
                  start_line=start, end_line=end, exported=exported)


def _net(tmp_path, vertices, edges, source, entries):
    (tmp_path / "a.ts").write_text(source)
    surfaces = [Surface(id=f"s{i}", vertex_id=e, kind="public_api") for i, e in enumerate(entries)]
    return Hypernetwork(language="ts", root=str(tmp_path), vertices=vertices,
                        hyperedges=edges, surfaces=surfaces)


def _sql(net, tmp_path):
    return [x for x in audit(net, source_root=tmp_path).findings if x.kind == "sql_injection"]


def test_literal_in_suggestively_named_var_is_not_tainted(tmp_path):
    # FIX 1: `data` is a literal — being NAMED like a source must not make it tainted.
    src = ('export function f(): void {\n'
           '  const data = "SELECT 1";\n'
           '  return db.query(data);\n'
           '}\n')
    f = _sql(_net(tmp_path, [_v("f", "f", 1, 4, exported=True)], [], src, ["f"]), tmp_path)
    assert f and f[0].taint == "reachable"


def test_sanitized_value_is_not_tainted(tmp_path):
    # FIX 2: sanitize() detoxifies — the result is clean.
    src = ("export function f(req: any): void {\n"
           "  const safe = sanitize(req.body.id);\n"
           "  return db.query(safe);\n"
           "}\n"
           "function sanitize(x: string): string { return x; }\n")
    net = _net(tmp_path, [_v("f", "f", 1, 4, exported=True), _v("san", "sanitize", 5, 5)],
               [Hyperedge(id="e", kind="references", members=["f", "san"], resolved=True)], src, ["f"])
    assert _sql(net, tmp_path)[0].taint == "reachable"


def test_sanitizer_wrapping_sink_arg_directly(tmp_path):
    src = ("export function f(req: any): void {\n"
           "  return db.query(sanitize(req.id));\n"
           "}\n"
           "function sanitize(x: string): string { return x; }\n")
    net = _net(tmp_path, [_v("f", "f", 1, 3, exported=True), _v("san", "sanitize", 4, 4)],
               [Hyperedge(id="e", kind="references", members=["f", "san"], resolved=True)], src, ["f"])
    assert _sql(net, tmp_path)[0].taint == "reachable"


def test_return_value_taint_is_propagated(tmp_path):
    # FIX 3: a function that returns tainted data makes its caller's result tainted.
    src = ("export function f(): void {\n"
           "  const d = readInput();\n"
           "  return db.query(d);\n"
           "}\n"
           "function readInput(): string {\n"
           "  return request.body.id;\n"
           "}\n")
    net = _net(tmp_path, [_v("f", "f", 1, 4, exported=True), _v("ri", "readInput", 5, 7)],
               [Hyperedge(id="e", kind="references", members=["f", "ri"], resolved=True)], src, ["f"])
    assert _sql(net, tmp_path)[0].taint == "argument_flow"


def test_direct_param_taint_still_detected(tmp_path):
    # regression: the true positive must survive the precision fixes.
    src = ("export function f(req: any): void {\n"
           "  return db.query(req.body.id);\n"
           "}\n")
    f = _sql(_net(tmp_path, [_v("f", "f", 1, 3, exported=True)], [], src, ["f"]), tmp_path)
    assert f[0].taint == "argument_flow"


# ── name-tier precision: the generic word "query" is demoted, never dropped ──
# (FIRE=lead / SILENCE≠proof: getQueryParams-style names stay reported, but as a
#  distinct low-severity category so they can't pollute high-severity rankings.)

def _name_net(vertices, edges, entries):
    surfaces = [Surface(id=f"s{i}", vertex_id=e, kind="public_api")
                for i, e in enumerate(entries)]
    return Hypernetwork(language="ts", root="/x", vertices=vertices,
                        hyperedges=edges, surfaces=surfaces)


def _nv(vid, name, exported=False):
    return Vertex(id=vid, kind="function", name=name, file="f.ts",
                  start_line=1, end_line=2, exported=exported)


def _kinds_sevs(net):
    return {(f.kind, f.severity) for f in audit(net).findings}


def test_generic_query_name_is_demoted_to_possible():
    net = _name_net([_nv("h", "handler", exported=True), _nv("q", "getQueryParams")],
                    [Hyperedge(id="e", kind="calls", members=["h", "q"], resolved=True)],
                    ["h"])
    ks = _kinds_sevs(net)
    assert ("sql_injection_possible", "low") in ks, ks
    assert not any(k == "sql_injection" for k, _ in ks), ks


def test_strong_sql_names_keep_high_severity():
    for name in ("executeQuery", "runQuery", "dbQuery", "rawSqlQuery"):
        net = _name_net([_nv("h", "handler", exported=True), _nv("q", name)],
                        [Hyperedge(id="e", kind="calls", members=["h", "q"], resolved=True)],
                        ["h"])
        assert ("sql_injection", "high") in _kinds_sevs(net), name


def test_exact_query_name_stays_high():
    # a function literally named `query` is almost always a DB wrapper — strong.
    net = _name_net([_nv("h", "handler", exported=True), _nv("q", "query")],
                    [Hyperedge(id="e", kind="calls", members=["h", "q"], resolved=True)],
                    ["h"])
    ks = _kinds_sevs(net)
    assert ("sql_injection", "high") in ks, ks
    assert not any(k == "sql_injection_possible" for k, _ in ks), ks


def test_missing_gate_on_weak_sink_is_demoted():
    # an ungated route to a name-only "query" match is low-priority review,
    # not a high-severity auth bypass.
    net = _name_net([_nv("h", "handler", exported=True), _nv("q", "getQueryParams"),
                     _nv("g", "requireAuth")],
                    [Hyperedge(id="e", kind="calls", members=["h", "q"], resolved=True)],
                    ["h"])
    ks = _kinds_sevs(net)
    assert ("missing_authentication", "low") in ks, ks
    assert ("missing_authentication", "high") not in ks, ks


def test_missing_gate_on_strong_sink_stays_high():
    net = _name_net([_nv("h", "handler", exported=True), _nv("q", "executeQuery"),
                     _nv("g", "requireAuth")],
                    [Hyperedge(id="e", kind="calls", members=["h", "q"], resolved=True)],
                    ["h"])
    assert ("missing_authentication", "high") in _kinds_sevs(net)
