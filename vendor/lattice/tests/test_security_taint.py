# tests/test_security_taint.py
# Tier-2 security upgrade: external library-call sinks + intraprocedural taint.
from lattice.graph.models import Vertex, Surface, Hypernetwork
from lattice.security import audit


def _entry(vid, name, file, start, end):
    return Vertex(id=vid, kind="function", name=name, file=file,
                  start_line=start, end_line=end, exported=True)


def _net(tmp_path, vertices, source_files: dict):
    for fname, text in source_files.items():
        (tmp_path / fname).write_text(text)
    surfaces = [Surface(id=f"s{i}", vertex_id=v.id, kind="public_api")
                for i, v in enumerate(vertices)]
    return Hypernetwork(language="ts", root=str(tmp_path), vertices=vertices,
                        hyperedges=[], surfaces=surfaces)


def test_external_unwrapped_sink_is_caught(tmp_path):
    # spawn() is a library call, NOT a defined symbol — tier-1 missed it, tier-2 catches it.
    src = "export function admin(cmd: string): void {\n  return spawn(cmd);\n}\n"
    net = _net(tmp_path, [_entry("ts-sym:a.ts#admin", "admin", "a.ts", 1, 3)],
               {"a.ts": src})
    r = audit(net, source_root=tmp_path)
    cmd = [f for f in r.findings if f.kind == "command_exec"]
    assert cmd and cmd[0].severity == "critical"


def test_argument_taint_flow_is_detected(tmp_path):
    # cmd is admin's parameter and flows into spawn(...) -> tainted, not just reachable.
    src = "export function admin(cmd: string): void {\n  return spawn(cmd);\n}\n"
    net = _net(tmp_path, [_entry("ts-sym:a.ts#admin", "admin", "a.ts", 1, 3)],
               {"a.ts": src})
    f = [x for x in audit(net, source_root=tmp_path).findings if x.kind == "command_exec"][0]
    assert f.taint == "argument_flow"


def test_literal_arg_is_reachable_not_tainted(tmp_path):
    # spawn("ls") — constant arg, no input flows in -> reachable, not tainted.
    src = 'export function admin(): void {\n  return spawn("ls");\n}\n'
    net = _net(tmp_path, [_entry("ts-sym:a.ts#admin", "admin", "a.ts", 1, 3)],
               {"a.ts": src})
    f = [x for x in audit(net, source_root=tmp_path).findings if x.kind == "command_exec"][0]
    assert f.taint == "reachable"


def test_request_identifier_counts_as_taint(tmp_path):
    src = "export function h(req: any): void {\n  return db.query(req.body.id);\n}\n"
    net = _net(tmp_path, [_entry("ts-sym:a.ts#h", "h", "a.ts", 1, 3)], {"a.ts": src})
    f = [x for x in audit(net, source_root=tmp_path).findings if x.kind == "sql_injection"]
    assert f and f[0].taint == "argument_flow"


def test_local_variable_taint_propagation(tmp_path):
    # taint laundered through a local: const id = req.body.id; query(id) -> still tainted
    src = ("export function h(req: any): void {\n"
           "  const id = req.body.id;\n"
           "  return db.query(id);\n"
           "}\n")
    net = _net(tmp_path, [_entry("ts-sym:a.ts#h", "h", "a.ts", 1, 4)], {"a.ts": src})
    f = [x for x in audit(net, source_root=tmp_path).findings if x.kind == "sql_injection"][0]
    assert f.taint == "argument_flow"


def test_taint_contract_is_honest(tmp_path):
    src = "export function admin(cmd: string): void {\n  return spawn(cmd);\n}\n"
    net = _net(tmp_path, [_entry("ts-sym:a.ts#admin", "admin", "a.ts", 1, 3)],
               {"a.ts": src})
    r = audit(net, source_root=tmp_path)
    assert "interprocedural_taint" in r.verified
    assert "exploitability" in r.not_verified              # reachability+taint != proven exploit


def test_audit_without_source_still_works(tmp_path):
    # backward compat: pure-graph audit (no source_root) unchanged
    from lattice.graph.models import Hyperedge
    net = Hypernetwork(language="ts", root="/x",
                       vertices=[Vertex(id="api", kind="function", name="apiHandler",
                                        file="f", start_line=1, end_line=2, exported=True),
                                 Vertex(id="q", kind="function", name="rawSqlQuery",
                                        file="f", start_line=3, end_line=4)],
                       hyperedges=[Hyperedge(id="e", kind="references", members=["api", "q"],
                                             resolved=True)],
                       surfaces=[Surface(id="s", vertex_id="api", kind="public_api")])
    r = audit(net)
    assert any(f.kind == "sql_injection" for f in r.findings)
