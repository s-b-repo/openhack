# tests/test_sidecar.py
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.sidecar import digest, changes, render


def _v(vid, name, kind="function", exported=False, stub=False, file="a.ts"):
    return Vertex(id=vid, kind=kind, name=name, file=file, start_line=1, end_line=2,
                  exported=exported, stub=stub)


def _net(vs, es=None, surf=None):
    return Hypernetwork(language="ts", root="/x", vertices=vs, hyperedges=es or [],
                        surfaces=surf or [])


def test_digest_reflects_current_structure():
    net = _net([_v("api", "handler", exported=True),
                _v("dead", "unused"),
                _v("todo", "notDone", stub=True)],
               [_e := Hyperedge(id="e", kind="references", members=["api", "todo"], resolved=True)],
               surf=[Surface(id="s", vertex_id="api", kind="public_api")])
    dg = digest(net)
    assert dg["vertices"] == 3
    assert dg["public_api"] == 1
    assert dg["health"]["stubs"] >= 1
    assert "coverage" in dg


def test_digest_health_is_complete_gate_and_preserves_all_diagnostics():
    warning = {"kind": "partial", "severity": "warning", "file": "a.ts",
               "line": 1, "message": "warning evidence"}
    error = {"kind": "parse_error", "severity": "error", "file": "a.ts",
             "line": 2, "message": "fatal evidence"}
    net = _net([_v("api", "handler", exported=True)])
    net.diagnostics = [warning, error]

    dg = digest(net)
    assert dg["health"]["verdict"] == "fail"
    assert "ingest_diagnostics" in dg["health"]["failing_checks"]
    assert dg["health"]["diagnostics"] == [warning, error]
    assert "structural_verdict" in dg["health"]
    markdown = render(dg, None)
    assert "warning evidence" in markdown and "fatal evidence" in markdown


def test_changes_reports_the_delta():
    prev = _net([_v("a", "a")])
    cur = _net([_v("a", "a"), _v("b", "b")],
               [Hyperedge(id="e", kind="references", members=["b", "missing"], resolved=False)])
    ch = changes(prev, cur)
    assert ch["added_vertices"] >= 1
    assert ch["verdict"] in ("clean", "regressed")


def test_render_produces_markdown_with_both_endpoints():
    net = _net([_v("api", "handler", exported=True)],
               surf=[Surface(id="s", vertex_id="api", kind="public_api")])
    md = render(digest(net), None)
    assert "# Footings Sidecar" in md or "Sidecar" in md
    assert "coverage" in md.lower()


def test_update_is_noop_when_nothing_changed(tmp_path):
    import json
    from lattice import sidecar as sc
    from lattice.changeset import file_manifest
    src = tmp_path / "proj"
    src.mkdir()
    (src / "a.ts").write_text("export const x = 1;\n")
    out = tmp_path / ".footings"
    out.mkdir()
    (out / "manifest.json").write_text(json.dumps(file_manifest(src)))   # matches current
    cached = Hypernetwork(language="typescript", root=str(src),
                          vertices=[], hyperedges=[], surfaces=[])
    (out / "graph.json").write_text(json.dumps(cached.to_dict()))
    (out / "state.json").write_text(json.dumps({"language": "typescript"}))
    r = sc.update(src, out)
    assert r["updated"] is False and r["mode"] == "noop"
    assert r["digest"]["health"]["verdict"] == "pass"


def test_unchanged_failed_sidecar_retries_and_recovers(tmp_path, monkeypatch):
    from lattice import cache
    from lattice import sidecar as sc
    from lattice.ingest.types import RawIngest, RawSymbol

    src = tmp_path / "proj"
    src.mkdir()
    (src / "main.go").write_text("package main\nfunc main() {}\n")
    calls = []

    def fail_then_restore(root, language):
        calls.append(language)
        if len(calls) == 1:
            return RawIngest(
                language=language, root=str(root), files=["main.go"],
                diagnostics=[{
                    "kind": "frontend_unavailable", "severity": "error",
                    "language": language, "file": "main.go", "line": 1,
                    "message": "temporary frontend outage",
                }],
            )
        return RawIngest(
            language=language, root=str(root), files=["main.go"],
            symbols=[RawSymbol("main", "function", "main.go", 2, 2,
                               exported=True)],
        )

    monkeypatch.setattr(cache, "ingest_source", fail_then_restore)
    out = tmp_path / "sidecar"
    failed = sc.update(src, out, language="go", force=True)
    recovered = sc.update(src, out, language="go")
    stable = sc.update(src, out, language="go")

    assert failed["digest"]["health"]["verdict"] == "fail"
    assert recovered["updated"] is True and recovered["mode"] == "full"
    assert recovered["digest"]["health"]["verdict"] == "pass"
    assert stable["updated"] is False and stable["mode"] == "noop"
    assert calls == ["go", "go"]


def test_watch_exit_status_recovers_after_transient_failed_graph(
        tmp_path, monkeypatch, capsys):
    from lattice import sidecar as sc
    from lattice.cli import main as cli

    def result(verdict):
        return {
            "updated": True, "mode": "full", "changes": None,
            "changed_files": [],
            "digest": {
                "health": {"verdict": verdict},
                "coverage": {"ratio": 1.0}, "bugs": {"total": 0},
            },
        }

    responses = iter([result("fail"), result("pass")])
    monkeypatch.setattr(sc, "update", lambda *args, **kwargs: next(responses))

    rc = cli.main([
        "watch", str(tmp_path), "--lang", "go",
        "--interval", "0", "--iterations", "2",
    ])
    assert rc == 0
    output = capsys.readouterr().out
    assert "verdict=fail" in output and "verdict=pass" in output


def test_sidecar_cli_exits_nonzero_when_complete_gate_fails(tmp_path, monkeypatch, capsys):
    from lattice import sidecar as sc
    from lattice.cli import main as cli

    failed = {
        "updated": False, "mode": "noop", "changes": None, "changed_files": [],
        "digest": {"health": {"verdict": "fail"}},
    }
    monkeypatch.setattr(sc, "update", lambda *args, **kwargs: failed)
    assert cli.main(["sidecar", str(tmp_path), "--lang", "ts"]) == 1
    assert "verdict=fail" in capsys.readouterr().out


def test_update_native_language_uses_central_dispatcher(tmp_path, monkeypatch):
    from lattice import cache
    from lattice import sidecar as sc
    from lattice.ingest.types import RawIngest, RawSymbol

    src = tmp_path / "proj"
    src.mkdir()
    (src / "main.go").write_text("package main\nfunc main() {}\n")
    calls = []

    def fake_dispatch(root, language):
        calls.append(language)
        return RawIngest(
            language=language, root=str(root), files=["main.go"],
            symbols=[RawSymbol("main", "function", "main.go", 2, 2, exported=True)],
        )

    monkeypatch.setattr(cache, "ingest_source", fake_dispatch)
    result = sc.update(src, tmp_path / "sidecar", language="go", force=True)
    assert result["mode"] == "full"
    assert calls == ["go"]


def test_package_entrypoint_change_forces_full_sidecar_ingest(tmp_path, monkeypatch):
    import json
    from lattice import cache, incremental
    from lattice import sidecar as sc
    from lattice.graph.models import Hypernetwork
    from lattice.ingest.types import RawIngest

    src = tmp_path / "proj"
    (src / "src").mkdir(parents=True)
    (src / "src" / "a.ts").write_text("export const a = 1\n")
    (src / "src" / "b.ts").write_text("export const b = 1\n")
    package = src / "package.json"
    package.write_text(json.dumps({"main": "dist/a.js"}))

    calls = []

    def fake_dispatch(root, language):
        calls.append(language)
        main = json.loads((root / "package.json").read_text())["main"]
        entry = "src/a.ts" if main.endswith("a.js") else "src/b.ts"
        return RawIngest(language=language, root=str(root),
                         files=["src/a.ts", "src/b.ts"], entry_files={entry})

    monkeypatch.setattr(cache, "ingest_source", fake_dispatch)
    monkeypatch.setattr(
        incremental, "incremental_ingest",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("metadata used incremental ingest")),
    )
    out = tmp_path / "sidecar"
    sc.update(src, out, language="typescript", force=True)
    package.write_text(json.dumps({"main": "dist/b.js"}))
    result = sc.update(src, out, language="typescript")

    assert result["mode"] == "full" and calls == ["typescript", "typescript"]
    net = Hypernetwork.from_dict(json.loads((out / "graph.json").read_text()))
    entry_ids = {s.vertex_id for s in net.surfaces if s.kind == "entrypoint"}
    assert any(v.file == "src/b.ts" and v.id in entry_ids for v in net.vertices)


def test_sidecar_language_is_part_of_noop_cache_key(tmp_path, monkeypatch):
    import json
    from lattice import cache
    from lattice import sidecar as sc
    from lattice.ingest.types import RawIngest, RawSymbol

    src = tmp_path / "proj"
    src.mkdir()
    (src / "run.sh").write_text("echo shell\n")
    (src / "query.sql").write_text("select 1;\n")
    calls = []

    def fake_dispatch(root, language):
        calls.append(language)
        filename = "run.sh" if language == "shell" else "query.sql"
        return RawIngest(
            language=language, root=str(root), files=[filename],
            symbols=[RawSymbol(language, "function", filename, 1, 1, exported=True)],
        )

    monkeypatch.setattr(cache, "ingest_source", fake_dispatch)
    out = tmp_path / "sidecar"
    sc.update(src, out, language="shell", force=True)
    result = sc.update(src, out, language="sql")

    assert result["updated"] is True and result["mode"] == "full"
    assert calls == ["shell", "sql"]
    graph = Hypernetwork.from_dict(json.loads((out / "graph.json").read_text()))
    assert graph.language == "sql"
    assert json.loads((out / "state.json").read_text()) == {"language": "sql"}


def test_sidecar_auto_builds_mixed_graph_at_graph_level(tmp_path):
    import json
    from lattice import sidecar as sc

    (tmp_path / "run.sh").write_text("#!/bin/sh\nlaunch() { echo ready; }\n")
    (tmp_path / "schema.sql").write_text("CREATE TABLE users (id integer);\n")
    out = tmp_path / "sidecar"
    result = sc.update(tmp_path, out, language="auto", force=True)

    graph = Hypernetwork.from_dict(json.loads((out / "graph.json").read_text()))
    assert result["mode"] == "full" and graph.language == "mixed"
    assert {"launch", "users"} <= {vertex.name for vertex in graph.vertices}
    assert json.loads((out / "state.json").read_text()) == {"language": "auto"}


def test_sidecar_detects_sql_changes_inside_vendor_directory(tmp_path):
    import json
    from lattice import sidecar as sc

    src = tmp_path / "project"
    vendor = src / "vendor"
    vendor.mkdir(parents=True)
    schema = vendor / "schema.sql"
    schema.write_text("CREATE TABLE old_name (id INT);\n")
    out = tmp_path / "sidecar"

    first = sc.update(src, out, language="sql", force=True)
    schema.write_text("CREATE TABLE new_name (id INT);\n")
    second = sc.update(src, out, language="sql")
    graph = Hypernetwork.from_dict(json.loads((out / "graph.json").read_text()))

    assert first["updated"] is True
    assert second["updated"] is True and second["mode"] == "full"
    assert "vendor/schema.sql" in second["changed_files"]
    names = {vertex.name for vertex in graph.vertices}
    assert "new_name" in names and "old_name" not in names
