# tests/test_cache.py
import json
import builtins
import sys
import types
import pytest
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.cache import load_network


def test_load_network_from_cached_json_roundtrips(tmp_path):
    net = Hypernetwork(
        language="typescript", root="/proj",
        vertices=[Vertex(id="a", kind="function", name="a", file="f",
                         start_line=1, end_line=2, exported=True)],
        hyperedges=[Hyperedge(id="e", kind="references", members=["a", "b"],
                              resolved=True, confidence=0.5, provenance="nominal")],
        surfaces=[Surface(id="s", vertex_id="a", kind="public_api")])
    p = tmp_path / "g.json"
    p.write_text(json.dumps(net.to_dict()))

    loaded, root = load_network(p)
    assert [v.id for v in loaded.vertices] == ["a"]
    assert loaded.vertices[0].exported is True
    assert loaded.hyperedges[0].confidence == 0.5
    assert loaded.hyperedges[0].provenance == "nominal"
    assert loaded.surfaces[0].kind == "public_api"
    assert str(root) == "/proj"            # source root recovered from the cache


def test_load_network_detects_json_vs_dir(tmp_path):
    # a .json file is loaded as a cache; a directory would be ingested (not tested here)
    net = Hypernetwork(language="typescript", root=str(tmp_path),
                       vertices=[], hyperedges=[], surfaces=[])
    p = tmp_path / "cache.json"
    p.write_text(json.dumps(net.to_dict()))
    loaded, _ = load_network(p)
    assert loaded.language == "typescript"


def test_load_network_and_cli_refuse_cached_frontend_errors(tmp_path, capsys):
    from lattice.cache import GraphIngestError
    from lattice.cli import main as cli

    warning = {"kind": "partial", "severity": "warning", "file": "a.ts",
               "line": 1, "message": "warning evidence"}
    error = {"kind": "parse_error", "severity": "error", "file": "a.ts",
             "line": 2, "message": "error evidence"}
    net = Hypernetwork(language="typescript", root=str(tmp_path),
                       vertices=[], hyperedges=[], surfaces=[],
                       diagnostics=[warning, error])
    path = tmp_path / "failed.json"
    path.write_text(json.dumps(net.to_dict()))

    with pytest.raises(GraphIngestError) as exc:
        load_network(path)
    assert exc.value.report.diagnostics == [warning, error]

    for command in ("diagnose", "hunt"):
        assert cli.main([command, str(path)]) == 2
        stderr = capsys.readouterr().err
        assert "warning evidence" in stderr and "error evidence" in stderr


def test_auto_language_detection_returns_each_js_family_once(tmp_path):
    from lattice.cache import detect_languages

    (tmp_path / "one.ts").write_text("export const ts = 1\n")
    (tmp_path / "one.js").write_text("exports.js = 1\n")
    detected = detect_languages(tmp_path)
    assert detected == ["typescript", "javascript"]
    assert len(detected) == len(set(detected))


def test_auto_empty_project_is_diagnostic_and_fails_gate(tmp_path):
    from lattice.cache import (GraphIngestError, SourceIngestError, build_auto,
                               ingest_source)
    from lattice.complete.gate import check

    net, languages = build_auto(tmp_path)
    assert languages == []
    assert net.diagnostics == [{
        "kind": "no_source_files", "language": "auto", "file": "<project>",
        "line": 1, "severity": "error",
        "message": f"no supported source files were found under {tmp_path}",
    }]
    assert check(net).verdict == "fail"
    with pytest.raises(GraphIngestError, match="no supported source files"):
        load_network(tmp_path, "auto")
    with pytest.raises(SourceIngestError, match="graph-level operation"):
        ingest_source(tmp_path, "auto")


def test_build_auto_preserves_python_when_optional_cpp_binding_is_missing(
        tmp_path, monkeypatch):
    from lattice.cache import build_auto
    from lattice.complete.gate import check

    (tmp_path / "app.py").write_text("def python_api():\n    return 1\n")
    (tmp_path / "native.c").write_text("int native_api(void) { return 2; }\n")
    original_import = builtins.__import__

    def import_without_clang(name, *args, **kwargs):
        if name == "clang" or name.startswith("clang."):
            raise ModuleNotFoundError("No module named 'clang'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_clang)
    net, languages = build_auto(tmp_path)

    assert languages == ["python", "cpp"]
    assert "python_api" in {vertex.name for vertex in net.vertices}
    assert check(net).verdict == "fail"
    errors = [diagnostic for diagnostic in net.diagnostics
              if diagnostic.get("severity") == "error"]
    assert len(errors) == 1
    assert errors[0]["kind"] == "frontend_unavailable"
    assert "lattice[cpp]" in errors[0]["message"]


def test_load_network_wraps_libclang_load_failure_as_graph_error(
        tmp_path, monkeypatch):
    from lattice.cache import GraphIngestError

    (tmp_path / "native.c").write_text("int native_api(void) { return 2; }\n")

    class FakeLibclangError(Exception):
        pass

    class FailingIndex:
        @staticmethod
        def create():
            raise FakeLibclangError("could not load libclang shared library")

    fake_clang = types.ModuleType("clang")
    fake_cindex = types.ModuleType("clang.cindex")
    fake_cindex.Index = FailingIndex
    fake_cindex.LibclangError = FakeLibclangError
    fake_clang.cindex = fake_cindex
    monkeypatch.setitem(sys.modules, "clang", fake_clang)
    monkeypatch.setitem(sys.modules, "clang.cindex", fake_cindex)

    with pytest.raises(GraphIngestError) as exc:
        load_network(tmp_path, "auto")
    diagnostic = exc.value.report.diagnostics[0]
    assert diagnostic["kind"] == "frontend_unavailable"
    assert diagnostic["severity"] == "error"
    assert "could not load libclang shared library" in diagnostic["message"]
    assert "lattice[cpp]" in diagnostic["message"]
