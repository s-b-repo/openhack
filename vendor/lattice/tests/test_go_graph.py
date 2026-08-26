# Unit tests for the Go graph frontend (go_graph.py + tools/goast -mode graph).
# The go_deep fixture plants: exported Serve -> process -> notDone (panic stub),
# unused dead function, main.go importing example.com/deep/api, package main entry.
from __future__ import annotations
import json
import pathlib
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain missing")

REPO = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "go_deep"


def _ingest():
    from lattice.ingest.go_graph import go_ingest
    return go_ingest(FIXTURE)


def _sym(raw, name):
    matches = [s for s in raw.symbols if s.name == name]
    assert matches, f"symbol {name} not found in {[s.name for s in raw.symbols]}"
    return matches[0]


def test_language_and_files():
    raw = _ingest()
    assert raw.language == "go"
    assert "main.go" in raw.files and "api/api.go" in raw.files


def test_exported_follows_capitalization():
    raw = _ingest()
    assert _sym(raw, "Serve").exported is True
    assert _sym(raw, "process").exported is False


def test_stub_detected_from_panic_literal():
    raw = _ingest()
    assert _sym(raw, "notDone").is_stub is True
    assert _sym(raw, "process").is_stub is False


def test_entrypoint_is_package_main_with_func_main():
    raw = _ingest()
    assert "main.go" in raw.entry_files
    assert "api/api.go" not in raw.entry_files


def test_import_resolves_through_gomod_module_path():
    raw = _ingest()
    imports = [r for r in raw.references if r.kind == "imports"]
    assert any(r.from_file == "main.go" and r.to_file == "api/api.go" and r.resolved
               for r in imports), f"imports: {[(r.from_file, r.to_file) for r in imports]}"


def test_calls_resolve_by_name_with_name_field():
    raw = _ingest()
    calls = [r for r in raw.references if r.kind == "references"]
    process_line = _sym(raw, "process").start_line
    assert any(r.from_file == "api/api.go" and r.to_file == "api/api.go"
               and r.to_line == process_line and r.name == "process" and r.resolved
               for r in calls), f"calls: {[(r.from_file, r.name, r.to_line) for r in calls]}"


def test_structs_interfaces_methods_and_embedding(tmp_path):
    from lattice.ingest.go_graph import go_ingest
    (tmp_path / "go.mod").write_text("module example.com/shapes\n\ngo 1.22\n")
    (tmp_path / "shapes.go").write_text(
        "package shapes\n\n"
        "type Base struct{}\n\n"
        "type Shape interface {\n\tArea() float64\n}\n\n"
        "type Circle struct {\n\tBase\n\tr float64\n}\n\n"
        "func (c *Circle) Area() float64 {\n\treturn c.r\n}\n\n"
        "func (c *Circle) empty() {}\n")
    raw = go_ingest(tmp_path)
    by = {s.name: s for s in raw.symbols}
    assert by["Circle"].kind == "class"
    assert by["Shape"].kind == "interface"
    assert by["Circle"].extends == ["Base"]
    assert by["Area"].kind == "method" and by["Area"].container == "Circle"
    assert by["Area"].exported is True
    assert by["empty"].is_stub is True


def test_builder_prefixes_go_vertices():
    from lattice.graph.builder import build
    net = build(_ingest())
    sym_ids = [v.id for v in net.vertices if ":" in v.id and v.kind != "module"]
    assert sym_ids and all(i.startswith("go-") for i in sym_ids), sym_ids[:5]


def test_cache_routes_go():
    from lattice.cache import ingest_source, normalize_language
    assert normalize_language("go") == "go"
    raw = ingest_source(FIXTURE, "go")
    assert raw.language == "go" and raw.symbols


def test_taint_bridge_output_shape_unchanged(tmp_path):
    """The graph mode must be additive: the default bridge invocation keeps the
    per-function taint JSON shape that go_taint.py depends on."""
    from lattice.ingest.go_graph import ensure_bridge
    bridge = ensure_bridge()
    src = tmp_path / "t.go"
    src.write_text('package t\n\nfunc f(a string) {\n\tg(a)\n}\n')
    out = subprocess.run([str(bridge), str(src)], capture_output=True, text=True, check=True)
    funcs = json.loads(out.stdout)
    assert isinstance(funcs, list) and funcs[0]["name"] == "f"
    assert set(funcs[0].keys()) >= {"name", "params", "calls", "assigns", "returns"}
