# Bare C files must reach the graph through the libclang cpp frontend.
# Before this, *.c was absent from the glob set: only headers were ingested,
# so a pure-C program had no function bodies, no call edges, and no depth.
from __future__ import annotations
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "c_deep"


def _clang_available() -> bool:
    try:
        from clang import cindex
        cindex.Index.create()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _clang_available(), reason="libclang unavailable")


def test_dot_c_files_are_ingested():
    from lattice.ingest.cpp import cpp_ingest
    raw = cpp_ingest(FIXTURE)
    names = {s.name for s in raw.symbols}
    assert {"serve", "process", "main"} <= names, f"missing: {names}"
    assert "api.c" in raw.files and "main.c" in raw.files
    assert raw.entry_files == {"main.c"}
    assert not next(s for s in raw.symbols if s.name == "process").exported


def test_c_main_entry_surface_reaches_main_and_file_local_helper():
    from lattice.graph.builder import build
    from lattice.graph.query import GraphView
    from lattice.ingest.cpp import cpp_ingest

    net = build(cpp_ingest(FIXTURE, "c"))
    entry = next(s.vertex_id for s in net.surfaces if s.kind == "entrypoint")
    main = next(v.id for v in net.vertices if v.name == "main")
    process = next(v.id for v in net.vertices if v.name == "process")
    reached = GraphView(net).reachable_from(entry)

    assert main in reached
    assert process in reached


def test_c_call_edges_recovered():
    from lattice.ingest.cpp import cpp_ingest
    raw = cpp_ingest(FIXTURE)
    process = next(s for s in raw.symbols if s.name == "process")
    calls = [r for r in raw.references if r.kind == "references"]
    assert any(r.from_file == "api.c" and r.to_file == process.file
               and r.to_line == process.start_line for r in calls), (
        f"calls: {[(r.from_file, r.to_file, r.to_line) for r in calls]}, "
        f"process at {process.file}:{process.start_line}")


def test_detect_languages_sees_bare_c():
    from lattice.cache import detect_languages
    assert "cpp" in detect_languages(FIXTURE)


def test_standard_c_restrict_parameters_are_parsed_as_c(tmp_path):
    from lattice.ingest.cpp import _clang_args, cpp_ingest

    source = tmp_path / "copy.c"
    source.write_text(
        "void copy_values(int n, int *restrict dst, const int *restrict src) {\n"
        "  for (int i = 0; i < n; ++i) dst[i] = src[i];\n"
        "}\n"
    )
    assert _clang_args(source)[:3] == ["-x", "c", "-std=c11"]
    raw = cpp_ingest(tmp_path)
    fn = next(s for s in raw.symbols if s.name == "copy_values")
    assert fn.params == ["n", "dst", "src"]


def test_c_alias_dispatches_standalone_headers_through_c_grammar(tmp_path):
    from lattice.cache import ingest_source, normalize_language

    (tmp_path / "api.h").write_text(
        "void consume(int n, const int *restrict values);\n")
    assert normalize_language("c") == "c"
    raw = ingest_source(tmp_path, "c")
    fn = next(s for s in raw.symbols if s.name == "consume")
    assert raw.language == "c"
    assert fn.params == ["n", "values"]


def test_malformed_c_is_retained_and_fails_the_completeness_gate(tmp_path):
    from lattice.cache import ingest_source
    from lattice.complete.gate import check
    from lattice.graph.builder import build

    (tmp_path / "broken.c").write_text("int broken( { return 1; }\n")
    raw = ingest_source(tmp_path, "c")
    assert "broken.c" in raw.files
    assert any(d.get("severity") == "error" and d.get("file") == "broken.c"
               for d in raw.diagnostics), raw.diagnostics
    report = check(build(raw))
    assert report.verdict == "fail"
    assert "ingest_diagnostics" in report.failing_checks


def test_duplicate_static_c_functions_resolve_calls_by_clang_identity(tmp_path):
    from lattice.cache import ingest_source

    (tmp_path / "a.c").write_text(
        "static int Run(void) { return 1; }\n"
        "int CallA(void) { return Run(); }\n")
    (tmp_path / "b.c").write_text(
        "static int Run(void) { return 2; }\n"
        "int CallB(void) { return Run(); }\n")
    raw = ingest_source(tmp_path, "c")
    run_b = next(s for s in raw.symbols if s.file == "b.c" and s.name == "Run")
    call_b = next(s for s in raw.symbols if s.file == "b.c" and s.name == "CallB")
    refs = [r for r in raw.references
            if r.from_file == "b.c" and r.from_line == call_b.start_line and r.name == "Run"]
    assert any(r.resolved and r.to_file == "b.c" and r.to_line == run_b.start_line
               for r in refs), refs
    assert not any(r.resolved and r.to_file == "a.c" for r in refs), refs


def test_c_include_edges_distinguish_local_missing_and_system_headers(tmp_path):
    from lattice.cache import ingest_source
    from lattice.complete.gate import check
    from lattice.graph.builder import build

    (tmp_path / "api.h").write_text("int api_value(void);\n")
    (tmp_path / "main.c").write_text(
        '#include "api.h"\n'
        '#include "missing.h"\n'
        '#include <stdio.h>\n'
        "int main(void) { return api_value(); }\n")
    raw = ingest_source(tmp_path, "c")
    imports = [r for r in raw.references if r.kind == "imports" and r.from_file == "main.c"]
    assert any(r.name == "api.h" and r.to_file == "api.h" and r.resolved for r in imports)
    assert any(r.name == "missing.h" and r.to_file == "missing.h" and not r.resolved
               for r in imports)
    assert any(r.name == "stdio.h" and r.to_file is None and not r.resolved for r in imports)
    report = check(build(raw))
    assert report.verdict == "fail"
    assert any("missing.h" in item for item in report.unresolved_imports)


def test_cli_c_alias_preserves_c_frontend_and_header_grammar(tmp_path):
    import json
    from lattice.cli.main import main

    (tmp_path / "api.h").write_text(
        "void consume(int n, const int *restrict values);\n")
    graph_path = tmp_path / "c-graph.json"
    assert main(["ingest", str(tmp_path), "--lang", "c", "--out", str(graph_path)]) == 0
    graph = json.loads(graph_path.read_text())
    assert graph["language"] == "c"
    consume = next(v for v in graph["vertices"] if v["name"] == "consume")
    assert consume["params"] == ["n", "values"]


def test_direct_c_file_ingest_follows_local_include_closure(tmp_path):
    from lattice.cache import detect_languages, ingest_source

    (tmp_path / "api.h").write_text(
        "static inline int api_value(void) { return 7; }\n")
    source = tmp_path / "main.c"
    source.write_text('#include "api.h"\nint main(void) { return api_value(); }\n')
    assert detect_languages(source) == ["cpp"]
    raw = ingest_source(source, "c")
    assert raw.root == str(tmp_path)
    assert {"main.c", "api.h"} <= set(raw.files)
    assert {"main", "api_value"} <= {s.name for s in raw.symbols}


def test_explicit_c_empty_or_unsupported_source_fails_closed(tmp_path, capsys):
    from lattice.cache import GraphIngestError, ingest_source, load_network
    from lattice.cli import main as cli

    raw = ingest_source(tmp_path, "c")
    assert raw.diagnostics[0]["kind"] == "no_source_files"
    with pytest.raises(GraphIngestError, match=r"no C/C\+\+ source files"):
        load_network(tmp_path, "c")

    unsupported = tmp_path / "notes.txt"
    unsupported.write_text("int this_is_not_selected_source(void);\n")
    raw = ingest_source(unsupported, "cpp")
    assert raw.files == [] and raw.diagnostics[0]["file"] == "notes.txt"
    with pytest.raises(GraphIngestError, match=r"unsupported C/C\+\+ source suffix"):
        load_network(unsupported, "cpp")
    assert cli.main(["hunt", str(unsupported), "--lang", "cpp"]) == 2
    assert "unsupported C/C++ source suffix" in capsys.readouterr().err


def test_cpp_namespace_and_class_identity_selects_exact_duplicate_method(tmp_path):
    from lattice.cache import ingest_source
    from lattice.graph.builder import build

    source = tmp_path / "main.cpp"
    source.write_text(
        "namespace a { struct X { static int Run() { return 1; } }; }\n"
        "namespace b { struct X { static int Run() { return 2; } }; }\n"
        "int selected() { return b::X::Run(); }\n"
    )
    raw = ingest_source(tmp_path, "cpp")
    runs = [s for s in raw.symbols if s.name == "Run"]
    assert {s.container for s in runs} == {"a::X", "b::X"}
    selected = next(s for s in raw.symbols if s.name == "selected")
    b_run = next(s for s in runs if s.container == "b::X")
    calls = [r for r in raw.references
             if r.name == "Run" and r.from_line == selected.start_line]
    assert any(r.resolved and r.to_line == b_run.start_line for r in calls), calls
    assert len([v for v in build(raw).vertices if v.name == "Run"]) == 2
