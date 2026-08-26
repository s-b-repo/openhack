"""Adversarial contracts for native graph frontends.

These cases intentionally exercise the shapes that a happy-path fixture misses:
parser failure, duplicate identifiers, unresolved dependencies, and nested module
paths.  A graph may be partial, but it must never turn those unknowns into a clean
or confidence-1 claim about the wrong target.
"""
from __future__ import annotations

import importlib
import pathlib
import shutil
import subprocess

import pytest

from lattice.complete.gate import check
from lattice.graph.builder import build
from lattice.graph.merge import merge
from lattice.graph.models import Hypernetwork
from lattice.ingest.types import RawIngest


def test_diagnostics_survive_build_json_and_merge_and_fail_gate():
    from lattice.cache import _merge as merge_auto_graphs

    diagnostic = {
        "kind": "parse_error", "severity": "error", "language": "go",
        "file": "broken.go", "message": "expected declaration",
    }
    first = build(RawIngest(language="go", root="/x", diagnostics=[diagnostic],
                            files=["broken.go"]))
    restored = Hypernetwork.from_dict(first.to_dict())
    combined = merge([restored, Hypernetwork(language="rust", root="/x")])
    auto_combined = merge_auto_graphs([
        restored, Hypernetwork(language="rust", root="/x"),
    ])

    assert combined.diagnostics == [diagnostic]
    assert auto_combined.diagnostics == [diagnostic]
    report = check(combined)
    assert report.verdict == "fail"
    assert report.diagnostics == [diagnostic]
    assert "ingest_diagnostics" in report.failing_checks


@pytest.mark.parametrize(
    ("language", "module_name", "filename", "source", "helper"),
    [
        ("go", "lattice.ingest.go_graph", "main.go", "package main\n", "ensure_bridge"),
        ("rust", "lattice.ingest.rust_graph", "main.rs", "fn main() {}\n", "ensure_bridge"),
        ("ruby", "lattice.ingest.ruby_graph", "main.rb", "def main; end\n", "ruby_bridge"),
    ],
)
def test_native_graph_bridge_timeout_is_gate_visible(
        tmp_path, monkeypatch, language, module_name, filename, source, helper):
    module = importlib.import_module(module_name)
    (tmp_path / filename).write_text(source)
    if helper == "ruby_bridge":
        monkeypatch.setattr(module, helper, lambda _script: pathlib.Path("/fake/bridge"))
    else:
        monkeypatch.setattr(module, helper, lambda: pathlib.Path("/fake/bridge"))

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("bridge", 30)

    monkeypatch.setattr(module.subprocess, "run", timeout)
    raw = getattr(module, f"{language}_ingest")(tmp_path)

    assert any(d["kind"] == "bridge_error" and "timed out" in d["message"]
               for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain missing")
def test_go_parse_failure_is_not_a_clean_empty_graph(tmp_path):
    from lattice.ingest.go_graph import go_ingest

    (tmp_path / "broken.go").write_text("package main\nfunc {\n")
    raw = go_ingest(tmp_path)

    assert raw.files == ["broken.go"]
    assert any(d["kind"] == "parse_error" for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")
def test_rust_parse_failure_is_not_a_clean_empty_graph(tmp_path):
    from lattice.ingest.rust_graph import rust_ingest

    (tmp_path / "broken.rs").write_text("fn {\n")
    raw = rust_ingest(tmp_path)

    assert raw.files == ["broken.rs"]
    assert any(d["kind"] == "parse_error" for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby missing")
def test_ruby_parse_failure_is_not_a_clean_empty_graph(tmp_path):
    from lattice.ingest.ruby_graph import ruby_ingest

    (tmp_path / "broken.rb").write_text("def broken(\n")
    raw = ruby_ingest(tmp_path)

    assert raw.files == ["broken.rb"]
    assert any(d["kind"] == "parse_error" for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain missing")
def test_go_qualified_call_never_chooses_first_duplicate(tmp_path):
    from lattice.ingest.go_graph import go_ingest

    (tmp_path / "go.mod").write_text("module example.com/dupe\n\ngo 1.22\n")
    for package in ("a", "b"):
        folder = tmp_path / package
        folder.mkdir()
        (folder / f"{package}.go").write_text(f"package {package}\nfunc Run() {{}}\n")
    (tmp_path / "main.go").write_text(
        'package main\nimport "example.com/dupe/b"\nfunc main() { b.Run() }\n'
    )

    raw = go_ingest(tmp_path)
    calls = [r for r in raw.references
             if r.kind == "references" and r.from_file == "main.go" and r.resolved]
    assert any(r.to_file == "b/b.go" and r.name == "b.Run" for r in calls)
    assert not any(r.to_file == "a/a.go" for r in calls)


@pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")
def test_rust_qualified_call_never_chooses_first_duplicate(tmp_path):
    from lattice.ingest.rust_graph import rust_ingest

    (tmp_path / "main.rs").write_text(
        "struct A;\nstruct B;\n"
        "impl A { fn run() {} }\nimpl B { fn run() {} }\n"
        "fn main() { B::run(); }\n"
    )
    raw = rust_ingest(tmp_path)
    b_run = next(s for s in raw.symbols if s.container == "B" and s.name == "run")
    calls = [r for r in raw.references if r.kind == "references" and r.resolved]

    assert any(r.to_line == b_run.start_line and r.name == "B::run" for r in calls)
    assert not any(r.to_line != b_run.start_line and r.name == "B::run" for r in calls)


@pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")
def test_rust_inline_modules_keep_full_identity_for_duplicate_functions(tmp_path):
    from lattice.ingest.rust_graph import rust_ingest

    (tmp_path / "main.rs").write_text(
        "mod a { pub fn run() {} }\n"
        "mod b { pub fn run() {} }\n"
        "fn main() { b::run(); }\n"
    )
    raw = rust_ingest(tmp_path)
    runs = [s for s in raw.symbols if s.name == "run"]
    b_run = next(s for s in runs if s.container == "b")
    calls = [r for r in raw.references if r.kind == "references" and r.resolved]

    assert {s.container for s in runs} == {"a", "b"}
    assert any(r.name == "b::run" and r.to_line == b_run.start_line for r in calls)
    assert not any(r.name == "b::run" and r.to_line != b_run.start_line for r in calls)

    net = build(raw)
    run_ids = {v.id for v in net.vertices if v.name == "run"}
    fact_targets = {e.members[-1] for e in net.hyperedges
                    if e.members[-1] in run_ids and e.confidence == 1.0}
    assert fact_targets == {next(v.id for v in net.vertices
                                 if v.name == "run" and v.start_line == b_run.start_line)}


@pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")
def test_rust_inline_module_use_binding_does_not_leak_to_sibling(tmp_path):
    from lattice.ingest.rust_graph import rust_ingest

    src = tmp_path / "src"
    src.mkdir()
    (src / "target.rs").write_text("pub fn go() {}\n")
    (src / "lib.rs").write_text(
        "mod target;\n"
        "mod a { use crate::target::go; pub fn invoke() { go(); } }\n"
        "mod b { pub fn invoke() { go(); } }\n"
    )
    raw = rust_ingest(tmp_path)
    calls = [r for r in raw.references if r.kind == "references" and r.name == "go"]
    a_invoke = next(s for s in raw.symbols if s.name == "invoke" and s.container == "a")
    b_invoke = next(s for s in raw.symbols if s.name == "invoke" and s.container == "b")
    a_call = next(r for r in calls if a_invoke.start_line <= r.from_line <= a_invoke.end_line)
    b_call = next(r for r in calls if b_invoke.start_line <= r.from_line <= b_invoke.end_line)

    assert a_call.resolved and a_call.to_file == "src/target.rs"
    assert not b_call.resolved and b_call.to_file is None
    net = build(raw)
    go_ids = {v.id for v in net.vertices if v.name == "go"}
    b_id = next(v.id for v in net.vertices
                if v.name == "invoke" and v.start_line == b_invoke.start_line)
    assert not any(e.members[0] == b_id and e.members[-1] in go_ids
                   and e.confidence == 1.0 for e in net.hyperedges)


@pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")
def test_rust_renamed_use_selects_original_symbol_in_requested_module(tmp_path):
    from lattice.ingest.rust_graph import rust_ingest

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.rs").write_text("pub fn run() {}\n")
    (src / "b.rs").write_text("pub fn run() {}\n")
    (src / "lib.rs").write_text(
        "mod a;\nmod b;\n"
        "use crate::b::run as selected;\n"
        "pub fn invoke() { selected(); }\n"
    )
    raw = rust_ingest(tmp_path)
    selected = next(r for r in raw.references
                    if r.kind == "references" and r.name == "selected")

    assert selected.resolved
    assert selected.to_file == "src/b.rs"
    assert not selected.to_file == "src/a.rs"

    net = build(raw)
    b_run_id = next(v.id for v in net.vertices
                    if v.file == "src/b.rs" and v.name == "run")
    a_run_id = next(v.id for v in net.vertices
                    if v.file == "src/a.rs" and v.name == "run")
    invoke_id = next(v.id for v in net.vertices if v.name == "invoke")
    fact_targets = {e.members[-1] for e in net.hyperedges
                    if e.members[0] == invoke_id and e.confidence == 1.0}
    assert b_run_id in fact_targets
    assert a_run_id not in fact_targets


@pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")
def test_rust_crate_qualified_call_selects_separate_module_file(tmp_path):
    from lattice.ingest.rust_graph import rust_ingest

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.rs").write_text("pub fn run() {}\n")
    (src / "b.rs").write_text("pub fn run() {}\n")
    (src / "lib.rs").write_text(
        "mod a;\nmod b;\npub fn invoke() { crate::b::run(); }\n"
    )

    raw = rust_ingest(tmp_path)
    call = next(r for r in raw.references
                if r.kind == "references" and r.name == "crate::b::run")

    assert call.resolved
    assert call.to_file == "src/b.rs"
    net = build(raw)
    invoke_id = next(v.id for v in net.vertices if v.name == "invoke")
    a_id = next(v.id for v in net.vertices if v.file == "src/a.rs" and v.name == "run")
    b_id = next(v.id for v in net.vertices if v.file == "src/b.rs" and v.name == "run")
    facts = {edge.members[-1] for edge in net.hyperedges
             if edge.members[0] == invoke_id and edge.confidence == 1.0}
    assert b_id in facts
    assert a_id not in facts


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby missing")
def test_ruby_receiver_command_call_resolves_within_its_container(tmp_path):
    from lattice.ingest.ruby_graph import ruby_ingest

    (tmp_path / "app.rb").write_text(
        "class A\n  def run(x); end\nend\n"
        "class B\n  def run(x); end\n  def call(x)\n    self.run x\n  end\nend\n"
    )
    raw = ruby_ingest(tmp_path)
    b_run = next(s for s in raw.symbols if s.container == "B" and s.name == "run")
    calls = [r for r in raw.references if r.kind == "references" and r.resolved]

    assert any(r.to_line == b_run.start_line and r.name == "B.run" for r in calls)
    assert not any(r.to_line != b_run.start_line and r.name == "B.run" for r in calls)


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby missing")
def test_ambiguous_receiver_call_never_becomes_a_first_definition_fact(tmp_path):
    from lattice.ingest.ruby_graph import ruby_ingest

    (tmp_path / "app.rb").write_text(
        "class A\n  def run(x); end\nend\n"
        "class B\n  def run(x); end\nend\n"
        "class Caller\n  def invoke(target, x)\n    target.run x\n  end\nend\n"
    )
    raw = ruby_ingest(tmp_path)
    invoke = next(s for s in raw.symbols if s.container == "Caller" and s.name == "invoke")
    ambiguous = [r for r in raw.references
                 if r.kind == "references" and r.from_line > invoke.start_line
                 and r.from_line <= invoke.end_line and r.name == "run"]
    assert ambiguous and all(not r.resolved and r.to_file is None for r in ambiguous)

    net = build(raw)
    invoke_id = next(v.id for v in net.vertices
                     if v.name == "invoke" and v.kind == "method")
    duplicate_ids = {v.id for v in net.vertices if v.name == "run" and v.kind == "method"}
    target_edges = [e for e in net.hyperedges
                    if e.members[0] == invoke_id and e.members[-1] in duplicate_ids]
    assert target_edges
    assert all(e.kind == "dispatch" and e.provenance == "name-match"
               and e.confidence < 1.0 for e in target_edges)


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby missing")
def test_ruby_nested_constants_keep_full_identity_for_self_call(tmp_path):
    from lattice.ingest.ruby_graph import ruby_ingest

    (tmp_path / "app.rb").write_text(
        "module A\n  class X\n    def run; :a; end\n  end\nend\n"
        "module B\n  class X\n    def run; :b; end\n"
        "    def invoke\n      self.run\n    end\n  end\nend\n"
    )
    raw = ruby_ingest(tmp_path)
    runs = [s for s in raw.symbols if s.name == "run"]
    b_run = next(s for s in runs if s.container == "B::X")
    calls = [r for r in raw.references if r.kind == "references" and r.resolved]

    assert {s.container for s in runs} == {"A::X", "B::X"}
    assert any(r.name == "B::X.run" and r.to_line == b_run.start_line for r in calls)
    assert not any(r.name == "B::X.run" and r.to_line != b_run.start_line for r in calls)


@pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain missing")
def test_go_preserves_external_and_broken_internal_imports(tmp_path):
    from lattice.ingest.go_graph import go_ingest

    (tmp_path / "go.mod").write_text("module example.com/imports\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text(
        'package main\nimport _ "fmt"\nimport _ "example.com/imports/missing"\nfunc main() {}\n'
    )
    raw = go_ingest(tmp_path)
    imports = [r for r in raw.references if r.kind == "imports"]

    assert any(r.name == "fmt" and r.to_file is None for r in imports)
    assert any(r.name.endswith("/missing") and r.to_file and not r.resolved for r in imports)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")
def test_rust_preserves_external_and_broken_internal_imports(tmp_path):
    from lattice.ingest.rust_graph import rust_ingest

    (tmp_path / "main.rs").write_text(
        "mod missing;\nuse serde::Serialize;\nfn main() {}\n"
    )
    raw = rust_ingest(tmp_path)
    imports = [r for r in raw.references if r.kind == "imports"]

    assert any(r.name == "serde::Serialize" and r.to_file is None for r in imports)
    assert any(r.name == "missing" and r.to_file and not r.resolved for r in imports)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby missing")
def test_ruby_preserves_imports_and_normalizes_require_relative(tmp_path):
    from lattice.ingest.ruby_graph import ruby_ingest

    (tmp_path / "api.rb").write_text("class Api; end\n")
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.rb").write_text(
        'require "json"\nrequire_relative "../lib/../api"\nrequire_relative "../missing"\n'
    )
    raw = ruby_ingest(tmp_path)
    imports = [r for r in raw.references if r.kind == "imports"]

    assert any(r.name == "json" and r.to_file is None for r in imports)
    assert any(r.to_file == "api.rb" and r.resolved for r in imports)
    assert any(r.to_file == "missing.rb" and not r.resolved for r in imports)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")
def test_rust_nested_file_module_resolves_below_the_file_stem(tmp_path):
    from lattice.ingest.rust_graph import rust_ingest

    src = tmp_path / "src"
    (src / "foo").mkdir(parents=True)
    (src / "lib.rs").write_text("mod foo;\n")
    (src / "foo.rs").write_text("mod bar;\n")
    (src / "foo" / "bar.rs").write_text("pub fn nested() {}\n")
    raw = rust_ingest(tmp_path)
    imports = [r for r in raw.references if r.kind == "imports"]

    assert any(r.from_file == "src/foo.rs" and r.to_file == "src/foo/bar.rs"
               and r.resolved for r in imports)


@pytest.mark.parametrize(
    ("language", "fixture"),
    [("go", "tests/fixtures/go_deep"), ("rust", "tests/fixtures/rust_deep")],
)
def test_native_main_entrypoint_reaches_main_symbol(language, fixture):
    required = "go" if language == "go" else "cargo"
    if shutil.which(required) is None:
        pytest.skip(f"{required} missing")
    from pathlib import Path
    from lattice.cache import ingest_source
    from lattice.graph.query import GraphView

    raw = ingest_source(Path(__file__).resolve().parents[1] / fixture, language)
    net = build(raw)
    entry_modules = {s.vertex_id for s in net.surfaces if s.kind == "entrypoint"}
    main_ids = {v.id for v in net.vertices if v.kind == "function" and v.name == "main"}
    stub_ids = {v.id for v in net.vertices if v.stub}

    assert any(e.members[0] in entry_modules and e.members[-1] in main_ids
               and e.resolved for e in net.hyperedges)
    view = GraphView(net)
    reached = set().union(*(view.reachable_from(entry) for entry in entry_modules))
    assert main_ids <= reached
    assert stub_ids & reached, "entrypoint traversal stopped before the downstream stub"
    assert main_ids.isdisjoint(view.dead_code()), "main remains dead despite its entry surface"
