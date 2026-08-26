"""Completeness and identity contracts shared by Python and Solidity frontends."""
from __future__ import annotations

import shutil

import pytest

from lattice.complete.gate import check
from lattice.graph.builder import build


@pytest.mark.parametrize(
    ("language", "tool", "filename", "source"),
    [
        ("python", None, "one.py", "def run():\n    return 1\n"),
        ("go", "go", "one.go", "package one\nfunc Run() {}\n"),
        ("rust", "cargo", "one.rs", "pub fn run() {}\n"),
        ("ruby", "ruby", "one.rb", "def run\n  1\nend\n"),
        ("solidity", "solc", "One.sol",
         "pragma solidity ^0.8.0; contract One { function run() external {} }\n"),
    ],
)
def test_direct_source_file_ingest_is_not_a_clean_empty_graph(
        tmp_path, language, tool, filename, source):
    if tool and shutil.which(tool) is None:
        pytest.skip(f"{tool} missing")
    from lattice.cache import ingest_source, load_network

    path = tmp_path / filename
    path.write_text(source)
    raw = ingest_source(path, language)
    net, source_root = load_network(path, language)

    assert raw.root == str(tmp_path)
    assert raw.files == [filename]
    assert raw.symbols and not raw.diagnostics
    assert net.vertices
    assert source_root == tmp_path


@pytest.mark.parametrize("language", ["python", "go", "rust", "ruby", "solidity"])
def test_explicit_wrong_source_file_type_fails_closed(tmp_path, language):
    from lattice.cache import ingest_source

    path = tmp_path / "notes.txt"
    path.write_text("not source for the selected frontend\n")
    raw = ingest_source(path, language)

    assert raw.root == str(tmp_path)
    assert raw.files == []
    assert any(d["kind"] == "unsupported_source_file" for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.parametrize("language", ["python", "go", "rust", "ruby", "solidity"])
def test_explicit_empty_source_directory_fails_closed(tmp_path, language):
    from lattice.cache import ingest_source

    raw = ingest_source(tmp_path, language)

    assert raw.root == str(tmp_path)
    assert raw.files == []
    assert any(d["kind"] == "no_source_files" for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


def test_python_parse_failure_is_diagnostic_and_fails_gate(tmp_path):
    from lattice.ingest.python_ast import python_ingest

    (tmp_path / "broken.py").write_text("def broken(\n")
    raw = python_ingest(tmp_path)

    assert raw.files == ["broken.py"]
    assert any(d["kind"] == "parse_error" for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


def test_python_imports_include_resolved_external_and_broken_relative(tmp_path):
    from lattice.ingest.python_ast import python_ingest

    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "api.py").write_text("def run():\n    return 1\n")
    (package / "main.py").write_text(
        "import json\nfrom .api import run\nfrom .missing import nope\nrun()\n"
    )
    raw = python_ingest(tmp_path)
    imports = [r for r in raw.references if r.kind == "imports"]

    assert any(r.name == "json" and r.to_file is None for r in imports)
    assert any(r.name == ".api" and r.to_file == "pkg/api.py" and r.resolved
               for r in imports)
    assert any(r.name == ".missing" and r.to_file == "pkg/missing.py" and not r.resolved
               for r in imports)
    assert check(build(raw)).verdict == "fail"


def test_python_import_binding_selects_the_requested_duplicate(tmp_path):
    from lattice.ingest.python_ast import python_ingest

    (tmp_path / "a.py").write_text("def run():\n    return 'a'\n")
    (tmp_path / "b.py").write_text("def run():\n    return 'b'\n")
    (tmp_path / "main.py").write_text("from b import run\nrun()\n")
    raw = python_ingest(tmp_path)
    calls = [r for r in raw.references
             if r.kind == "references" and r.from_file == "main.py" and r.resolved]

    assert any(r.to_file == "b.py" for r in calls)
    assert not any(r.to_file == "a.py" for r in calls)


def test_python_import_alias_keeps_the_original_target_identity(tmp_path):
    from lattice.ingest.python_ast import python_ingest

    (tmp_path / "api.py").write_text("def execute():\n    return 1\n")
    (tmp_path / "main.py").write_text("from api import execute as run\nrun()\n")
    raw = python_ingest(tmp_path)
    execute = next(s for s in raw.symbols if s.file == "api.py" and s.name == "execute")

    assert any(r.kind == "references" and r.from_file == "main.py" and r.resolved
               and r.to_file == "api.py" and r.to_line == execute.start_line
               for r in raw.references)


def test_python_module_import_does_not_target_nested_method(tmp_path):
    from lattice.ingest.python_ast import python_ingest

    (tmp_path / "util.py").write_text(
        "class C:\n"
        "    @staticmethod\n"
        "    def run():\n"
        "        return 1\n"
    )
    (tmp_path / "main.py").write_text(
        "import util\n"
        "def invoke():\n"
        "    return util.run()\n"
    )

    raw = python_ingest(tmp_path)
    call = next(r for r in raw.references
                if r.from_file == "main.py" and r.name == "run")

    assert not call.resolved
    assert call.to_file is None


def test_python_function_local_import_binding_does_not_leak_to_sibling_scope(tmp_path):
    from lattice.ingest.python_ast import python_ingest

    (tmp_path / "a.py").write_text("def go():\n    return 1\n")
    (tmp_path / "main.py").write_text(
        "def setup():\n"
        "    import a as svc\n"
        "    return svc\n"
        "def run():\n"
        "    return svc.go()\n"
    )
    raw = python_ingest(tmp_path)
    call = next(r for r in raw.references
                if r.kind == "references" and r.from_file == "main.py" and r.name == "go")

    assert not call.resolved and call.to_file is None
    net = build(raw)
    go_ids = {v.id for v in net.vertices if v.name == "go"}
    assert not any(e.members[-1] in go_ids and e.confidence == 1.0
                   for e in net.hyperedges)


def test_python_self_call_selects_its_container_duplicate(tmp_path):
    from lattice.ingest.python_ast import python_ingest

    (tmp_path / "app.py").write_text(
        "class A:\n    def run(self):\n        return 'a'\n"
        "class B:\n    def run(self):\n        return 'b'\n"
        "    def invoke(self):\n        return self.run()\n"
    )
    raw = python_ingest(tmp_path)
    b_run = next(s for s in raw.symbols if s.container == "B" and s.name == "run")
    calls = [r for r in raw.references if r.kind == "references" and r.resolved]

    assert any(r.name == "self.run" and r.to_line == b_run.start_line for r in calls)
    assert not any(r.name == "self.run" and r.to_line != b_run.start_line for r in calls)


def test_python_nested_scopes_keep_full_identity_for_duplicate_methods_and_functions(tmp_path):
    from lattice.ingest.python_ast import python_ingest

    (tmp_path / "app.py").write_text(
        "class A:\n"
        "    class X:\n"
        "        def run(self): return 'a'\n"
        "class B:\n"
        "    class X:\n"
        "        def run(self): return 'b'\n"
        "        def invoke(self): return self.run()\n"
        "def left():\n"
        "    def helper(): return 'left'\n"
        "    return helper()\n"
        "def right():\n"
        "    def helper(): return 'right'\n"
        "    return helper()\n"
        "def factory():\n"
        "    class Hidden:\n"
        "        def run(self): return 'hidden'\n"
        "    return Hidden\n"
    )
    raw = python_ingest(tmp_path)
    b_run = next(s for s in raw.symbols if s.container == "B.X" and s.name == "run")
    right_helper = next(s for s in raw.symbols
                        if s.container == "right" and s.name == "helper")
    resolved = [r for r in raw.references if r.kind == "references" and r.resolved]

    assert any(r.name == "self.run" and r.to_line == b_run.start_line for r in resolved)
    assert any(r.name == "helper" and r.to_line == right_helper.start_line for r in resolved)
    assert not any(r.name == "self.run" and r.to_line != b_run.start_line for r in resolved)

    net = build(raw)
    public_ids = {surface.vertex_id for surface in net.surfaces
                  if surface.kind == "public_api"}
    nested = {v.id for v in net.vertices
              if v.name in {"helper", "Hidden"}
              or (v.name == "run" and v.start_line > right_helper.start_line)}
    assert nested.isdisjoint(public_ids)


_HAS_SOLC = shutil.which("solc") is not None


def test_solidity_import_scanner_ignores_comments_and_string_contents():
    from lattice.ingest.solidity import _solidity_imports

    source = (
        '// import "./Comment.sol";\n'
        'string constant NOTE = "import \\\"./String.sol\\\";";\n'
        'import {Thing as Alias} from "./Real.sol";\n'
        '/* import "./Block.sol"; */\n'
    )
    assert list(_solidity_imports(source)) == [(3, "./Real.sol")]


@pytest.mark.skipif(not _HAS_SOLC, reason="solc not installed")
def test_solidity_parse_failure_is_diagnostic_and_fails_gate(tmp_path):
    from lattice.ingest.solidity import solidity_ingest

    (tmp_path / "Broken.sol").write_text("pragma solidity ^0.8.0; contract {\n")
    raw = solidity_ingest(tmp_path)

    assert raw.files == ["Broken.sol"]
    assert any(d["kind"] == "parse_error" for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(not _HAS_SOLC, reason="solc not installed")
def test_solidity_imports_preserve_resolved_external_and_broken_paths(tmp_path):
    from lattice.ingest.solidity import solidity_ingest

    (tmp_path / "Base.sol").write_text(
        "pragma solidity ^0.8.0; contract Base {}\n"
    )
    (tmp_path / "App.sol").write_text(
        'pragma solidity ^0.8.0;\nimport "./Base.sol";\n'
        'import "./Missing.sol";\nimport "@vendor/External.sol";\ncontract App {}\n'
    )
    raw = solidity_ingest(tmp_path)
    imports = [r for r in raw.references if r.kind == "imports"]

    assert any(r.name == "./Base.sol" and r.to_file == "Base.sol" and r.resolved
               for r in imports)
    assert any(r.name == "./Missing.sol" and r.to_file == "Missing.sol" and not r.resolved
               for r in imports)
    assert any(r.name == "@vendor/External.sol" and r.to_file is None for r in imports)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(not _HAS_SOLC, reason="solc not installed")
def test_solidity_internal_call_selects_its_contract_duplicate(tmp_path):
    from lattice.ingest.solidity import solidity_ingest

    (tmp_path / "App.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract A { function helper() internal {} }\n"
        "contract B {\n"
        "  function helper() internal {}\n"
        "  function invoke() public { helper(); }\n"
        "}\n"
    )
    raw = solidity_ingest(tmp_path)
    b_helper = next(s for s in raw.symbols if s.container == "B" and s.name == "helper")
    calls = [r for r in raw.references if r.kind == "references" and r.resolved]

    assert any(r.name == "B.helper" and r.to_line == b_helper.start_line for r in calls)
    assert not any(r.name == "B.helper" and r.to_line != b_helper.start_line for r in calls)


@pytest.mark.skipif(not _HAS_SOLC, reason="solc not installed")
def test_solidity_this_and_known_library_receivers_resolve_without_losing_boundary(tmp_path):
    from lattice.ingest.solidity import solidity_ingest

    (tmp_path / "App.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "library Lib {\n"
        "  function helper() internal {}\n"
        "  function exportedHelper() public {}\n"
        "}\n"
        "contract Base { function inherited() public {} }\n"
        "contract App is Base {\n"
        "  function local() public {}\n"
        "  function invoke() public {\n"
        "    this.local(); Lib.helper(); Lib.exportedHelper(); super.inherited();\n"
        "  }\n"
        "}\n"
    )
    raw = solidity_ingest(tmp_path)
    local = next(s for s in raw.symbols if s.container == "App" and s.name == "local")
    helper = next(s for s in raw.symbols if s.container == "Lib" and s.name == "helper")
    inherited = next(s for s in raw.symbols
                     if s.container == "Base" and s.name == "inherited")
    resolved = [r for r in raw.references if r.kind == "references" and r.resolved]
    unresolved = [r for r in raw.references if r.kind == "references" and not r.resolved]

    assert any(r.name == "this.local" and r.to_line == local.start_line for r in resolved)
    assert any(r.name == "Lib.helper" and r.to_line == helper.start_line for r in resolved)
    assert any(r.name == "super.inherited" and r.to_line == inherited.start_line
               for r in resolved)
    assert {r.name for r in unresolved} >= {
        "external:this.local", "external:Lib.exportedHelper",
    }
    assert "external:Lib.helper" not in {r.name for r in unresolved}
    assert not any("super.inherited" in (r.name or "") for r in unresolved)

    net = build(raw)
    invoke_id = next(v.id for v in net.vertices if v.name == "invoke")
    external_sources = {s.vertex_id for s in net.surfaces if s.kind == "external_call"}
    assert invoke_id in external_sources  # this/public-library calls remain boundaries
    assert not any(v.name == "super.inherited" and v.kind == "external"
                   for v in net.vertices)


@pytest.mark.skipif(not _HAS_SOLC, reason="solc not installed")
def test_solidity_ambiguous_super_call_stays_internal_and_fails_closed(tmp_path):
    from lattice.ingest.solidity import solidity_ingest

    (tmp_path / "App.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Left { function run() public virtual {} }\n"
        "contract Right { function run() public virtual {} }\n"
        "contract App is Left, Right {\n"
        "  function run() public override(Left, Right) { super.run(); }\n"
        "}\n"
    )
    raw = solidity_ingest(tmp_path)
    unresolved = [r for r in raw.references if not r.resolved and r.name == "super.run"]

    assert len(unresolved) == 1
    assert unresolved[0].to_file == "App.sol"
    net = build(raw)
    report = check(net)
    assert report.verdict != "pass"
    assert "dangling_edges" in report.failing_checks
    assert not any(v.kind == "external" and "super.run" in v.name for v in net.vertices)


@pytest.mark.skipif(not _HAS_SOLC, reason="solc not installed")
def test_solidity_duplicate_contract_names_do_not_cross_wire_super_resolution(tmp_path):
    from lattice.ingest.solidity import solidity_ingest

    (tmp_path / "First.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Left { function run() public virtual {} }\n"
        "contract App is Left { function invoke() public { super.run(); } }\n"
    )
    (tmp_path / "Second.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Right { function run() public virtual {} }\n"
        "contract App is Right {}\n"
    )
    raw = solidity_ingest(tmp_path)
    left_run = next(s for s in raw.symbols
                    if s.file == "First.sol" and s.container == "Left" and s.name == "run")
    super_call = next(r for r in raw.references
                      if r.from_file == "First.sol" and r.name == "super.run")

    assert super_call.resolved
    assert super_call.to_file == "First.sol"
    assert super_call.to_line == left_run.start_line
