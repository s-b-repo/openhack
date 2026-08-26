import shutil
import pytest
from lattice.cache import detect_languages, build_auto, ingest_source
from lattice.complete.gate import check
from lattice.graph.builder import build


def test_detect_languages_sees_python(tmp_path):
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    assert "python" in detect_languages(tmp_path)


def test_detect_languages_sees_javascript(tmp_path):
    (tmp_path / "main.js").write_text("function run() {}\n")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("function built() {}\n")
    assert "javascript" in detect_languages(tmp_path)


def test_detect_languages_ignores_only_generated_javascript(tmp_path):
    (tmp_path / "renderer.bundle.js").write_text("function generated() {}\n")
    assert "javascript" not in detect_languages(tmp_path)


@pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed")
def test_auto_handles_python_and_solidity_in_one_graph(tmp_path):
    """'Handle any code it sees': a directory with both Python and Solidity is detected
    and ingested into ONE unified graph, no --lang needed."""
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract C { function g() public {} }\n")
    langs = detect_languages(tmp_path)
    assert {"python", "solidity"} <= set(langs), langs
    net, handled = build_auto(tmp_path)
    names = {v.name for v in net.vertices}
    assert {"f", "C", "g"} <= names, names         # both languages, one graph
    # edge ids stay unique across the merge (no g0:/g1: collisions break anything)
    assert len({e.id for e in net.hyperedges}) == len(net.hyperedges)


@pytest.mark.parametrize(
    ("language", "filename", "source", "expected"),
    [
        ("shell", "script.sh", "run() { echo hi; }\nrun\n", "run"),
        ("sql", "schema.sql", "CREATE FUNCTION do_work() RETURNS void AS $$ SELECT 1; $$ LANGUAGE sql;\n",
         "do_work"),
        ("iac", "Dockerfile", "FROM alpine AS app\nEXPOSE 8080\n", "app"),
    ],
)
def test_auto_and_explicit_ingest_support_single_non_lsp_source_file(
        tmp_path, language, filename, source, expected):
    path = tmp_path / filename
    path.write_text(source)

    raw = ingest_source(path, language)
    net, handled = build_auto(path)

    assert raw.root == str(tmp_path)
    assert raw.files == [filename]
    assert expected in {symbol.name for symbol in raw.symbols}
    assert raw.diagnostics == []
    assert handled == [language]
    assert expected in {vertex.name for vertex in net.vertices}
    assert check(net).verdict == "pass"


@pytest.mark.parametrize(
    ("language", "filename"),
    [("shell", "script.txt"), ("sql", "schema.txt"), ("iac", "compose.yaml")],
)
def test_explicit_non_lsp_ingest_rejects_unsupported_single_file(
        tmp_path, language, filename):
    path = tmp_path / filename
    path.write_text("not supported by this frontend\n")

    raw = ingest_source(path, language)

    assert raw.root == str(tmp_path)
    assert raw.files == []
    assert [diagnostic["kind"] for diagnostic in raw.diagnostics] == ["unsupported_file"]
    assert check(build(raw)).verdict == "fail"


@pytest.mark.parametrize("language", ["shell", "sql", "iac"])
def test_explicit_non_lsp_ingest_rejects_empty_directory(tmp_path, language):
    raw = ingest_source(tmp_path, language)

    assert raw.files == []
    assert [diagnostic["kind"] for diagnostic in raw.diagnostics] == ["no_source_files"]
    assert check(build(raw)).verdict == "fail"


def test_malformed_shell_source_fails_closed(tmp_path):
    if shutil.which("bash") is None and shutil.which("sh") is None:
        pytest.skip("shell syntax validator unavailable")
    source = tmp_path / "broken.sh"
    source.write_text("run() {\n  echo never-closed\n")

    raw = ingest_source(source, "shell")

    assert any(d["kind"] == "parse_error" and d["severity"] == "error"
               for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.parametrize(
    ("language", "filename", "source"),
    [
        ("sql", "broken.sql", "CREATE FUNCTION broken(\n"),
        ("iac", "Dockerfile", "FROM\nRUN echo unreachable\n"),
    ],
)
def test_obviously_malformed_regex_frontend_source_fails_closed(
        tmp_path, language, filename, source):
    path = tmp_path / filename
    path.write_text(source)

    raw = ingest_source(path, language)

    assert any(d["kind"] == "parse_error" and d["severity"] == "error"
               for d in raw.diagnostics)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.parametrize(
    ("language", "suffix", "definition", "caller"),
    [
        ("shell", ".sh", "run() { echo ok; }\n", "call() { run; }\n"),
        ("sql", ".sql",
         "CREATE FUNCTION run() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql;\n",
         "CREATE FUNCTION call() RETURNS int AS $$ SELECT run(); $$ LANGUAGE sql;\n"),
    ],
)
def test_duplicate_regex_frontend_names_resolve_to_same_file_definition(
        tmp_path, language, suffix, definition, caller):
    (tmp_path / f"a{suffix}").write_text(definition)
    (tmp_path / f"b{suffix}").write_text(definition + caller)

    raw = ingest_source(tmp_path, language)
    target = next(s for s in raw.symbols if s.file == f"b{suffix}" and s.name == "run")
    refs = [r for r in raw.references if r.from_file == f"b{suffix}" and r.name == "run"]

    assert any(r.resolved and r.to_file == target.file and r.to_line == target.start_line
               for r in refs), refs
    assert not any(r.resolved and r.to_file == f"a{suffix}" for r in refs), refs


def test_dockerfile_prior_stage_resolution_does_not_self_link(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM --platform=linux/arm64 alpine AS build-stage\n"
        "FROM build-stage AS app\n"
    )

    raw = ingest_source(dockerfile, "iac")
    second = next(r for r in raw.references if r.from_line == 2)

    assert second.resolved
    assert second.to_line == 1
