# tests/test_paradox.py
from lattice.logic.extract import extract_conditions
from lattice.logic.scan import scan_paradoxes


def test_extract_if_and_while():
    text = "function f(){\n  if (a && !a) {\n    g();\n  }\n  while (p || q) {}\n}"
    got = extract_conditions(text)
    assert (2, "a && !a") in got
    assert any(c == "p || q" for _, c in got)


def test_extract_handles_nested_parens():
    text = "if (foo(x) && (a || b)) {}"
    assert extract_conditions(text) == [(1, "foo(x) && (a || b)")]


def test_scan_finds_contradiction(tmp_path):
    (tmp_path / "a.ts").write_text("if (ready && !ready) { dead(); }\n")
    fs = scan_paradoxes(tmp_path)
    assert len(fs) == 1
    assert fs[0]["kind"] == "contradiction"
    assert fs[0]["file"] == "a.ts" and fs[0]["line"] == 1


def test_scan_finds_tautology(tmp_path):
    (tmp_path / "a.ts").write_text("while (x || !x) { spin(); }\n")
    fs = scan_paradoxes(tmp_path)
    assert len(fs) == 1 and fs[0]["kind"] == "tautology"


def test_scan_clean(tmp_path):
    (tmp_path / "a.ts").write_text("if (a && b) { ok(); }\nif (x !== y) { go(); }\n")
    assert scan_paradoxes(tmp_path) == []


def test_cli_paradox_exit_codes(tmp_path):
    from lattice.cli import main as cli
    (tmp_path / "a.ts").write_text("if (x || !x) { always(); }\n")
    assert cli.main(["paradox", str(tmp_path)]) == 0
    assert cli.main(["paradox", str(tmp_path), "--fail-on-paradox"]) == 1
