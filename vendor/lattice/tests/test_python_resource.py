"""Pins the cross-language proof: the SAME conservation engine that finds token value-leaks in
Solidity finds resource leaks in Python via a thin adapter — the obstruction math is shared."""
import pathlib
from lattice.ingest.python_resource import resource_audit


def _audit(tmp_path, src):
    (tmp_path / "m.py").write_text(src)
    return {(f["kind"], f["function"]) for f in resource_audit(tmp_path / "m.py")}


def test_open_without_close_is_a_leak(tmp_path):
    got = _audit(tmp_path, "def f():\n    h = open('x')\n    return h.read()\n")
    assert ("resource_leak", "f") in got


def test_balanced_open_close_is_clean(tmp_path):
    got = _audit(tmp_path, "def f():\n    h = open('x')\n    d = h.read()\n    h.close()\n    return d\n")
    assert got == set()


def test_with_statement_is_clean(tmp_path):
    got = _audit(tmp_path, "def f():\n    with open('x') as h:\n        return h.read()\n")
    assert got == set()


def test_double_close_is_over_release(tmp_path):
    got = _audit(tmp_path, "def f():\n    h = open('x')\n    h.close()\n    h.close()\n")
    assert ("over_release", "f") in got
