"""Pins the homology-leg cross-language proof: the SAME homology operator that detects reentrancy
detects Python lock-ordering deadlock — with the undirected-vs-directed boundary handled honestly
(sound on 2-cycles, blind-spot escalation on N>=3 directed cycles)."""
import pathlib
from lattice.ingest.python_locks import lock_order_audit


def _audit(tmp_path, src):
    (tmp_path / "m.py").write_text(src)
    return [f["kind"] for f in lock_order_audit(tmp_path / "m.py")]


def test_pairwise_inversion_is_deadlock(tmp_path):
    src = ("def t():\n    with a:\n        with b: pass\n"
           "def u():\n    with b:\n        with a: pass\n")
    assert "lock_order_inversion" in _audit(tmp_path, src)


def test_consistent_order_is_clean(tmp_path):
    # a<b, b<c, a<c — an undirected triangle but a CONSISTENT order: must NOT false-positive
    src = ("def f():\n    with a:\n        with b: pass\n"
           "def g():\n    with b:\n        with c: pass\n"
           "def h():\n    with a:\n        with c: pass\n")
    assert _audit(tmp_path, src) == []


def test_directed_3cycle_is_deadlock(tmp_path):
    # a->b, b->c, c->a is a real directed deadlock — the DIRECTED variant now FIRES (not a blind spot)
    src = ("def f():\n    with a:\n        with b: pass\n"
           "def g():\n    with b:\n        with c: pass\n"
           "def h():\n    with c:\n        with a: pass\n")
    assert "lock_order_inversion" in _audit(tmp_path, src)
