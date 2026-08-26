# Python frontend stub detection: the TS frontend has had is_stub since phase 1;
# the Python frontend never set it, so hunt's public_path_to_stub and called_stub
# signals were structurally blind on Python code.
from __future__ import annotations
import pathlib


def _ingest(tmp_path: pathlib.Path, body: str):
    from lattice.ingest.python_ast import python_ingest
    (tmp_path / "m.py").write_text(body)
    return python_ingest(tmp_path)


def _sym(raw, name):
    return next(s for s in raw.symbols if s.name == name)


def test_pass_only_body_is_a_stub(tmp_path):
    raw = _ingest(tmp_path, "def todo():\n    pass\n")
    assert _sym(raw, "todo").is_stub is True


def test_ellipsis_body_is_a_stub(tmp_path):
    raw = _ingest(tmp_path, "def todo():\n    ...\n")
    assert _sym(raw, "todo").is_stub is True


def test_raise_not_implemented_is_a_stub(tmp_path):
    raw = _ingest(tmp_path, "def todo():\n    raise NotImplementedError\n")
    assert _sym(raw, "todo").is_stub is True
    raw = _ingest(tmp_path, "def todo2():\n    raise NotImplementedError('later')\n")
    assert _sym(raw, "todo2").is_stub is True


def test_docstring_only_body_is_a_stub(tmp_path):
    raw = _ingest(tmp_path, 'def todo():\n    """will do later"""\n')
    assert _sym(raw, "todo").is_stub is True


def test_real_bodies_are_not_stubs(tmp_path):
    raw = _ingest(tmp_path,
                  "def real(x):\n    return x + 1\n\n"
                  "def guard(x):\n    if not x:\n        raise ValueError('x')\n    return x\n\n"
                  'def documented(x):\n    """doc"""\n    return x\n')
    assert _sym(raw, "real").is_stub is False
    assert _sym(raw, "guard").is_stub is False
    assert _sym(raw, "documented").is_stub is False


def test_method_stubs_detected_too(tmp_path):
    raw = _ingest(tmp_path,
                  "class A:\n    def done(self):\n        return 1\n\n"
                  "    def pending(self):\n        raise NotImplementedError\n")
    assert _sym(raw, "pending").is_stub is True
    assert _sym(raw, "done").is_stub is False
