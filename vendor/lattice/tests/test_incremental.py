# tests/test_incremental.py
# Correctness guarantee: splice(old, change) must build the SAME graph as a full
# re-ingest of the new state. If these ever diverge, the mirror drifts — so this
# test is the gate that keeps incremental honest.
import os
import pathlib
import subprocess
import sys
from contextlib import contextmanager, nullcontext

import pytest
from lattice.ingest.types import RawIngest, RawSymbol, RawReference
from lattice.ingest.lsp_client import ingest
from lattice.graph.builder import build
from lattice.incremental import splice, incremental_ingest


def _sym(name, file, start, end):
    return RawSymbol(name=name, kind="function", file=file, start_line=start, end_line=end)


def _ref(ff, fl, tf, tl, kind="references"):
    return RawReference(kind=kind, from_file=ff, from_line=fl, to_file=tf, to_line=tl, resolved=True)


def _sig(net):
    return (sorted(v.id for v in net.vertices),
            sorted((e.kind, tuple(e.members)) for e in net.hyperedges),
            sorted((s.vertex_id, s.kind) for s in net.surfaces),
            net.diagnostics)


def test_splice_equals_full_reingest_when_a_file_gains_a_symbol():
    # OLD: a#foo calls b#bar ; c#baz calls b#bar
    old = RawIngest("ts", "/x",
        symbols=[_sym("foo", "a.ts", 1, 3), _sym("bar", "b.ts", 1, 2), _sym("baz", "c.ts", 1, 3)],
        references=[_ref("a.ts", 2, "b.ts", 1), _ref("c.ts", 2, "b.ts", 1),
                    _ref("a.ts", 1, "b.ts", 1, "imports"), _ref("c.ts", 1, "b.ts", 1, "imports")],
        files=["a.ts", "b.ts", "c.ts"])

    # NEW (b.ts changed: bar now calls a new helper in b.ts) — full re-ingest:
    full = RawIngest("ts", "/x",
        symbols=[_sym("foo", "a.ts", 1, 3), _sym("bar", "b.ts", 1, 3),
                 _sym("helper", "b.ts", 4, 5), _sym("baz", "c.ts", 1, 3)],
        references=[_ref("a.ts", 2, "b.ts", 1), _ref("c.ts", 2, "b.ts", 1), _ref("b.ts", 2, "b.ts", 4),
                    _ref("a.ts", 1, "b.ts", 1, "imports"), _ref("c.ts", 1, "b.ts", 1, "imports")],
        files=["a.ts", "b.ts", "c.ts"])

    # INCREMENTAL: changed={b.ts}; b imports nothing, so requery={b.ts}. Re-ingesting
    # the b region yields b's fresh symbols and all references TO b.
    spliced = splice(old, changed_files={"b.ts"}, removed_files=set(), requery_files={"b.ts"},
                     fresh_symbols=[_sym("bar", "b.ts", 1, 3), _sym("helper", "b.ts", 4, 5)],
                     fresh_refs=[_ref("a.ts", 2, "b.ts", 1), _ref("c.ts", 2, "b.ts", 1),
                                 _ref("b.ts", 2, "b.ts", 4)],
                     files=["a.ts", "b.ts", "c.ts"])

    assert _sig(build(spliced)) == _sig(build(full))


def test_splice_equals_full_reingest_on_symbol_deletion():
    # OLD: a#foo calls b#bar
    old = RawIngest("ts", "/x",
        symbols=[_sym("foo", "a.ts", 1, 3), _sym("bar", "b.ts", 1, 2)],
        references=[_ref("a.ts", 2, "b.ts", 1), _ref("a.ts", 1, "b.ts", 1, "imports")],
        files=["a.ts", "b.ts"])
    # NEW: b.ts emptied (bar deleted) — a still imports b but bar is gone
    full = RawIngest("ts", "/x",
        symbols=[_sym("foo", "a.ts", 1, 3)],
        references=[_ref("a.ts", 1, "b.ts", 1, "imports")],
        files=["a.ts", "b.ts"])
    spliced = splice(old, changed_files={"b.ts"}, removed_files=set(), requery_files={"b.ts"},
                     fresh_symbols=[], fresh_refs=[], files=["a.ts", "b.ts"])
    assert _sig(build(spliced)) == _sig(build(full))


def test_splice_drops_old_target_when_changed_caller_moves_from_b_to_c():
    old = RawIngest("ts", "/x", symbols=[
        _sym("caller", "a.ts", 1, 3), _sym("b", "b.ts", 1, 2),
        _sym("c", "c.ts", 1, 2),
    ], references=[
        _ref("a.ts", 1, "b.ts", 1, "imports"),
        _ref("a.ts", 2, "b.ts", 1),
    ], files=["a.ts", "b.ts", "c.ts"])
    full = RawIngest("ts", "/x", symbols=[
        _sym("caller", "a.ts", 1, 3), _sym("b", "b.ts", 1, 2),
        _sym("c", "c.ts", 1, 2),
    ], references=[
        _ref("a.ts", 1, "c.ts", 1, "imports"),
        _ref("a.ts", 2, "c.ts", 1),
    ], files=["a.ts", "b.ts", "c.ts"])

    spliced = splice(
        old, changed_files={"a.ts"}, removed_files=set(),
        requery_files={"a.ts", "c.ts"},
        fresh_symbols=[_sym("caller", "a.ts", 1, 3)],
        fresh_refs=[_ref("a.ts", 1, "c.ts", 1, "imports"),
                    _ref("a.ts", 2, "c.ts", 1)],
        files=["a.ts", "b.ts", "c.ts"],
    )

    assert _sig(build(spliced)) == _sig(build(full))


@pytest.mark.integration
def test_incremental_ingest_matches_full_reingest_on_real_change(tmp_path):
    (tmp_path / "package.json").write_text('{"main":"dist/main.js"}\n')
    (tmp_path / "util.ts").write_text("export function helper(x: number): number {\n  return x + 1;\n}\n")
    (tmp_path / "main.ts").write_text(
        'import { helper } from "./util";\n'
        "export function run(): number {\n  return helper(1);\n}\n")
    raw_old = ingest(tmp_path, "typescript")

    # change main.ts: run() now calls a new local extra(), passed into helper
    (tmp_path / "main.ts").write_text(
        'import { helper } from "./util";\n'
        "export function run(): number {\n  return helper(extra());\n}\n"
        "function extra(): number {\n  return 2;\n}\n")
    raw_full = ingest(tmp_path, "typescript")
    raw_inc = incremental_ingest(raw_old, tmp_path, ["main.ts"], [], "typescript")

    assert raw_inc is not None
    assert raw_inc.entry_files == raw_full.entry_files == {"main.ts"}
    assert _sig(build(raw_inc)) == _sig(build(raw_full))   # incremental == full, no drift


@pytest.mark.integration
def test_incremental_import_move_does_not_query_removed_old_target(tmp_path):
    (tmp_path / "a.ts").write_text(
        'import { target } from "./b";\n'
        "export function caller(): number { return target(); }\n"
    )
    (tmp_path / "b.ts").write_text(
        "export function target(): number { return 1; }\n"
    )
    raw_old = ingest(tmp_path, "typescript")

    (tmp_path / "a.ts").write_text(
        'import { target } from "./c";\n'
        "export function caller(): number { return target(); }\n"
    )
    (tmp_path / "c.ts").write_text(
        "export function target(): number { return 2; }\n"
    )
    (tmp_path / "b.ts").unlink()

    raw_inc = incremental_ingest(
        raw_old, tmp_path, ["a.ts", "c.ts"], ["b.ts"], "typescript")
    raw_full = ingest(tmp_path, "typescript")

    assert raw_inc is not None
    assert not raw_inc.diagnostics
    assert _sig(build(raw_inc)) == _sig(build(raw_full))


def test_incremental_javascript_settles_after_each_open(tmp_path, monkeypatch):
    """Mirror full ingest's Python 3.13/multilspy buffer-resize guard."""
    import shutil
    import multilspy
    from lattice import incremental
    from lattice.ingest import lsp_client

    (tmp_path / "a.js").write_text("export const a = 1;\n")
    (tmp_path / "b.js").write_text("export const b = 2;\n")
    opened = []
    sleeps = []

    class FakeLSP:
        @contextmanager
        def open_file(self, rel):
            opened.append(rel)
            yield

    fake = FakeLSP()
    monkeypatch.setattr(multilspy.SyncLanguageServer, "create", lambda *a, **k: fake)
    monkeypatch.setattr(lsp_client, "_quote_lsp_launch_command", lambda _lsp: None)
    monkeypatch.setattr(lsp_client, "_started_server", lambda _lsp: nullcontext(fake))
    monkeypatch.setattr(lsp_client, "_append_dynamic_dispatch_refs",
                        lambda *a, **k: None)
    monkeypatch.setattr(lsp_client, "_JS_OPEN_SETTLE", 0.123)
    monkeypatch.setattr(lsp_client, "_REFERENCE_SETTLE", 0.456)
    monkeypatch.setattr(incremental.time, "sleep", sleeps.append)
    monkeypatch.setattr(shutil, "which", lambda _binary: "/fake/server")

    raw = incremental_ingest(
        RawIngest("javascript", str(tmp_path), files=["a.js", "b.js"]),
        tmp_path, [], [], "javascript",
    )

    assert raw is not None
    assert opened == ["a.js", "b.js"]
    assert sleeps == [0.123, 0.123, 0.456]


@pytest.mark.integration
def test_incremental_ingest_quotes_a_fresh_language_server(tmp_path):
    """Incremental-first callers must work without a full ingest priming multilspy."""
    (tmp_path / "main.ts").write_text(
        "export function run(): number { return 1; }\nrun();\n"
    )
    source_root = pathlib.Path(__file__).resolve().parents[1] / "src"
    script = """
import pathlib
import sys

from lattice.incremental import incremental_ingest
from lattice.ingest.types import RawIngest

root = pathlib.Path(sys.argv[1])
old = RawIngest(language="typescript", root=str(root), files=["main.ts"])
raw = incremental_ingest(old, root, ["main.ts"], [], "typescript")
assert raw is not None
assert "run" in {symbol.name for symbol in raw.symbols}
assert not raw.diagnostics
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(source_root), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    env["LATTICE_LSP_TIMEOUT"] = "5"
    env["LATTICE_LSP_SETTLE"] = "0.05"
    env["LATTICE_LSP_JS_OPEN_SETTLE"] = "0.01"
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        env=env, text=True, capture_output=True, timeout=15,
    )
    assert completed.returncode == 0, completed.stderr


def test_splice_preserves_entry_files_and_diagnostics():
    warning = {"kind": "partial", "severity": "warning", "file": "a.ts",
               "line": 1, "message": "kept"}
    old = RawIngest("ts", "/x", symbols=[_sym("main", "a.ts", 1, 2)],
                    diagnostics=[warning], files=["a.ts"], entry_files={"a.ts"})
    fresh = splice(old, changed_files=set(), removed_files=set(), requery_files=set(),
                   fresh_symbols=[], fresh_refs=[], files=["a.ts"])
    assert fresh.entry_files == {"a.ts"}
    assert fresh.diagnostics == [warning]


def test_splice_replaces_projectwide_babel_recovery_diagnostics():
    old_error = {"kind": "parse_error", "severity": "error", "file": "old.ts",
                 "line": 1, "message": "old", "parser": "babel"}
    fresh_error = {"kind": "parse_error", "severity": "error", "file": "old.ts",
                   "line": 1, "message": "fresh", "parser": "babel"}
    old = RawIngest("ts", "/x", diagnostics=[old_error], files=["old.ts"])
    result = splice(
        old, changed_files={"changed.ts"}, removed_files=set(),
        requery_files={"changed.ts"}, fresh_symbols=[], fresh_refs=[],
        files=["old.ts", "changed.ts"], fresh_diagnostics=[fresh_error],
    )
    assert result.diagnostics == [fresh_error]


def test_splice_preserves_unrerun_schema_errors_and_clears_lifecycle_errors():
    schema_error = {"kind": "lsp_schema_error", "severity": "error",
                    "file": "target.ts", "line": 1, "message": "bad schema"}
    reference_error = {"kind": "reference_error", "severity": "error",
                       "file": "target.ts", "line": 1, "message": "old ref"}
    lifecycle_error = {"kind": "lsp_process_error", "severity": "error",
                       "file": "<project>", "line": 1, "message": "old process"}
    old = RawIngest(
        "ts", "/x", diagnostics=[schema_error, reference_error, lifecycle_error],
        files=["changed.ts", "target.ts"],
    )

    result = splice(
        old, changed_files={"changed.ts"}, removed_files=set(),
        requery_files={"changed.ts", "target.ts"}, fresh_symbols=[], fresh_refs=[],
        files=["changed.ts", "target.ts"], fresh_diagnostics=[],
    )

    assert result.diagnostics == [schema_error]


def test_raw_roundtrips_through_json():
    import json
    from lattice.incremental import raw_to_dict, raw_from_dict
    raw = RawIngest("ts", "/x",
        symbols=[_sym("foo", "a.ts", 1, 3)],
        references=[_ref("a.ts", 2, "b.ts", 1), _ref("a.ts", 1, "b.ts", 1, "imports")],
        files=["a.ts", "b.ts"])
    back = raw_from_dict(json.loads(json.dumps(raw_to_dict(raw))))
    assert _sig(build(back)) == _sig(build(raw))
