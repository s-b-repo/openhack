# tests/test_review_fixes.py
"""Regression gate for the 2026-06 structural review.

Each test pins a defect found in review; the fix is only real once these pass
WITHOUT regressing the rest of the suite.
"""
import shutil
import sys

import pytest

from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.graph.query import GraphView
from lattice.ingest.types import RawIngest, RawSymbol, RawReference
from lattice.incremental import raw_to_dict, raw_from_dict


def _sym(name, file, start, end):
    return RawSymbol(name=name, kind="function", file=file, start_line=start, end_line=end)


# ---- incremental: serialization round-trip must not lose graph-shaping state ----

def test_raw_roundtrip_preserves_entry_files():
    raw = RawIngest("typescript", "/x", symbols=[_sym("foo", "a.ts", 1, 3)],
                    references=[], files=["a.ts"], entry_files={"a.ts"})
    back = raw_from_dict(raw_to_dict(raw))
    assert back.entry_files == {"a.ts"}


def test_raw_from_dict_tolerates_unknown_future_keys():
    d = raw_to_dict(RawIngest("typescript", "/x",
                              symbols=[_sym("foo", "a.ts", 1, 3)],
                              references=[RawReference(kind="references", from_file="a.ts",
                                                       from_line=2, to_file="b.ts", to_line=1)],
                              files=["a.ts"]))
    d["symbols"][0]["future_field"] = 1
    d["references"][0]["future_field"] = 2
    back = raw_from_dict(d)
    assert back.symbols[0].name == "foo"
    assert back.references[0].to_file == "b.ts"


# ---- incremental: file discovery must match the full ingest (tsx + build dirs) ----

def test_incremental_project_files_include_tsx_and_skip_build_dirs(tmp_path):
    from lattice.incremental import _project_files
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.tsx").write_text("export const A = 1;\n")
    (tmp_path / "src" / "lib.ts").write_text("export const B = 2;\n")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "x.ts").write_text("export const C = 3;\n")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "app.ts").write_text("export const D = 4;\n")
    files = _project_files(tmp_path)
    assert "src/app.tsx" in files, files
    assert "src/lib.ts" in files, files
    assert not any("node_modules" in f for f in files), files
    assert not any(f.startswith("dist/") for f in files), files


# ---- query: SCC detection must survive deep graphs (iterative, not recursive) ----

def test_find_cycles_survives_deep_chains():
    n = 1500          # > CPython's default recursion limit
    vs = [Vertex(id=f"ts-sym:a.ts#n{i}", kind="function", name=f"n{i}", file="a.ts",
                 start_line=1, end_line=2) for i in range(n)]
    es = [Hyperedge(id=f"c{i}", kind="calls",
                    members=[f"ts-sym:a.ts#n{i}", f"ts-sym:a.ts#n{i+1}"], resolved=True)
          for i in range(n - 1)]
    g = GraphView(Hypernetwork(language="typescript", root="/x", vertices=vs, hyperedges=es))
    assert g.find_cycles() == []


# ---- taint audits: never descend into vendored / virtualenv / build trees ----
# NOTE: the os.system / system() snippets below are STRING FIXTURES written to tmp
# files as *input for the taint auditor* (the sentinel must be a real injection
# idiom so the auditor would fire on it). They are never executed.

def test_python_taint_audit_skips_virtualenv(tmp_path):
    from lattice.ingest.python_taint import python_taint_audit
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n")
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "evil.py").write_text(
        "import os\n"
        "def venv_only_sentinel(request):\n"
        "    cmd = request.args['host']\n"
        "    os.system('ping ' + cmd)\n")
    findings = python_taint_audit(tmp_path)
    assert "venv_only_sentinel" not in {f.get("function") for f in findings}, findings


def test_ruby_taint_audit_skips_vendor(tmp_path):
    from lattice.ingest.ruby_taint import ruby_taint_audit, _BRIDGE
    if not (_BRIDGE.exists() and shutil.which("ruby")):
        pytest.skip("ruby not available")
    (tmp_path / "app.rb").write_text("def ok\n  1\nend\n")
    vend = tmp_path / "vendor" / "bundle"
    vend.mkdir(parents=True)
    (vend / "evil.rb").write_text(
        "def vendor_only_sentinel\n  host = params[:host]\n  system(\"ping #{host}\")\nend\n")
    findings = ruby_taint_audit(tmp_path)
    assert "vendor_only_sentinel" not in {f.get("function") for f in findings}, findings


def test_c_taint_audit_skips_build_dir(tmp_path):
    from lattice.ingest.c_taint import c_taint_audit
    if not shutil.which("clang"):
        pytest.skip("clang not available")
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n")
    build = tmp_path / "build"
    build.mkdir()
    (build / "gen.c").write_text(
        "#include <stdlib.h>\n#include <stdio.h>\n"
        "void build_only_sentinel(void) {\n"
        "    char *host = getenv(\"HOST\");\n"
        "    char cmd[256];\n"
        "    sprintf(cmd, \"ping %s\", host);\n"
        "    system(cmd);\n"
        "}\n")
    findings = c_taint_audit(tmp_path)
    assert "build_only_sentinel" not in {f.get("function") for f in findings}, findings


# ---- single-file audits: a non-UTF-8 source file must not crash the audit ----

_LATIN1_PY = b"# caf\xe9 comment\nimport threading\n\ndef ok():\n    return 1\n"


def test_lock_audit_survives_non_utf8(tmp_path):
    from lattice.ingest.python_locks import lock_order_audit
    p = tmp_path / "legacy.py"
    p.write_bytes(_LATIN1_PY)
    assert isinstance(lock_order_audit(p), list)


def test_resource_audit_survives_non_utf8(tmp_path):
    from lattice.ingest.python_resource import resource_audit
    p = tmp_path / "legacy.py"
    p.write_bytes(_LATIN1_PY)
    assert isinstance(resource_audit(p), list)


def test_union_audit_survives_non_utf8(tmp_path):
    from lattice.ingest.c_unions import union_audit
    p = tmp_path / "legacy.c"
    p.write_bytes(b"/* caf\xe9 */\nstruct S { int a; };\n")
    assert isinstance(union_audit(p), list)


# ---- solver bridge: remote command must shell-quote the configured root ----

def test_remote_command_quotes_solver_root(monkeypatch):
    import shlex
    import lattice.solver_bridge as sb
    evil = "/tmp/x; rm -rf $HOME"
    monkeypatch.setenv("FOOTINGS_SOLVER_ROOT", evil)
    assert shlex.quote(evil) in sb._remote_cmd()


# ---- recall sink: importable everywhere, helper resolved lazily + overridably ----

def test_recall_sink_loader_honors_env_and_fails_actionably(monkeypatch, tmp_path):
    import lattice.memory.recall_sink as rs
    monkeypatch.setenv("LATTICE_RECALL_SCRIPTS", str(tmp_path))   # empty: no helper here
    monkeypatch.delitem(sys.modules, "recall_helper", raising=False)
    with pytest.raises(RuntimeError, match="LATTICE_RECALL_SCRIPTS"):
        rs._load_build_proposal()
