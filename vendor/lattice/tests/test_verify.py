# tests/test_verify.py
"""Tests the git-based differential verify flow WITHOUT an LSP: a fake ingest
parses a trivial line format so we exercise the real git-worktree plumbing,
builder, and diff end-to-end."""
import subprocess
from pathlib import Path

from lattice.ingest.types import RawIngest, RawSymbol, RawReference
from lattice.complete.verify import verify_against_ref


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def _fake_ingest(root: Path, language: str) -> RawIngest:
    """Parse every *.ts under root. Lines:
       'sym NAME'            -> exported function symbol NAME
       'import TARGET.ts'    -> resolved relative import to TARGET.ts
    """
    symbols, refs, files, diagnostics = [], [], [], []
    for ts in sorted(Path(root).rglob("*.ts")):
        rel = ts.relative_to(root).as_posix()
        files.append(rel)
        for i, line in enumerate(ts.read_text().splitlines(), start=1):
            line = line.strip()
            if line.startswith("sym "):
                symbols.append(RawSymbol(name=line[4:], kind="function", file=rel,
                                         start_line=i, end_line=i, exported=True))
            elif line.startswith("import "):
                tgt = line[7:]
                refs.append(RawReference(kind="imports", from_file=rel, from_line=i,
                                         to_file=tgt, to_line=None, resolved=True))
            elif line.startswith("error "):
                diagnostics.append({"severity": "error", "kind": "parse_error",
                                    "file": rel, "message": line[6:]})
    return RawIngest(language=language, root=str(root),
                     symbols=symbols, references=refs, diagnostics=diagnostics, files=files)


def _init_repo(tmp_path) -> Path:
    repo = tmp_path / "proj"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.t")
    _git(repo, "config", "user.name", "t")
    return repo


def test_clean_change_against_head(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "a.ts").write_text("sym foo\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    # working-tree change: add a new symbol — purely additive, no breakage
    (repo / "a.ts").write_text("sym foo\nsym bar\n")
    rep = verify_against_ref(repo, ref="HEAD", _ingest=_fake_ingest)
    assert rep.verdict == "clean"
    assert "ts-sym:a.ts#bar" in rep.added_vertices


def test_unchanged_subdirectory_compares_the_same_scope_at_baseline(tmp_path):
    repo = _init_repo(tmp_path)
    package = repo / "pkg"
    package.mkdir()
    (package / "a.ts").write_text("sym foo\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")

    report = verify_against_ref(package, ref="HEAD", _ingest=_fake_ingest)

    assert report.verdict == "clean"
    assert report.added_vertices == []
    assert report.removed_vertices == []
    assert report.removed_public_api == []


def test_deleting_public_api_against_head_is_regressed(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "a.ts").write_text("sym foo\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    # working-tree change: delete the exported symbol
    (repo / "a.ts").write_text("")
    rep = verify_against_ref(repo, ref="HEAD", _ingest=_fake_ingest)
    assert "ts-sym:a.ts#foo" in rep.removed_public_api
    assert rep.verdict == "regressed"


def test_cli_verify_exit_code_on_regression(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    (repo / "a.ts").write_text("sym foo\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    (repo / "a.ts").write_text("")  # delete public api -> regressed

    from lattice.cli import main as cli
    monkeypatch.setattr(
        cli, "verify_against_ref",
        lambda path, ref="HEAD", language="typescript": _verify_with_fake(path, ref))
    rc = cli.main(["verify", str(repo), "--against", "HEAD"])
    assert rc == 1  # regression -> non-zero so an agent/CI sees the failure


def test_cli_verify_clean_exits_zero(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    (repo / "a.ts").write_text("sym foo\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    (repo / "a.ts").write_text("sym foo\nsym bar\n")  # additive -> clean

    from lattice.cli import main as cli
    monkeypatch.setattr(
        cli, "verify_against_ref",
        lambda path, ref="HEAD", language="typescript": _verify_with_fake(path, ref))
    rc = cli.main(["verify", str(repo), "--against", "HEAD"])
    assert rc == 0


def test_cli_verify_surfaces_new_ingest_error(tmp_path, monkeypatch, capsys):
    repo = _init_repo(tmp_path)
    (repo / "a.ts").write_text("sym foo\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    (repo / "a.ts").write_text("sym foo\nerror unexpected token\n")

    from lattice.cli import main as cli
    monkeypatch.setattr(
        cli, "verify_against_ref",
        lambda path, ref="HEAD", language="typescript": _verify_with_fake(path, ref))
    rc = cli.main(["verify", str(repo), "--against", "HEAD"])
    captured = capsys.readouterr()

    assert rc == 1
    assert "new_error_diagnostics" in captured.err
    assert "unexpected token" in captured.err


def test_cli_verify_preexisting_ingest_error_is_unverifiable_not_regressed(
        tmp_path, monkeypatch, capsys):
    repo = _init_repo(tmp_path)
    (repo / "a.ts").write_text("sym foo\nerror persistent parser failure\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")

    from lattice.cli import main as cli
    monkeypatch.setattr(
        cli, "verify_against_ref",
        lambda path, ref="HEAD", language="typescript": _verify_with_fake(path, ref))
    rc = cli.main(["verify", str(repo), "--against", "HEAD"])
    captured = capsys.readouterr()

    assert rc == 2
    assert "UNVERIFIABLE" in captured.err
    assert "persistent parser failure" in captured.err
    assert "REGRESSED" not in captured.err


def _verify_with_fake(path, ref):
    return verify_against_ref(path, ref=ref, _ingest=_fake_ingest)


def test_worktree_is_cleaned_up(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "a.ts").write_text("sym foo\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    verify_against_ref(repo, ref="HEAD", _ingest=_fake_ingest)
    # no leftover worktrees registered
    out = subprocess.run(["git", "worktree", "list"], cwd=repo,
                         capture_output=True, text=True).stdout
    assert out.strip().count("\n") == 0  # only the main worktree


def test_verify_default_path_uses_native_dispatcher(tmp_path, monkeypatch):
    import lattice.complete.verify as verify_module

    repo = _init_repo(tmp_path)
    (repo / "main.go").write_text("package main\nfunc main() {}\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    calls = []

    def fake_dispatch(root, language):
        calls.append((Path(root).name, language))
        return RawIngest(language=language, root=str(root), files=["main.go"])

    monkeypatch.setattr(verify_module, "ingest_source", fake_dispatch)
    assert verify_module.verify_against_ref(repo, language="go").verdict == "clean"
    assert len(calls) == 2 and {language for _, language in calls} == {"go"}


def test_verify_auto_compares_graph_level_mixed_networks(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "run.sh").write_text("#!/bin/sh\nlaunch() { echo old; }\n")
    (repo / "schema.sql").write_text("CREATE TABLE users (id integer);\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "mixed baseline")

    (repo / "run.sh").write_text("#!/bin/sh\ndeploy() { echo new; }\n")
    (repo / "schema.sql").write_text(
        "CREATE TABLE users (id integer);\nCREATE TABLE orders (id integer);\n")
    report = verify_against_ref(repo, language="auto")

    assert any(vertex.endswith("#deploy") for vertex in report.added_vertices)
    assert any(vertex.endswith("#orders") for vertex in report.added_vertices)
    assert any(vertex.endswith("#launch") for vertex in report.removed_vertices)
