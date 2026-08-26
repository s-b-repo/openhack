# src/lattice/complete/verify.py
"""Git-based differential verification — the entry point an agent calls to ask
'did the change I just made break the structure?'

Baseline ('before') = the codebase at a git ref (default HEAD), extracted into a
detached worktree so the working tree is never touched. 'after' = the current
working tree. Both are ingested, built, and compared via complete.diff.
"""
from __future__ import annotations
import contextlib
import subprocess
import tempfile
from pathlib import Path

from lattice.cache import build_source, ingest_source, normalize_language
from lattice.graph.builder import build
from lattice.complete.diff import diff, DiffReport


@contextlib.contextmanager
def _detached_worktree(repo: Path, ref: str):
    """Materialize `ref` in a throwaway detached worktree; always clean up."""
    repo = Path(repo).resolve()
    tmp = Path(tempfile.mkdtemp(prefix="lattice-base-"))
    # `git worktree add` wants the target dir to not pre-exist.
    target = tmp / "tree"
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach",
                    str(target), ref], check=True, capture_output=True, text=True)
    try:
        yield target
    finally:
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force",
                        str(target)], check=False, capture_output=True, text=True)
        with contextlib.suppress(Exception):
            target.rmdir()
        with contextlib.suppress(Exception):
            tmp.rmdir()


def verify_against_ref(path, ref: str = "HEAD", language: str = "typescript",
                       *, _ingest=None) -> DiffReport:
    """Compare a checkout against ``ref`` through the canonical language dispatcher.

    ``_ingest`` remains an injectable test seam, but production calls no longer route
    Go/Rust/Ruby/C/etc. into the TypeScript LSP frontend.
    """
    scope = Path(path).resolve()
    git_cwd = scope if scope.is_dir() else scope.parent
    repo = Path(subprocess.run(
        ["git", "-C", str(git_cwd), "rev-parse", "--show-toplevel"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()).resolve()
    relative_scope = scope.relative_to(repo)
    def build_graph(root: Path):
        # Preserve the RawIngest injection seam for tests/custom frontends. Production
        # auto dispatch is graph-level because it merges several concrete frontends.
        if _ingest is not None:
            return build(_ingest(root, language))
        canonical = normalize_language(language)
        if canonical in ("auto", "mixed"):
            return build_source(root, canonical)
        return build(ingest_source(root, canonical))

    after = build_graph(scope)
    with _detached_worktree(repo, ref) as base:
        before = build_graph(base / relative_scope)
    return diff(before, after)
