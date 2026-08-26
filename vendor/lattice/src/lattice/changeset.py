# src/lattice/changeset.py
"""Per-file content-hash change detection — the safe foundation for fast updates.

A manifest maps each source file to a content hash. Comparing two manifests tells you
exactly which files were added / modified / removed. The sidecar stores the manifest
so an update is an instant no-op when nothing changed, and re-analysis runs only on
real change. This is *always correct* (it's just hashing), and it's step one of any
incremental ingest: you can't update only what changed until you know what changed.
"""
from __future__ import annotations
import hashlib
import pathlib

_EXTS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".sol", ".go",
    ".rs", ".rb", ".c", ".cpp", ".cc", ".cxx", ".c++", ".h", ".hpp",
    ".hh", ".hxx", ".cu", ".cuh", ".sh", ".bash", ".sql",
}
# This manifest is language-independent and must be a superset of every frontend's
# selected source set. Only skip directories rejected by all frontends; for example,
# SQL and IaC may intentionally live under vendor/build/target even though native or
# LSP frontends exclude those directories.
_SKIP_PARTS = {"node_modules", ".git"}
_GRAPH_METADATA_NAMES = {
    "package.json", "go.mod", "go.work", "Cargo.toml", "Gemfile", "pyproject.toml",
    "setup.cfg", "setup.py", "compile_commands.json", "CMakeLists.txt",
}


def is_graph_metadata(path: pathlib.Path) -> bool:
    """Configuration whose edits can alter source discovery, resolution, or surfaces."""
    name = path.name
    return (name in _GRAPH_METADATA_NAMES
            or (name.startswith("tsconfig") and name.endswith(".json"))
            or (name.startswith("jsconfig") and name.endswith(".json")))


def graph_metadata_files(root: pathlib.Path):
    """Yield graph-affecting metadata below ``root``, excluding dependency/build trees."""
    root = pathlib.Path(root)
    for p in root.rglob("*"):
        if not p.is_file() or (_SKIP_PARTS & set(p.relative_to(root).parts)):
            continue
        if is_graph_metadata(p):
            yield p


def file_manifest(root, exts=_EXTS) -> dict[str, str]:
    """Map of relative path -> content hash for every source file under root."""
    root = pathlib.Path(root)
    out: dict[str, str] = {}
    metadata = set(graph_metadata_files(root))
    for p in sorted(root.rglob("*")):
        if not p.is_file() or (_SKIP_PARTS & set(p.relative_to(root).parts)):
            continue
        is_dockerfile = (p.name.lower() == "dockerfile"
                         or p.name.lower().startswith("dockerfile.")
                         or p.name.lower().endswith(".dockerfile"))
        if p.suffix not in exts and p not in metadata and not is_dockerfile:
            continue
        try:
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            continue
    return out


def changed_files(old: dict[str, str], new: dict[str, str]) -> dict:
    """Diff two manifests into added / modified / removed."""
    old_keys, new_keys = set(old), set(new)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    modified = sorted(k for k in old_keys & new_keys if old[k] != new[k])
    return {
        "added": added,
        "modified": modified,
        "removed": removed,
        "any": bool(added or modified or removed),
    }
