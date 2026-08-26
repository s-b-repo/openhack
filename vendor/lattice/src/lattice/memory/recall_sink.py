from __future__ import annotations
import importlib.util
import json, os, pathlib, subprocess, tempfile
from lattice.graph.models import Hypernetwork
from lattice.complete.report import HypernetworkReport

# recall_helper ships with the recall skill, not with lattice — resolve it lazily so
# `import lattice.memory.recall_sink` (and therefore the whole CLI) works on machines
# without it. Only persist() actually needs the helper.
_DEFAULT_RECALL_SCRIPTS = "/Users/hendrixx./.claude/skills/recall/scripts"


def _load_build_proposal():
    scripts = os.environ.get("LATTICE_RECALL_SCRIPTS", _DEFAULT_RECALL_SCRIPTS)
    helper = pathlib.Path(scripts) / "recall_helper.py"
    if not helper.is_file():
        raise RuntimeError(
            f"recall persistence needs recall_helper.py; nothing at {helper} — "
            "set LATTICE_RECALL_SCRIPTS to the directory that contains it")
    spec = importlib.util.spec_from_file_location("recall_helper", helper)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_proposal

_LANG_PREFIX = {"typescript": "ts", "javascript": "js", "python": "py"}

_EDGE_KIND = {
    "imports": "code-imports",
    "calls": "code-references",
    "references": "code-references",
    "inherits": "code-inherits",
    "implements": "code-implements",
    "defines": "code-defined-in",
    "returns": "code-references",
}


def _admit(proposal: dict, db_path: str) -> str:
    """Admit a cell to recall and return the persisted cell UUID."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(proposal, f)
        path = f.name
    try:
        r = subprocess.run(
            ["recall", "--db", db_path, "admit", "--json", path],
            capture_output=True, text=True,
        )
    finally:
        os.unlink(path)
    if r.returncode != 0:
        raise RuntimeError(f"recall admit failed: {r.stderr.strip()}")
    result = json.loads(r.stdout)
    if not result.get("accepted"):
        raise RuntimeError(f"recall admit not accepted: {r.stdout.strip()}")
    # recall v0.12+ returns `cell.key`; older releases returned `node.id`. Accept both
    # so a downgrade doesn't silently break — key is the canonical identifier now.
    cell = result.get("cell") or result.get("node") or {}
    return cell.get("key") or cell["id"]


def _add_hyperedge(edge_json: dict, db_path: str) -> None:
    """Write a hyperedge to recall."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(edge_json, f)
        path = f.name
    try:
        r = subprocess.run(
            ["recall", "--db", db_path, "hyperedge", "add", "--json", path],
            capture_output=True, text=True,
        )
    finally:
        os.unlink(path)
    if r.returncode != 0:
        raise RuntimeError(f"recall hyperedge add failed: {r.stderr.strip()}")


def persist(
    net: Hypernetwork,
    report: HypernetworkReport,
    db_path: str,
    project: str = "lattice",
) -> None:
    build_proposal = _load_build_proposal()
    prefix = _LANG_PREFIX.get(net.language, net.language[:2])

    # Step 1: admit all non-external vertices, build lattice id → recall cell uuid map
    cell_by_vertex: dict[str, str] = {}
    for v in net.vertices:
        if v.kind == "external":
            continue
        entities = [f"{prefix}-sym:{v.name}"]
        body = (
            f"# {v.kind}: {v.name}\n\n"
            f"**File:** `{v.file}` (lines {v.start_line}-{v.end_line})\n"
            f"**Type:** {v.type or 'n/a'}\n"
            f"**Exported:** {v.exported}  **Stub:** {v.stub}\n"
        )
        prop = build_proposal(
            kind="obj",                                    # recall v0.12+ kind: object/artifact
            title=f"{v.kind}: {v.file}::{v.name}",
            body=body,
            confidence=0.9,
            topics=["code", net.language, v.kind],
            project=project,
            entities=entities,
        )
        cell_uuid = _admit(prop, db_path)
        cell_by_vertex[v.id] = cell_uuid

    # Step 2: admit the report cell
    rep_body = (
        f"# Completeness report ({report.verdict})\n\n"
        f"resolution={report.resolution:.3f}; "
        f"unresolved_imports={len(report.unresolved_imports)}; "
        f"dangling={len(report.dangling_edges)}; stubs={len(report.stubs)}\n"
    )
    rep_prop = build_proposal(
        kind="obs",                                        # recall v0.12+ kind: observation
        title=f"completeness: {net.root} [{report.verdict}]",
        body=rep_body,
        confidence=0.95,
        topics=["code", "completeness", net.language],
        project=project,
    )
    _admit(rep_prop, db_path)

    # Step 3: persist hyperedges for all edges whose endpoints were both admitted
    for e in net.hyperedges:
        src_id = e.members[0] if e.members else None
        tgt_id = e.members[-1] if len(e.members) > 1 else None
        if src_id is None or tgt_id is None:
            continue
        if src_id not in cell_by_vertex or tgt_id not in cell_by_vertex:
            continue
        recall_kind = _EDGE_KIND.get(e.kind, "code-references")
        edge_json = {
            "kind": recall_kind,
            "title": f"{e.kind}: {src_id} -> {tgt_id}",
            "members": [
                # recall v0.12+ hyperedge member key is `key` (cell key); pre-v0.12 used
                # `nodeId`. We standardize on the current name — a downgrade would need to
                # rewrite this field anyway.
                {"key": cell_by_vertex[src_id], "role": "source", "ordinal": 0},
                {"key": cell_by_vertex[tgt_id], "role": "target", "ordinal": 1},
            ],
            "metadata": {"created_by": "lattice", "resolved": e.resolved},
        }
        _add_hyperedge(edge_json, db_path)
