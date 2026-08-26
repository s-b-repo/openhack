# src/lattice/sidecar.py
"""The living sidecar — a self-maintaining, referenceable reflection of a codebase.

`digest(net)` is the reflection: a structured snapshot of what's there and its health
(endpoint A — where you are). `changes(prev, net)` is the evolving part: what moved
since the last snapshot, via the differential gate. `render()` turns them into a
human/agent-readable `INVENTORY.md`.

It reflects; it does not drive. An agent or human reads it to orient, then uses
plan/optimize/impact to define the target (endpoint B) and decide the in-between.
"""
from __future__ import annotations
import json
import pathlib

from lattice.graph.models import Hypernetwork
from lattice.complete.gate import check
from lattice.complete.diff import diff
from lattice.diagnose import diagnose
from lattice.hunt import hunt


def digest(net: Hypernetwork) -> dict:
    """Endpoint A — an honest snapshot of current structure + health."""
    report = check(net)
    d = diagnose(net)
    bugs = hunt(net)
    # dead_code from hunt (precise: no callers), NOT diagnose (noisy reachability-from-
    # public-API) — an honest mirror shows one number, the trustworthy one.
    dead = sum(1 for b in bugs if b.kind == "dead_code")
    real = [v for v in net.vertices if v.kind not in ("external", "module")]
    by_kind: dict = {}
    for v in net.vertices:
        by_kind[v.kind] = by_kind.get(v.kind, 0) + 1
    return {
        "files": len({v.file for v in real}),
        "vertices": len(net.vertices),
        "edges": len(net.hyperedges),
        "by_kind": by_kind,
        "public_api": sum(1 for v in net.vertices
                          if v.exported and v.kind in ("function", "method")),
        "coverage": report.coverage,
        "health": {
            # Public health is the completeness gate, not diagnose's independent
            # structural-obstruction summary. Parser/LSP errors must never appear clean.
            "verdict": report.verdict,
            "failing_checks": list(report.failing_checks),
            "diagnostics": list(report.diagnostics),
            "structural_verdict": d.summary["verdict"],
            "cycles": d.summary["cycles"],
            "dead_code": dead,
            "stubs": d.summary["stubs"],
            "obstructions": d.summary["obstructions"],
        },
        "bugs": {
            "total": len(bugs),
            "by_severity": {s: sum(1 for b in bugs if b.severity == s)
                            for s in ("critical", "high", "medium", "low")},
        },
        "top_bugs": [{"kind": b.kind, "severity": b.severity, "symbol": b.symbol}
                     for b in bugs[:10]],
    }


def changes(prev: Hypernetwork, net: Hypernetwork) -> dict:
    """The evolving part — what moved since the previous snapshot (the differential)."""
    d = diff(prev, net)
    return {
        "added_vertices": len(d.added_vertices),
        "removed_vertices": len(d.removed_vertices),
        "new_unresolved_imports": d.new_unresolved_imports,
        "new_dangling_edges": d.new_dangling_edges,
        "error_diagnostics": d.error_diagnostics,
        "new_error_diagnostics": d.new_error_diagnostics,
        "broken_by_removal": d.broken_by_removal,
        "removed_public_api": d.removed_public_api,
        "verdict": d.verdict,           # clean | regressed | unverifiable
    }


def render(dg: dict, ch: dict | None) -> str:
    cov = dg["coverage"]
    h = dg["health"]
    bs = dg["bugs"]["by_severity"]
    lines = [
        "# Footings Sidecar",
        "",
        "_An honest reflection of the codebase. It shows what is; you decide what's next._",
        "",
        "## Where you are (endpoint A)",
        f"- files: {dg['files']}  ·  vertices: {dg['vertices']}  ·  edges: {dg['edges']}",
        f"- public API: {dg['public_api']} exported functions/methods",
        f"- coverage: {cov.get('ratio', 1.0):.2f} "
        f"({cov.get('functions_with_inbound_refs', 0)}/{cov.get('functions_total', 0)} fns referenced) "
        f"— recall indicator, not a completeness guarantee",
        "",
        "## Health",
        f"- verdict: **{h['verdict']}**  ·  cycles: {h['cycles']}  ·  obstructions: {h['obstructions']}  "
        f"·  stubs: {h['stubs']}  ·  dead code: {h['dead_code']}",
        f"- structural verdict: **{h.get('structural_verdict', h['verdict'])}**",
        f"- bugs: {dg['bugs']['total']} "
        f"(critical {bs['critical']} · high {bs['high']} · medium {bs['medium']} · low {bs['low']})",
    ]
    if h.get("failing_checks"):
        lines.append(f"- failing checks: {', '.join(h['failing_checks'])}")
    if h.get("diagnostics"):
        lines += ["", "### Ingest diagnostics"]
        for item in h["diagnostics"]:
            severity = item.get("severity", "error")
            where = f"{item.get('file', '<project>')}:{item.get('line', 1)}"
            kind = item.get("kind", "ingest")
            lines.append(f"- [{severity}] {where} {kind}: {item.get('message', '')}")
    if dg["top_bugs"]:
        lines.append("")
        lines.append("### Top findings")
        for b in dg["top_bugs"]:
            lines.append(f"- [{b['severity']}] {b['kind']}: `{b['symbol']}`")
    if ch:
        lines += [
            "",
            "## What changed since last (evolution)",
            f"- verdict: **{ch['verdict']}**  ·  +{ch['added_vertices']} / -{ch['removed_vertices']} symbols",
        ]
        if ch["new_unresolved_imports"]:
            lines.append(f"- ⚠ new broken imports: {ch['new_unresolved_imports']}")
        if ch["new_error_diagnostics"]:
            lines.append(f"- ⚠ new ingest errors: {ch['new_error_diagnostics']}")
        elif ch["error_diagnostics"]:
            lines.append(f"- ⚠ verification blocked by existing ingest errors: "
                         f"{ch['error_diagnostics']}")
        if ch["broken_by_removal"]:
            lines.append(f"- ⚠ deletions broke references: {ch['broken_by_removal']}")
        if ch["removed_public_api"]:
            lines.append(f"- ⚠ removed public API: {ch['removed_public_api']}")
    return "\n".join(lines) + "\n"


def update(src, out, language: str = "typescript", force: bool = False) -> dict:
    """One self-maintaining update: detect changes, (incrementally) re-ingest, refresh
    the sidecar artifacts. Returns a summary incl. whether anything was rebuilt. This is
    the unit a watch loop / commit hook repeats — instant no-op when nothing changed."""
    from lattice.changeset import file_manifest, changed_files
    from lattice.incremental import incremental_ingest, raw_to_dict, raw_from_dict
    from lattice.cache import ingest_source, normalize_language
    from lattice.graph.builder import build as _build

    src = pathlib.Path(src)
    out = pathlib.Path(out)
    language = normalize_language(language)
    out.mkdir(parents=True, exist_ok=True)
    cache, rawp = out / "graph.json", out / "raw.json"
    manifest_path, state_path = out / "manifest.json", out / "state.json"

    # The source manifest is language-independent, so it cannot by itself validate a
    # cached graph. Persist the canonical requested frontend separately and treat old,
    # missing, or mismatched state as a compulsory full rebuild.
    cached_language = None
    if state_path.exists():
        try:
            cached_language = normalize_language(
                json.loads(state_path.read_text()).get("language", ""))
        except (OSError, ValueError, TypeError, AttributeError):
            cached_language = None
    language_matches = cached_language == language

    cur_manifest = file_manifest(src)
    cf = None
    if manifest_path.exists():
        try:
            cf = changed_files(json.loads(manifest_path.read_text()), cur_manifest)
        except Exception:
            cf = None
        if cf is not None and not cf["any"] and not force and language_matches:
            # A matching manifest alone is insufficient: the sidecar's public no-op
            # result still needs the cached graph's complete health. Missing/corrupt
            # graph artifacts fall through to a full rebuild.
            if cache.exists():
                try:
                    current = Hypernetwork.from_dict(json.loads(cache.read_text()))
                    current_digest = digest(current)
                    if current_digest["health"]["verdict"] != "fail":
                        return {
                            "updated": False, "mode": "noop", "digest": current_digest,
                            "changes": None, "changed_files": [],
                        }
                    # A failed cached graph may reflect a transient frontend/runtime
                    # outage rather than source drift. Retrying unchanged source is the
                    # recovery path for watch; treating it as a no-op wedges the failure
                    # forever until an unrelated file edit occurs.
                except (OSError, ValueError, TypeError, KeyError):
                    pass

    prev = None
    if cache.exists() and language_matches:
        try:
            prev = Hypernetwork.from_dict(json.loads(cache.read_text()))
        except Exception:
            prev = None

    raw = None
    net = None
    mode = "full"
    incremental_safe = False
    if language in ("auto", "mixed"):
        # Auto is a graph-level union of several RawIngest frontends. It cannot pass
        # through ingest_source(), whose contract is exactly one RawIngest.
        from lattice.cache import build_auto
        net, _handled = build_auto(src)
    elif (language_matches and language in ("typescript", "javascript")
            and cf is not None and cf["any"]):
        # Incremental LSP splicing only accepts source documents. Metadata such as
        # package.json changes entrypoint surfaces, while ts/js config can change module
        # resolution; either requires a full ingest. Be conservative for paths excluded
        # by the frontend's source selector as well.
        from lattice.ingest.lsp_client import _select_source_files
        selected = {p.relative_to(src).as_posix()
                    for p in _select_source_files(src, language)}
        removed_exts = {".js", ".jsx", ".mjs", ".cjs"} \
            if language == "javascript" else {".ts", ".tsx"}
        current_paths = set(cf["modified"]) | set(cf["added"])
        removed_paths = set(cf["removed"])
        incremental_safe = (current_paths <= selected
                            and all(pathlib.Path(p).suffix in removed_exts
                                    for p in removed_paths))
    if net is None and incremental_safe and rawp.exists():
        try:
            old_raw = raw_from_dict(json.loads(rawp.read_text()))
            raw = incremental_ingest(old_raw, src, cf["modified"] + cf["added"], cf["removed"], language)
            if raw is not None:
                mode = "incremental"
        except Exception:
            raw = None
    if net is None and raw is None:
        raw = ingest_source(src, language)
        mode = "full"

    if net is None:
        net = _build(raw)
    dg = digest(net)
    ch = changes(prev, net) if prev is not None else None

    cache.write_text(json.dumps(net.to_dict()))
    if raw is not None:
        rawp.write_text(json.dumps(raw_to_dict(raw)))
    manifest_path.write_text(json.dumps(cur_manifest))
    state_path.write_text(json.dumps({"language": language}))
    (out / "INVENTORY.md").write_text(render(dg, ch))
    if ch:
        mark = "  ⚠" if (ch["new_unresolved_imports"] or ch["broken_by_removal"]
                         or ch["removed_public_api"] or ch["error_diagnostics"]) else ""
        with (out / "CHANGES.md").open("a") as f:
            f.write(f"- {ch['verdict']}: +{ch['added_vertices']}/-{ch['removed_vertices']} symbols{mark}\n")

    return {"updated": True, "mode": mode, "digest": dg, "changes": ch,
            "changed_files": (cf["modified"] + cf["added"] + cf["removed"]) if cf else []}
