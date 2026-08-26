# src/lattice/mcp/tools.py
"""The six MCP tool callables — plain functions over a Workspace, returning JSON-able
dicts. Kept transport-free so they unit-test directly; server.py wraps them for FastMCP.

Every analysis result carries a `freshness` block so a calling agent always knows
whether the cached graph still matches the source tree on disk.
"""
from __future__ import annotations

import difflib

from lattice.complete.gate import check
from lattice.graph.query import GraphView
from lattice.hunt import hunt
from lattice.impact import impact, resolve_targets
from lattice.security import audit as security_audit
from lattice.triage import triage

_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _graph_health(net) -> dict:
    report = check(net)
    return {
        "verdict": report.verdict,
        "failing_checks": list(report.failing_checks),
        # Preserve every frontend diagnostic, including warnings adjacent to errors.
        "diagnostics": list(report.diagnostics),
    }


def _freshness(ws, graph_health: dict | None = None) -> dict:
    s = ws.staleness()
    changed = s["changed"] + s["added"] + s["removed"]
    health = graph_health or (_graph_health(ws.net) if ws.net is not None else None)
    if changed:
        hint = "call lattice_refresh to rebuild"
    elif health is not None and health["verdict"] == "fail":
        hint = "source snapshot is current, but graph health failed; inspect graph_health"
    else:
        hint = "graph snapshot matches source"
    return {
        "stale": bool(changed),
        "changed_files": changed,
        "hint": hint,
    }


def _ensure(ws):
    """Lazy auto-map: an analysis tool on a never-mapped workspace maps it first."""
    mapped = ws.net is None
    ws.ensure()
    return mapped


# ---- map ----

def tool_map(ws, language: str = "auto") -> dict:
    net = ws.ensure(language=language)
    health = _graph_health(net)
    surfaces = {}
    for s in net.surfaces:
        surfaces[s.kind] = surfaces.get(s.kind, 0) + 1
    return {
        "root": str(ws.root),
        "language": ws.language,
        "vertices": net.stats["vertices"],
        "hyperedges": net.stats["hyperedges"],
        "surfaces": surfaces,
        "freshness": _freshness(ws, health),
        "graph_health": health,
    }


# ---- impact (the wedge: blast radius before an edit) ----

def tool_impact(ws, query: str) -> dict:
    net = ws.ensure()
    health = _graph_health(net)
    g = GraphView(net)

    # File query: union the blast radius of every symbol defined in that file.
    file_syms = [v.id for v in net.vertices
                 if v.kind not in ("module", "external")
                 and (v.file == query or v.file.endswith("/" + query) or v.file == query.lstrip("./"))]
    if file_syms:
        targets, by = file_syms, "file"
    else:
        targets, by = resolve_targets(net, query), "symbol"

    if not targets:
        all_names = sorted({v.name for v in net.vertices if v.kind not in ("module", "external")})
        substr = [n for n in all_names if query.lower() in n.lower()]
        fuzzy = difflib.get_close_matches(query, all_names, n=10, cutoff=0.5)
        suggestions = list(dict.fromkeys(substr + fuzzy))[:10]   # substring first, dedup
        return {"error": f"no symbol or file matches {query!r}",
                "suggestions": suggestions, "freshness": _freshness(ws, health),
                "graph_health": health}

    direct: set = set()
    transitive: set = set()
    public: set = set()
    files: set = set()
    public_ids = {s.vertex_id for s in net.surfaces if s.kind == "public_api"}
    vmap = {v.id: v for v in net.vertices}
    for vid in targets:
        rep = impact(net, vid, g=g)
        direct.update(rep.direct_dependents)
        transitive.update(rep.transitive_dependents)
        files.update(rep.affected_files)
        public.update(rep.affected_public_api)
    transitive -= set(targets)
    return {
        "by": by,
        "targets": sorted(targets),
        "direct_dependents": sorted(direct),
        "transitive_dependents": sorted(transitive),
        "affected_files": sorted(files),
        "affected_public_api": sorted(public),
        "blast_radius": len(transitive),
        "freshness": _freshness(ws, health),
        "graph_health": health,
    }


# ---- hunt (post-edit bug gate) ----

def tool_hunt(ws, severity_min: str = "low") -> dict:
    net = ws.ensure()
    health = _graph_health(net)
    floor = _SEV_RANK.get(severity_min, 0)
    findings = [b.to_dict() for b in hunt(net)
                if _SEV_RANK.get(b.severity, 0) >= floor]
    counts: dict = {}
    for b in findings:
        counts[b["severity"]] = counts.get(b["severity"], 0) + 1
    return {"findings": findings, "counts": counts, "total": len(findings),
            "freshness": _freshness(ws, health), "graph_health": health}


# ---- secaudit ----

def tool_secaudit(ws) -> dict:
    net = ws.ensure()
    health = _graph_health(net)
    rep = security_audit(net, source_root=ws.root)
    out = rep.to_dict()
    out["freshness"] = _freshness(ws, health)
    out["graph_health"] = health
    return out


# ---- triage ----

def tool_triage(ws) -> dict:
    net = ws.ensure()
    health = _graph_health(net)
    worklist = [t.to_dict() for t in triage(net)]
    return {"worklist": worklist, "total": len(worklist),
            "freshness": _freshness(ws, health), "graph_health": health}


# ---- refresh (freshness escape hatch) ----

def tool_refresh(ws) -> dict:
    out = ws.refresh()
    health = _graph_health(ws.net)
    out["freshness"] = _freshness(ws, health)
    out["graph_health"] = health
    return out
