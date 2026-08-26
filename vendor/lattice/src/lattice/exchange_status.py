from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from lattice.complete.gate import check
from lattice.complete.report import HypernetworkReport
from lattice.diagnose import Diagnostics, diagnose
from lattice.graph.models import Hypernetwork


SCHEMA_VERSION = "lattice.exchange_status.v1"
SURFACE_LIMIT = 128


def build_exchange_status(
    net: Hypernetwork,
    *,
    report: HypernetworkReport | None = None,
    diagnostics: Diagnostics | None = None,
    observed_at: str | None = None,
    source_path: str | None = None,
) -> dict[str, Any]:
    """Summarize a Lattice graph as an authority-neutral Exchange/Deck status payload."""
    report = report or check(net)
    diagnostics = diagnostics or diagnose(net)
    observed_at = observed_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    coverage = report.coverage if isinstance(report.coverage, dict) else {}
    coverage_ratio = _float(coverage.get("ratio"), default=1.0)
    resolution = _float(report.resolution, default=0.0)
    diag_summary = diagnostics.summary if isinstance(diagnostics.summary, dict) else {}
    surface_rows = _surface_rows(net)
    pressure = _pressure(report=report, diagnostics=diagnostics, coverage_ratio=coverage_ratio)

    return {
        "schema": SCHEMA_VERSION,
        "observed_at": observed_at,
        "source_path": source_path or net.root,
        "language": net.language,
        "overall_status": _overall_status(
            report=report,
            diagnostics=diagnostics,
            coverage_ratio=coverage_ratio,
        ),
        "pressure": pressure,
        "graph": {
            "root": net.root,
            "vertices": len(net.vertices),
            "hyperedges": len(net.hyperedges),
            "surfaces": len(net.surfaces),
            "vertex_kinds": dict(sorted(Counter(v.kind for v in net.vertices).items())),
            "edge_kinds": dict(sorted(Counter(e.kind for e in net.hyperedges).items())),
            "surface_kinds": dict(sorted(Counter(s.kind for s in net.surfaces).items())),
        },
        "completeness": {
            "verdict": report.verdict,
            "resolution": resolution,
            "coverage_ratio": coverage_ratio,
            "functions_total": int(coverage.get("functions_total") or 0),
            "functions_with_inbound_refs": int(coverage.get("functions_with_inbound_refs") or 0),
            "failing_checks": list(report.failing_checks),
            "dangling_edges": len(report.dangling_edges),
            "unresolved_imports": len(report.unresolved_imports),
            "stubs": len(report.stubs),
            "note": coverage.get("note"),
        },
        "diagnostics": {
            "verdict": diag_summary.get("verdict") or "unknown",
            "cycles": len(diagnostics.cycles),
            "dead_code": len(diagnostics.dead_code),
            "stubs": len(diagnostics.stubs),
            "dangling_edges": len(diagnostics.dangling_edges),
            "unresolved_imports": len(diagnostics.unresolved_imports),
            "reconciliation_candidates": len(diagnostics.reconciliation_candidates),
            "obstructions": len(diagnostics.obstructions),
            "b1": (diagnostics.betti or {}).get("b1", diag_summary.get("b1", 0)),
            "hotspots": diagnostics.hotspots[:10],
        },
        "surface_inventory": {
            "mode": "observer_only",
            "surface_count": len(surface_rows),
            "observer_count": len(surface_rows),
            "guard_relevant_count": sum(1 for surface in surface_rows if surface["guard_relevant"]),
            "control_authority_count": 0,
            "write_surface_count": 0,
            "surface_limit": SURFACE_LIMIT,
            "surfaces": surface_rows[:SURFACE_LIMIT],
            "surfaces_truncated": len(surface_rows) > SURFACE_LIMIT,
        },
        "confidence": {
            "value": round(max(0.0, min(1.0, 0.55 * resolution + 0.45 * coverage_ratio)), 3),
            "basis": "resolution_and_edge_recall_coverage",
            "source_quality": "high" if coverage_ratio >= 0.85 else "medium" if coverage_ratio >= 0.5 else "low",
        },
        "authority": {
            "control_authority": False,
            "writes": [],
            "reason": "Lattice is an analysis/status surface; Exchange and Guard own actions.",
        },
    }


def _surface_rows(net: Hypernetwork) -> list[dict[str, Any]]:
    vertices = {v.id: v for v in net.vertices}
    rows: list[dict[str, Any]] = []
    for surface in sorted(net.surfaces, key=lambda s: (s.kind, s.id)):
        vertex = vertices.get(surface.vertex_id)
        rows.append(
            {
                "surface_id": surface.id,
                "surface_kind": surface.kind,
                "vertex_id": surface.vertex_id,
                "vertex_name": vertex.name if vertex else None,
                "vertex_kind": vertex.kind if vertex else None,
                "file": vertex.file if vertex else None,
                "observer_only": True,
                "guard_relevant": surface.kind in {"entrypoint", "external_call", "trust_boundary"},
                "control_authority": False,
                "writes": [],
                "observes": [surface.vertex_id],
            }
        )
    return rows


def _overall_status(
    *,
    report: HypernetworkReport,
    diagnostics: Diagnostics,
    coverage_ratio: float,
) -> str:
    if report.verdict == "fail":
        return "blocked"
    if report.verdict == "partial":
        return "review"
    if coverage_ratio < 0.5:
        return "watch"
    if diagnostics.summary.get("verdict") == "issues":
        return "watch"
    return "healthy"


def _pressure(
    *,
    report: HypernetworkReport,
    diagnostics: Diagnostics,
    coverage_ratio: float,
) -> float:
    pressure = max(0.0, min(1.0, 1.0 - coverage_ratio))
    if report.verdict == "fail":
        pressure = max(pressure, 1.0)
    elif report.verdict == "partial":
        pressure = max(pressure, 0.65)
    if diagnostics.summary.get("verdict") == "issues":
        pressure = max(pressure, 0.45)
    if diagnostics.obstructions:
        pressure = max(pressure, 0.75)
    return round(pressure, 3)


def _float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
