# src/lattice/complete/gate.py
from __future__ import annotations
from lattice.graph.models import Hypernetwork
from lattice.complete.report import HypernetworkReport


def check(net: Hypernetwork) -> HypernetworkReport:
    external_ids = {v.id for v in net.vertices if v.kind == "external"}
    known_ids = {v.id for v in net.vertices}

    dangling: list[str] = []
    unresolved_imports: list[str] = []

    # Edges whose targets are entirely external are excluded from the
    # resolution denominator — they are inherently unresolvable in-project.
    countable_edges: list = []

    for e in net.hyperedges:
        targets_external = bool(e.members) and e.members[-1] in external_ids
        missing = [m for m in e.members if m not in known_ids]

        if e.kind == "imports" and not targets_external and (missing or not e.resolved):
            # Unresolved import that targets a known-but-missing in-project file:
            # collect the unknown member IDs. External-targeted imports (npm packages)
            # are excluded — they are inherently unresolvable in-project.
            unresolved_imports.extend(missing if missing else e.members[1:])
        elif not e.resolved and not targets_external:
            dangling.append(e.id)

        # Exclude external-targeted edges from resolution ratio
        if not targets_external:
            countable_edges.append(e)

    total = len(countable_edges)
    resolved = sum(1 for e in countable_edges if e.resolved)
    resolution = 1.0 if total == 0 else resolved / total

    stubs = [v.id for v in net.vertices if v.stub]
    surface_coverage = {
        "public_api": sum(1 for s in net.surfaces if s.kind == "public_api"),
        "external_call": sum(1 for s in net.surfaces if s.kind == "external_call"),
    }

    failing: list[str] = []
    diagnostics = net_diagnostics(net)
    diagnostic_errors = [d for d in diagnostics
                         if str(d.get("severity", "error")).lower() == "error"]
    if diagnostic_errors:
        failing.append("ingest_diagnostics")
    if unresolved_imports:
        failing.append("unresolved_imports")
    if dangling:
        failing.append("dangling_edges")

    if diagnostic_errors or unresolved_imports:
        verdict = "fail"
    elif resolution >= 0.98 and not dangling:
        verdict = "pass"
    elif resolution >= 0.85:
        verdict = "partial"
    else:
        verdict = "fail"

    # Coverage is a RECALL indicator, distinct from resolution: resolution says the
    # edges that exist are resolved; coverage estimates whether edges are *present*.
    # `verdict=pass` / `resolution=1.000` does NOT mean the graph is complete.
    ref_targets = {e.members[-1] for e in net.hyperedges
                   if e.kind == "references" and len(e.members) >= 2}
    fns = [v for v in net.vertices if v.kind in ("function", "method")]
    with_refs = sum(1 for v in fns if v.id in ref_targets)
    coverage = {
        "functions_total": len(fns),
        "functions_with_inbound_refs": with_refs,
        "ratio": (with_refs / len(fns)) if fns else 1.0,
        "note": ("recall indicator only — fraction of functions with a detected inbound "
                 "reference. Low values mean either dead exports OR missing edges; "
                 "resolution measures edge resolution, NOT edge completeness."),
    }

    return HypernetworkReport(
        resolution=resolution,
        dangling_edges=dangling,
        unresolved_imports=unresolved_imports,
        stubs=stubs,
        surface_coverage=surface_coverage,
        coverage=coverage,
        diagnostics=diagnostics,
        verdict=verdict,
        failing_checks=failing,
    )


def net_diagnostics(net: Hypernetwork) -> list[dict]:
    return list(net.diagnostics)
