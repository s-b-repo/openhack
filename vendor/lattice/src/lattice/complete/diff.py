# src/lattice/complete/diff.py
"""Differential gate: compare a 'before' and 'after' hypernetwork, report
structural regressions causally attributable to the change, and refuse to verify
an after graph that still carries error-severity ingest diagnostics.

This is the self-verification primitive: an absolute gate says "the codebase is
complete"; a differential gate says "your change introduced N new structural
breaks" — a claim an agent can honestly assert about its own work.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import json

from lattice.graph.models import Hypernetwork, Hyperedge, Vertex


def _edge_key(e: Hyperedge) -> tuple:
    # Edge ids (e1, e2, ...) are positional and unstable across ingests.
    # Structural identity = (kind, ordered members) is ingestion-order invariant.
    return (e.kind, tuple(e.members))


def _edge_attributes(e: Hyperedge) -> tuple:
    return (e.directed, e.resolved, float(e.confidence), e.provenance)


_FACT_PROVENANCE = {"ingest", "entrypoint"}


def _edge_is_downgraded(before: Hyperedge, after: Hyperedge) -> bool:
    """Whether the same structural edge now carries strictly weaker evidence."""
    return (
        (before.resolved and not after.resolved)
        or float(after.confidence) < float(before.confidence)
        or (before.provenance in _FACT_PROVENANCE
            and after.provenance not in _FACT_PROVENANCE)
        or before.directed != after.directed
    )


def _edge_map(net: Hypernetwork) -> dict[tuple, Hyperedge]:
    """Best-evidence representative per structural key (duplicates are uncommon)."""
    def strength(edge: Hyperedge) -> tuple:
        return (int(edge.resolved), float(edge.confidence),
                int(edge.provenance in _FACT_PROVENANCE))

    out: dict[tuple, Hyperedge] = {}
    for edge in net.hyperedges:
        key = _edge_key(edge)
        if key not in out or strength(edge) > strength(out[key]):
            out[key] = edge
    return out


def _vertex_contract(v: Vertex) -> tuple:
    """Line-independent semantic contract for one stable vertex identity."""
    return (v.kind, v.name, v.file, v.type, v.exported, v.stub, tuple(v.params))


def _surface_keys(net: Hypernetwork) -> set[tuple[str, str]]:
    # Surface ids are positional; boundary identity is kind + target vertex.
    return {(surface.kind, surface.vertex_id) for surface in net.surfaces}


def _external_ids(net: Hypernetwork) -> set[str]:
    return {v.id for v in net.vertices if v.kind == "external"}


def _problem_edges(net: Hypernetwork) -> tuple[set[tuple], set[tuple]]:
    """Return (unresolved_import_keys, dangling_keys) using the same predicate
    as complete.gate.check, but keyed structurally so they survive renumbering."""
    external = _external_ids(net)
    known = {v.id for v in net.vertices}
    unresolved_imports: set[tuple] = set()
    dangling: set[tuple] = set()
    for e in net.hyperedges:
        targets_external = bool(e.members) and e.members[-1] in external
        missing = any(m not in known for m in e.members)
        if e.kind == "imports" and not targets_external and (missing or not e.resolved):
            unresolved_imports.add(_edge_key(e))
        elif not e.resolved and not targets_external:
            dangling.add(_edge_key(e))
    return unresolved_imports, dangling


def _error_diagnostics(net: Hypernetwork) -> dict[str, dict]:
    """Canonical errors, ignoring checkout-root differences in diagnostic text."""
    out: dict[str, dict] = {}
    root = str(net.root).rstrip("/\\")

    def normalized(value):
        if isinstance(value, dict):
            return {key: normalized(item) for key, item in value.items()}
        if isinstance(value, list):
            return [normalized(item) for item in value]
        if isinstance(value, str) and root:
            return value.replace(root, "<root>")
        return value

    for diagnostic in net.diagnostics:
        if str(diagnostic.get("severity", "error")).lower() != "error":
            continue
        key = json.dumps(normalized(diagnostic), sort_keys=True,
                         separators=(",", ":"), default=str)
        out.setdefault(key, diagnostic)
    return out


@dataclass
class DiffReport:
    added_vertices: list[str] = field(default_factory=list)
    removed_vertices: list[str] = field(default_factory=list)
    added_edges: list[str] = field(default_factory=list)        # human-readable keys
    removed_edges: list[str] = field(default_factory=list)
    changed_vertices: list[str] = field(default_factory=list)
    changed_edges: list[str] = field(default_factory=list)
    downgraded_edges: list[str] = field(default_factory=list)
    added_surfaces: list[str] = field(default_factory=list)
    removed_surfaces: list[str] = field(default_factory=list)
    new_dangling_edges: list[str] = field(default_factory=list)
    new_unresolved_imports: list[str] = field(default_factory=list)
    baseline_error_diagnostics: list[dict] = field(default_factory=list)
    error_diagnostics: list[dict] = field(default_factory=list)
    new_error_diagnostics: list[dict] = field(default_factory=list)
    broken_by_removal: list[str] = field(default_factory=list)  # "edge -> deleted vertex"
    removed_public_api: list[str] = field(default_factory=list)
    changed_public_api: list[str] = field(default_factory=list)
    removed_entrypoints: list[str] = field(default_factory=list)
    verdict: str = "clean"           # "clean" | "regressed" | "unverifiable"
    regressions: list[str] = field(default_factory=list)
    # Honest output contract: name what this gate does and does NOT certify.
    verified: list[str] = field(default_factory=lambda: ["structural_delta"])
    not_verified: list[str] = field(default_factory=lambda:
                                    ["correctness", "intent", "runtime_behavior"])

    def to_dict(self) -> dict:
        return asdict(self)


def diff(before: Hypernetwork, after: Hypernetwork) -> DiffReport:
    before_v = {v.id: v for v in before.vertices}
    after_v = {v.id: v for v in after.vertices}

    added_vertices = sorted(set(after_v) - set(before_v))
    removed_vertices = sorted(set(before_v) - set(after_v))

    changed_vertices = sorted(
        vertex_id for vertex_id in (set(before_v) & set(after_v))
        if _vertex_contract(before_v[vertex_id]) != _vertex_contract(after_v[vertex_id])
    )

    before_edge_map = _edge_map(before)
    after_edge_map = _edge_map(after)
    before_e = set(before_edge_map)
    after_e = set(after_edge_map)
    added_edges = sorted(str(k) for k in (after_e - before_e))
    removed_edges = sorted(str(k) for k in (before_e - after_e))
    changed_edge_keys = {
        key for key in (before_e & after_e)
        if _edge_attributes(before_edge_map[key]) != _edge_attributes(after_edge_map[key])
    }
    changed_edges = sorted(str(key) for key in changed_edge_keys)
    downgraded_edges = sorted(
        str(key) for key in changed_edge_keys
        if _edge_is_downgraded(before_edge_map[key], after_edge_map[key])
    )

    before_surfaces = _surface_keys(before)
    after_surfaces = _surface_keys(after)
    added_surfaces = sorted(str(key) for key in (after_surfaces - before_surfaces))
    removed_surface_keys = before_surfaces - after_surfaces
    removed_surfaces = sorted(str(key) for key in removed_surface_keys)

    b_unres, b_dang = _problem_edges(before)
    a_unres, a_dang = _problem_edges(after)
    new_unresolved_imports = sorted(str(k) for k in (a_unres - b_unres))
    new_dangling_edges = sorted(str(k) for k in (a_dang - b_dang))
    before_diagnostics = _error_diagnostics(before)
    after_diagnostics = _error_diagnostics(after)
    baseline_error_diagnostics = [before_diagnostics[key]
                                  for key in sorted(before_diagnostics)]
    error_diagnostics = [after_diagnostics[key] for key in sorted(after_diagnostics)]
    new_error_diagnostics = [after_diagnostics[key]
                             for key in sorted(set(after_diagnostics) - set(before_diagnostics))]

    # Downstream damage: a deletion orphaned a SURVIVING caller. Scan the BEFORE graph
    # (not after — a fresh re-ingest never builds edges to a vertex that no longer
    # exists, so the after-graph is structurally blind to this). An edge counts as
    # broken when its target was deleted but its source still exists in `after`: live
    # code now references a symbol that's gone. This is the load-bearing prevention
    # signal for deleting a NON-exported function that still has callers.
    removed_set = set(removed_vertices)
    broken_by_removal: list[str] = []
    for e in before.hyperedges:
        if not e.members:
            continue
        src, tgt = e.members[0], e.members[-1]
        if tgt in removed_set and src in after_v and src not in removed_set:
            broken_by_removal.append(f"{e.kind}:{src} -> deleted {tgt}")

    # Objective signal for the policy decision below (does NOT yet affect verdict).
    removed_public_api = {
        vid for vid in removed_vertices
        if before_v[vid].exported and before_v[vid].kind in ("function", "method")
    }
    removed_public_api.update(
        vertex_id for kind, vertex_id in removed_surface_keys if kind == "public_api")
    removed_public_api.update(
        vertex_id for vertex_id in changed_vertices
        if before_v[vertex_id].exported
        and before_v[vertex_id].kind in ("function", "method")
        and not after_v[vertex_id].exported
    )
    changed_public_api = sorted(
        vertex_id for vertex_id in changed_vertices
        if before_v[vertex_id].exported and after_v[vertex_id].exported
        and before_v[vertex_id].kind in ("function", "method")
        and (_vertex_contract(before_v[vertex_id]) !=
             _vertex_contract(after_v[vertex_id]))
    )
    removed_entrypoints = sorted(
        vertex_id for kind, vertex_id in removed_surface_keys if kind == "entrypoint")

    report = DiffReport(
        added_vertices=added_vertices,
        removed_vertices=removed_vertices,
        added_edges=added_edges,
        removed_edges=removed_edges,
        changed_vertices=changed_vertices,
        changed_edges=changed_edges,
        downgraded_edges=downgraded_edges,
        added_surfaces=added_surfaces,
        removed_surfaces=removed_surfaces,
        new_dangling_edges=new_dangling_edges,
        new_unresolved_imports=new_unresolved_imports,
        baseline_error_diagnostics=baseline_error_diagnostics,
        error_diagnostics=error_diagnostics,
        new_error_diagnostics=new_error_diagnostics,
        broken_by_removal=broken_by_removal,
        removed_public_api=sorted(removed_public_api),
        changed_public_api=changed_public_api,
        removed_entrypoints=removed_entrypoints,
    )
    report.verdict, report.regressions = _classify(report)
    if report.baseline_error_diagnostics or report.error_diagnostics:
        report.verified = ([] if report.verdict == "unverifiable"
                           else ["ingest_diagnostic_delta"])
        report.not_verified = ["structural_delta", "correctness", "intent",
                               "runtime_behavior"]
    return report


def _classify(r: DiffReport) -> tuple[str, list[str]]:
    """Decide whether the structural delta is a regression.

    POLICY — this is the judgment call. The mechanical deltas above are objective
    facts; what *counts as a regression worth blocking* is a design decision.

    A change is "regressed" if it:
      - introduced a new broken import (new_unresolved_imports),
      - introduced a new dangling internal reference (new_dangling_edges),
      - introduced a new error-severity ingest diagnostic (new_error_diagnostics),
      - deleted a vertex that something still references (broken_by_removal), or
      - deleted/downgraded an exported public_api or entrypoint,
      - changed an exported callable's signature, or
      - weakened the evidence carried by an existing edge.

    The last rule is the STRICT stance. public_api is, by definition, the surface
    external consumers depend on — and the hypernetwork structurally cannot see
    those callers. "Zero in-repo references" is therefore not evidence of safety;
    it is a blind spot. The honest gate flags a deletion it cannot prove safe
    rather than certifying clean over what it can't see. A consumer who wants the
    lenient stance can drop the removed_public_api clause below.

    Error diagnostics take precedence over ordinary structural deltas: a newly
    introduced error is a regression, while an identical preexisting error makes
    the after graph unverifiable rather than clean or causally regressed.
    """
    regressions: list[str] = []
    if r.new_unresolved_imports:
        regressions.append("new_unresolved_imports")
    if r.new_dangling_edges:
        regressions.append("new_dangling_edges")
    if r.new_error_diagnostics:
        regressions.append("new_error_diagnostics")
    if r.broken_by_removal:
        regressions.append("broken_by_removal")
    if r.removed_public_api:
        regressions.append("removed_public_api")
    if r.changed_public_api:
        regressions.append("changed_public_api")
    if r.removed_entrypoints:
        regressions.append("removed_entrypoints")
    if r.downgraded_edges:
        regressions.append("downgraded_edges")
    if r.new_error_diagnostics:
        verdict = "regressed"
    elif r.error_diagnostics or r.baseline_error_diagnostics:
        # A failure in either graph makes the structural comparison incomplete.
        # Disappearing baseline errors are an improvement, but the incomplete baseline
        # still cannot prove which structural facts existed before the change.
        verdict = "unverifiable"
    elif regressions:
        verdict = "regressed"
    else:
        verdict = "clean"
    return verdict, regressions
