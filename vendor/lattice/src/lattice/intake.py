# src/lattice/intake.py
"""Agent intake — the complete, honestly-labeled payload a triage agent decides over.

The tool is recall-biased: it surfaces everything it found AND everywhere it went blind.
That's the wrong granularity for a final decision desk, so the consumption model is two
tiers: the tool produces this intake (facts + confidence + blind spots), and a provisioned
TRIAGE agent decides, per item, what reaches the judge — act / review / suppress / escalate.

Crucially, suppression and blind spots are NOT silently dropped: every item arrives with a
suggested disposition the triage agent can override, and blind spots arrive as `escalate`
because the ABSENCE of a finding where the tool couldn't look is not evidence of safety.
"""
from __future__ import annotations
import pathlib

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _disposition(severity: str, confidence: str) -> str:
    """The tool's SUGGESTED disposition — the triage agent makes the final call.
    proven + serious -> act; uncertain -> review; weak/low -> suppress-candidate."""
    if confidence == "proven" and severity in ("critical", "high"):
        return "act"
    if confidence == "heuristic" and severity in ("critical", "high"):
        return "act"            # structural facts (e.g. unguarded selfdestruct) are act-grade
    if confidence == "unproven" or severity == "medium":
        return "review"
    return "suppress_candidate"


def _solidity_intake(source_root) -> tuple[list, list, list]:
    from lattice.ingest.solidity import (
        solidity_audit, _audit_rel, _sol_files, _solc_ast,
    )
    root = pathlib.Path(source_root)
    findings: list[dict] = []
    blind = []
    coverage: list[dict] = []
    sol_files = [path for path in _sol_files(root) if path.suffix.lower() == ".sol"]
    if not sol_files:
        why = ("no Solidity source files were selected; none of the Solidity analyses ran, "
               "so an empty finding set is not evidence of safety")
        blind.append({"kind": "no_source_files", "where": str(root), "why": why,
                      "disposition": "escalate"})
        for analysis in (
            "solidity_audit",
            "oracle_taint",
            "donation_griefing",
            "arbitrary_call",
            "amm_invariant",
            "solidity_typed",
        ):
            coverage.append({"analysis": analysis, "status": "unavailable", "error": why})
        return findings, blind, coverage
    try:
        structural = solidity_audit(source_root)
    except Exception as exc:
        _record_analysis_failure(blind, coverage, root, "solidity_audit", exc)
    else:
        for f in structural:
            conf = "heuristic"  # structural AST facts: high-confidence but not dataflow-proven
            findings.append({
                "kind": f["kind"], "severity": f["severity"], "confidence": conf,
                "location": f"{f['file']}:{f['line']}",
                "subject": f"{f['contract']}.{f['function']}",
                "detail": f["detail"], "analysis": "solidity_audit",
                "disposition": _disposition(f["severity"], conf)})
        coverage.append({"analysis": "solidity_audit", "status": "completed",
                         "findings": len(structural)})
    # Use the same source selector as every detector.  In particular, ``Path.rglob``
    # on a directly requested file yields nothing; that used to omit the parse blind
    # spot even though the detector APIs themselves support singleton-file audits.
    for p in sol_files:
        if _solc_ast(p) is None:
            blind.append({"kind": "unparseable_file", "where": _audit_rel(p, root),
                          "why": "compiler version/syntax — NOT audited; absence of finding != safe",
                          "disposition": "escalate"})
    # The dedicated detector suite flows into the SAME intake.  These analyzers used to be
    # importable/tested but absent from the public cold-audit path, which made an empty report look
    # materially more complete than it was.  Keep failures explicit as blind spots so one optional
    # dependency or parser defect cannot silently erase the other legs.
    suites = (
        ("oracle_taint", "lattice.ingest.solidity_taint", "oracle_taint_audit"),
        ("donation_griefing", "lattice.ingest.solidity_donation", "donation_griefing_audit"),
        ("arbitrary_call", "lattice.ingest.solidity_arbitrary_call", "arbitrary_call_audit"),
        ("amm_invariant", "lattice.ingest.solidity_symbolic", "amm_invariant_audit"),
    )
    for analysis, module_name, callable_name in suites:
        try:
            module = __import__(module_name, fromlist=[callable_name])
            detector = getattr(module, callable_name)
            detected = detector(source_root)
        except Exception as exc:  # the omission is evidence, not a clean bill of health
            _record_analysis_failure(blind, coverage, root, analysis, exc)
            continue
        for finding in detected:
            findings.append(_normalize_solidity_finding(finding, root, analysis))
        coverage.append({"analysis": analysis, "status": "completed", "findings": len(detected)})

    # the typed-complex obstruction legs flow into the same payload
    try:
        tf, tb = _typed_intake(source_root)
    except Exception as exc:
        _record_analysis_failure(blind, coverage, root, "solidity_typed", exc)
    else:
        findings.extend(tf)
        blind.extend(tb)
        coverage.append({"analysis": "solidity_typed", "status": "completed",
                         "findings": len(tf), "blind_spots": len(tb)})
    return findings, blind, coverage


def _record_analysis_failure(blind: list, coverage: list, root: pathlib.Path,
                             analysis: str, exc: Exception) -> None:
    message = f"{analysis} did not run ({type(exc).__name__}: {exc})"
    blind.append({"kind": "analysis_failure", "where": str(root), "analysis": analysis,
                  "why": message, "disposition": "escalate"})
    coverage.append({"analysis": analysis, "status": "failed", "error": message})


def _normalize_solidity_finding(finding: dict, root: pathlib.Path, analysis: str) -> dict:
    """Preserve detector evidence while adding the common triage fields."""
    raw_file = str(finding.get("file") or "")
    if raw_file and root.is_file():
        # Detectors variously return an absolute path, the basename, or ``.`` for a
        # singleton root.  The public payload should consistently name the source.
        raw_file = (root.name
                    if raw_file == "." or pathlib.Path(raw_file).name == root.name
                    else raw_file)
    elif raw_file:
        path = pathlib.Path(raw_file)
        try:
            raw_file = path.relative_to(root).as_posix() if path.is_absolute() else path.as_posix()
        except ValueError:
            raw_file = path.as_posix()
    line = finding.get("line")
    location = raw_file + (f":{line}" if line is not None else "")
    contract = finding.get("contract") or ""
    function = finding.get("function") or ""
    subject = ".".join(x for x in (contract, function) if x)
    severity = finding.get("severity", "medium")
    raw_confidence = finding.get("confidence")
    confidence = raw_confidence if raw_confidence in {"proven", "heuristic", "unproven"} else (
        "unproven" if raw_confidence == "low" else "heuristic"
    )
    return {
        **finding,
        "severity": severity,
        "confidence": confidence,
        "location": location,
        "subject": subject,
        "analysis": analysis,
        "disposition": _disposition(severity, confidence),
    }


def _typed_intake(source_root) -> tuple[list, list]:
    """The typed-constraint-algebra legs (homology / typed_collision / conservation) normalized into
    the triage payload; the blindspot leg becomes escalate blind spots (no silent pass)."""
    from lattice.ingest.solidity_typed import typed_audit
    findings: list[dict] = []
    blind: list[dict] = []
    for f in typed_audit(source_root):
        if f["leg"] == "blindspot":
            blind.append({"kind": f["kind"], "where": f"{f['file']} · {f.get('contract', '')}",
                          "why": f["detail"], "disposition": "escalate"})
            continue
        conf = f.get("confidence", "heuristic")
        findings.append({
            "kind": f["kind"], "severity": f["severity"], "confidence": conf,
            "location": f"{f['file']}:{f.get('line', '?')}",
            "subject": f"{f.get('contract', '')}.{f.get('function', '')}",
            "detail": f["detail"], "analysis": f"typed:{f['leg']}",
            "disposition": _disposition(f["severity"], conf)})
    return findings, blind


def _graph_intake(source_root, language) -> tuple[list, list]:
    from lattice.cache import load_network
    from lattice.security import audit as security_audit
    from lattice.blindspots import blindspots
    net, root = load_network(source_root, language)
    findings: list[dict] = []
    rep = security_audit(net, source_root=root)
    for f in rep.findings:
        taint = getattr(f, "taint", "reachable")
        conf = "proven" if taint in ("reachable", "argument_flow") else "unproven"
        findings.append({
            "kind": f.kind, "severity": f.severity, "confidence": conf,
            "location": f.sink, "subject": f.source, "detail": f.detail,
            "analysis": "secaudit", "disposition": _disposition(f.severity, conf)})
    b = blindspots(net, root)
    blind = ([{"kind": "leaves_to_unmapped", "where": x, "disposition": "escalate",
               "why": "path exits to code with no graph — map it to follow through"}
              for x in b.leaves_to_unmapped]
             + [{"kind": "unreached", "where": x, "disposition": "review",
                 "why": "no followed path reaches it — dead, or reached via a path type not followed"}
                for x in b.unreached])
    return findings, blind


def agent_intake(source_root, language: str = "ts") -> dict:
    """Run the relevant analyses and consolidate into one triage-ready payload."""
    if language in ("solidity", "sol"):
        findings, blind, analysis_coverage = _solidity_intake(source_root)
    else:
        findings, blind = _graph_intake(source_root, language)
        analysis_coverage = [{"analysis": "graph", "status": "completed",
                              "findings": len(findings), "blind_spots": len(blind)}]

    findings.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 4),
                                 {"act": 0, "review": 1, "suppress_candidate": 2}.get(f["disposition"], 3)))
    by_disp: dict = {}
    for f in findings:
        by_disp[f["disposition"]] = by_disp.get(f["disposition"], 0) + 1

    return {
        "findings": findings,
        "blind_spots": blind,
        "analysis_coverage": analysis_coverage,
        "summary": {"total": len(findings), "by_disposition": by_disp,
                    "blind_spots": len(blind)},
        "triage_contract": (
            "You are the triage agent between this complete, recall-biased intake and the "
            "final decision desk. For EACH finding decide: act (surface as actionable), review "
            "(surface with your uncertainty noted), or suppress (do NOT surface — but RECORD the "
            "reason; never drop silently). For EACH blind spot decide escalate (flag for manual "
            "review — absence of a finding here is NOT evidence of safety) or accept (with reason). "
            "The suggested 'disposition' on each item is a default you may override. Bias: a false "
            "negative is invisible downstream, so when uncertain, surface or escalate rather than "
            "suppress. Your output is what reaches the judge — and your suppressions are auditable."),
    }
