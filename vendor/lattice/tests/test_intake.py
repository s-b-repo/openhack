import shutil
import importlib
import pytest
from lattice.intake import agent_intake

_SOLC = shutil.which("solc") is not None


@pytest.mark.skipif(not _SOLC, reason="solc")
def test_intake_normalizes_findings_with_confidence_and_dispositions(tmp_path):
    """The agent intake: every finding normalized with a confidence + a SUGGESTED
    disposition (act/review/suppress/escalate), plus blind spots surfaced as escalate —
    the recall-biased complete payload a triage agent decides over."""
    (tmp_path / "V.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract V {\n"
        "    mapping(address=>uint) bal;\n"
        "    function withdraw() public {\n"
        "        (bool ok,) = msg.sender.call{value: bal[msg.sender]}(\"\");\n"
        "        bal[msg.sender] = 0;\n"
        "    }\n"
        "    function nuke() public { selfdestruct(payable(msg.sender)); }\n"
        "}\n")
    (tmp_path / "broken.sol").write_text("pragma solidity ^0.7.0;\nthis is not valid solidity $$$\n")
    intake = agent_intake(str(tmp_path), language="solidity")
    assert intake["findings"], intake
    f0 = intake["findings"][0]
    assert {"kind", "severity", "confidence", "location", "detail", "disposition"} <= set(f0)
    # a critical unprotected selfdestruct should be suggested 'act'
    assert any(f["kind"] == "unprotected_selfdestruct" and f["disposition"] == "act"
               for f in intake["findings"]), intake["findings"]
    # the unparseable file must be an ESCALATE blind spot — absence of finding != safe
    assert any(b["disposition"] == "escalate" for b in intake["blind_spots"]), intake["blind_spots"]


@pytest.mark.skipif(not _SOLC, reason="solc")
def test_intake_includes_typed_obstruction_legs(tmp_path):
    """The typed-complex legs (homology/collision/conservation) flow into the SAME triage payload,
    tagged by analysis and normalized with confidence/disposition — so obstructions reach the judge
    through the one pipeline, and their blind spots escalate alongside."""
    (tmp_path / "Token.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Token {\n"
        "    mapping(address=>uint256) balances; uint256 totalSupply;\n"
        "    function reward(address u, uint256 amt) external { balances[u] += amt; }\n"  # unbacked mint
        "}\n")
    intake = agent_intake(str(tmp_path), language="solidity")
    cons = [f for f in intake["findings"] if f["analysis"] == "typed:conservation"]
    assert cons, intake["findings"]
    assert cons[0]["disposition"] in ("act", "review")     # normalized like any other finding
    assert "triage_contract" in intake          # the instruction the triage agent acts on


def test_solidity_intake_runs_every_dedicated_analyzer(monkeypatch, tmp_path):
    """The public intake must not omit a shipped Solidity detector while claiming suite coverage."""
    source = tmp_path / "V.sol"
    source.write_text("pragma solidity ^0.8.0; contract V {}\n")

    solidity = importlib.import_module("lattice.ingest.solidity")
    typed = importlib.import_module("lattice.ingest.solidity_typed")
    monkeypatch.setattr(solidity, "solidity_audit", lambda _root: [])
    monkeypatch.setattr(solidity, "_solc_ast", lambda _path: {"nodes": []})
    monkeypatch.setattr(typed, "typed_audit", lambda _root: [])

    expected = {
        "oracle_taint": ("lattice.ingest.solidity_taint", "oracle_taint_audit", "untrusted_flow"),
        "donation_griefing": (
            "lattice.ingest.solidity_donation", "donation_griefing_audit",
            "balance_invariant_griefable"),
        "arbitrary_call": (
            "lattice.ingest.solidity_arbitrary_call", "arbitrary_call_audit",
            "arbitrary_external_call"),
        "amm_invariant": (
            "lattice.ingest.solidity_symbolic", "amm_invariant_audit", "invariant_break"),
    }
    for analysis, (module_name, callable_name, kind) in expected.items():
        module = importlib.import_module(module_name)
        monkeypatch.setattr(module, callable_name, lambda _root, kind=kind: [{
            "kind": kind,
            "severity": "high",
            "file": str(source),
            "contract": "V",
            "function": "f",
            "detail": "evidence",
        }])

    intake = agent_intake(tmp_path, language="solidity")
    assert {f["analysis"] for f in intake["findings"]} == set(expected)
    assert all(f["location"] == "V.sol" for f in intake["findings"])
    assert all(f["subject"] == "V.f" and f["disposition"] == "act"
               for f in intake["findings"])
    completed = {item["analysis"] for item in intake["analysis_coverage"]
                 if item["status"] == "completed"}
    assert completed == {"solidity_audit", "solidity_typed", *expected}


def test_solidity_intake_single_file_keeps_parse_coverage_and_filename(monkeypatch, tmp_path):
    source = tmp_path / "V.sol"
    source.write_text("pragma solidity ^0.8.0; contract V {}\n")
    solidity = importlib.import_module("lattice.ingest.solidity")
    typed = importlib.import_module("lattice.ingest.solidity_typed")
    monkeypatch.setattr(solidity, "solidity_audit", lambda _root: [])
    monkeypatch.setattr(solidity, "_solc_ast", lambda _path: None)
    monkeypatch.setattr(typed, "typed_audit", lambda _root: [])
    for module_name, callable_name in (
        ("lattice.ingest.solidity_taint", "oracle_taint_audit"),
        ("lattice.ingest.solidity_donation", "donation_griefing_audit"),
        ("lattice.ingest.solidity_arbitrary_call", "arbitrary_call_audit"),
        ("lattice.ingest.solidity_symbolic", "amm_invariant_audit"),
    ):
        monkeypatch.setattr(importlib.import_module(module_name), callable_name,
                            lambda _root: [{"kind": "lead", "severity": "medium",
                                            "file": ".", "detail": "evidence"}])

    intake = agent_intake(source, language="solidity")

    assert any(item["kind"] == "unparseable_file" and item["where"] == "V.sol"
               for item in intake["blind_spots"])
    assert all(item["location"] == "V.sol" for item in intake["findings"])


def test_solidity_intake_exposes_detector_failure_as_blind_spot(monkeypatch, tmp_path):
    source = tmp_path / "V.sol"
    source.write_text("pragma solidity ^0.8.0; contract V {}\n")
    solidity = importlib.import_module("lattice.ingest.solidity")
    typed = importlib.import_module("lattice.ingest.solidity_typed")
    monkeypatch.setattr(solidity, "solidity_audit", lambda _root: [])
    monkeypatch.setattr(solidity, "_solc_ast", lambda _path: {"nodes": []})
    monkeypatch.setattr(typed, "typed_audit", lambda _root: [])
    donation = importlib.import_module("lattice.ingest.solidity_donation")
    monkeypatch.setattr(donation, "donation_griefing_audit",
                        lambda _root: (_ for _ in ()).throw(RuntimeError("bridge broke")))

    intake = agent_intake(tmp_path, language="solidity")
    blind = [b for b in intake["blind_spots"] if b.get("analysis") == "donation_griefing"]
    assert blind and blind[0]["kind"] == "analysis_failure"
    assert blind[0]["disposition"] == "escalate"
    status = {item["analysis"]: item["status"] for item in intake["analysis_coverage"]}
    assert status["donation_griefing"] == "failed"


@pytest.mark.parametrize("source_kind", ["empty_directory", "wrong_singleton"])
def test_solidity_intake_without_solidity_sources_escalates_and_does_not_claim_coverage(
    tmp_path, source_kind
):
    source = tmp_path
    if source_kind == "wrong_singleton":
        source = tmp_path / "not_solidity.py"
        source.write_text("print('not solidity')\n")

    intake = agent_intake(source, language="solidity")

    assert intake["summary"] == {"total": 0, "by_disposition": {}, "blind_spots": 1}
    assert intake["blind_spots"][0]["kind"] == "no_source_files"
    assert intake["blind_spots"][0]["disposition"] == "escalate"
    assert {item["analysis"] for item in intake["analysis_coverage"]} == {
        "solidity_audit",
        "oracle_taint",
        "donation_griefing",
        "arbitrary_call",
        "amm_invariant",
        "solidity_typed",
    }
    assert all(item["status"] == "unavailable" for item in intake["analysis_coverage"])
