import shutil
import pytest
from lattice.cold_audit import cold_audit, format_report, _in_skip, _sol_count

pytestmark = pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed")


def test_cold_audit_ranks_and_structures(tmp_path):
    """The harness returns a structured triage: findings ranked by severity, parse failures and
    blind spots surfaced SEPARATELY (so absence-of-finding is never read as 'safe')."""
    (tmp_path / "Bank.sol").write_text(
        "pragma solidity ^0.6.0;\n"
        "contract Bank { mapping(address=>uint) bal;\n"
        "  function withdraw() public { uint a=bal[msg.sender];"
        " (bool o,)=msg.sender.call{value:a}(''); require(o); bal[msg.sender]=0; } }\n")
    r = cold_audit(str(tmp_path))
    kinds = {f["kind"] for f in r["findings"]}
    assert "reentrancy" in kinds
    assert "parse_failure" not in kinds            # parse failures are not in `findings`
    assert "parse_failures" in r and "blind_spots" in r and "by_severity" in r
    assert {item["analysis"] for item in r["analysis_coverage"]} >= {
        "solidity_audit", "solidity_typed", "oracle_taint", "donation_griefing",
        "arbitrary_call", "amm_invariant",
    }


def test_cold_audit_skips_test_and_dep_dirs(tmp_path):
    """A finding in a test/ or lib/ dir is NOT the audited surface and must be filtered out."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Clean.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Clean { uint x; function set(uint v) public { x=v; } }\n")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "Bad.t.sol").write_text(
        "pragma solidity ^0.6.0;\ncontract Bad { address a;"
        " function f() public { a.call{value:1}(''); } }\n")
    r = cold_audit(str(tmp_path))
    assert all("test" not in f.get("location", "") for f in r["findings"])
    assert _in_skip("test/Bad.t.sol:3") and not _in_skip("src/Clean.sol:1")


def test_cold_audit_skip_filter_accepts_blind_spot_where_field():
    assert _in_skip("test/Broken.t.sol")


def test_cold_audit_counts_a_direct_solidity_file(tmp_path):
    source = tmp_path / "One.sol"
    source.write_text("pragma solidity ^0.8.0; contract One {}\n")
    assert _sol_count(source) == 1


def test_cold_audit_surfaces_parse_failure(tmp_path):
    """An unparseable file is surfaced as a parse_failure (not silently dropped, not a finding)."""
    (tmp_path / "Broken.sol").write_text(
        "pragma solidity ^0.4.19;\ncontract Broken { function f() public { uint a = ; } }\n")
    r = cold_audit(str(tmp_path))
    assert len(r["parse_failures"]) >= 1


def test_format_report_names_failed_analysis_and_reason():
    report = format_report({
        "root": "/repo", "sol_files": 1, "findings": [], "parse_failures": [],
        "by_severity": {},
        "analysis_coverage": [
            {"analysis": "solidity_audit", "status": "completed"},
            {"analysis": "amm_invariant", "status": "failed"},
        ],
        "blind_spots": [{
            "kind": "analysis_failure", "analysis": "amm_invariant",
            "why": "amm_invariant did not run (ImportError: sympy)",
        }],
    })
    assert "analyses FAILED: amm_invariant" in report
    assert "ImportError: sympy" in report
