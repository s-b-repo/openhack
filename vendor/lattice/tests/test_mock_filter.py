"""Mock/test-contract file filtering. A production audit should not surface findings in mock/test
contracts (the Fei MockTokemak* / forge-std Test.sol noise) — they are not deployed code. Skip by
directory (test/mock/...), foundry convention (*.t.sol / *.s.sol), and Mock* filenames. RECALL-SAFE:
the skip applies ONLY to directory globbing — a single mock file passed EXPLICITLY is still analyzed
(explicit intent), and real contracts in normal dirs/names are untouched.
"""
import pytest

from lattice.ingest.solidity import solidity_audit, _solc_ast
from lattice.ingest.solidity_arbitrary_call import arbitrary_call_audit


def _parses(tmp_path) -> bool:
    (tmp_path / "_probe.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract P { function f() public pure returns (uint){ return 1; } }\n")
    return _solc_ast(tmp_path / "_probe.sol") is not None


# a reentrancy that fires in solidity_audit
_VULN = """pragma solidity ^0.8.0;
contract Thing {
    mapping(address => uint) bal;
    function withdraw() public {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
"""
# an arbitrary-call that fires in arbitrary_call_audit
_ARB = """pragma solidity ^0.8.0;
contract Exec { function run(address target, bytes calldata data) external { target.call(data); } }
"""


def _files(findings):
    return {str(f.get("file", "")) for f in findings}


def test_mock_dir_skipped(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    (tmp_path / "src").mkdir(); (tmp_path / "src" / "Real.sol").write_text(_VULN)
    (tmp_path / "mock").mkdir(); (tmp_path / "mock" / "Fake.sol").write_text(_VULN)
    files = _files(solidity_audit(tmp_path))
    assert any("Real.sol" in f for f in files), files
    assert not any("mock" in f.lower() for f in files), f"mock/ dir must be skipped: {files}"


def test_test_dir_skipped(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    (tmp_path / "src").mkdir(); (tmp_path / "src" / "Real.sol").write_text(_VULN)
    (tmp_path / "test").mkdir(); (tmp_path / "test" / "Stuff.sol").write_text(_VULN)
    files = _files(solidity_audit(tmp_path))
    assert any("Real.sol" in f for f in files) and not any("/test/" in f or f.startswith("test/") for f in files), files


def test_mock_filename_skipped(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    (tmp_path / "MockToken.sol").write_text(_VULN)
    (tmp_path / "Real.sol").write_text(_VULN)
    files = _files(solidity_audit(tmp_path))
    assert any("Real.sol" in f for f in files) and not any("Mock" in f for f in files), files


def test_foundry_test_and_script_files_skipped(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    (tmp_path / "Counter.sol").write_text(_VULN)
    (tmp_path / "Counter.t.sol").write_text(_VULN)        # foundry test
    (tmp_path / "Deploy.s.sol").write_text(_VULN)         # foundry script
    files = _files(solidity_audit(tmp_path))
    assert any(f.endswith("Counter.sol") for f in files)
    assert not any(".t.sol" in f or ".s.sol" in f for f in files), files


def test_explicit_mock_file_still_analyzed(tmp_path):
    """A single mock file passed EXPLICITLY is analyzed (explicit intent overrides the skip)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    p = tmp_path / "MockToken.sol"
    p.write_text(_VULN)
    assert solidity_audit(p), "an explicitly-passed mock file must still be analyzed"


def test_economic_audit_skips_mock_dir(tmp_path):
    """The economic-tier audits (arbitrary_call/oracle/...) also skip mock/test dirs (they previously
    used a raw rglob with no filter — the Fei Test.deal / forge-std noise)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    (tmp_path / "src").mkdir(); (tmp_path / "src" / "Real.sol").write_text(_ARB)
    (tmp_path / "test").mkdir(); (tmp_path / "test" / "Harness.sol").write_text(_ARB)
    files = _files(arbitrary_call_audit(tmp_path))
    assert any("Real.sol" in f for f in files) and not any("test" in f.lower() for f in files), files
