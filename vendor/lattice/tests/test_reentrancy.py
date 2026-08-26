import shutil
import pytest
from lattice.ingest.solidity import reentrancy_findings

pytestmark = pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed")


def test_reentrancy_flagged_when_external_call_precedes_state_write(tmp_path):
    """CEI violation: an external call (.call) BEFORE the state update that guards re-entry
    is the reentrancy bug. The safe version (effect before interaction) must NOT flag."""
    (tmp_path / "Vuln.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vuln {\n"
        "    mapping(address => uint) public balances;\n"
        "    function withdraw() public {\n"
        "        uint amt = balances[msg.sender];\n"
        "        (bool ok,) = msg.sender.call{value: amt}(\"\");\n"   # interaction
        "        balances[msg.sender] = 0;\n"                          # effect AFTER -> bug
        "    }\n"
        "}\n")
    (tmp_path / "Safe.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Safe {\n"
        "    mapping(address => uint) public balances;\n"
        "    function withdraw() public {\n"
        "        uint amt = balances[msg.sender];\n"
        "        balances[msg.sender] = 0;\n"                          # effect FIRST
        "        (bool ok,) = msg.sender.call{value: amt}(\"\");\n"   # interaction after -> safe
        "    }\n"
        "}\n")
    findings = reentrancy_findings(str(tmp_path))
    flagged = {(f["contract"], f["function"]) for f in findings}
    assert ("Vuln", "withdraw") in flagged, findings
    assert ("Safe", "withdraw") not in flagged, findings
