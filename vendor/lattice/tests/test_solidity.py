import shutil
import pytest
from lattice.ingest.solidity import solidity_ingest

_HAS_SOLC = shutil.which("solc") is not None
pytestmark = pytest.mark.skipif(not _HAS_SOLC, reason="solc not installed")


def test_solidity_ingest_contracts_functions_inheritance_and_external_call(tmp_path):
    """A Solidity adapter: contracts -> class vertices, functions -> methods (public/
    external = the inbound boundary), `is Base` -> inheritance, and a low-level external
    call (.call/.transfer) -> an outbound-boundary reference (where reentrancy lives)."""
    (tmp_path / "Vault.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract Base { function tag() internal pure returns (uint) { return 1; } }\n"
        "contract Vault is Base {\n"
        "    mapping(address => uint) public balances;\n"
        "    function withdraw() public {\n"
        "        uint amt = balances[msg.sender];\n"
        "        (bool ok, ) = msg.sender.call{value: amt}(\"\");\n"
        "        require(ok);\n"
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "}\n")
    raw = solidity_ingest(tmp_path)
    names = {s.name for s in raw.symbols}
    assert {"Base", "Vault", "withdraw"} <= names, names
    vault = next(s for s in raw.symbols if s.name == "Vault")
    assert "Base" in vault.extends, vault.extends            # inheritance captured
    withdraw = next(s for s in raw.symbols if s.name == "withdraw")
    assert withdraw.exported and withdraw.kind == "method"   # public -> inbound boundary
    # the msg.sender.call is an external handoff -> an unresolved outbound reference
    assert any(r.kind == "references" and r.to_file is None and not r.resolved
               for r in raw.references), [r.__dict__ for r in raw.references]
