"""Reentrancy findings should be ONE per (contract, function), not one per state-var written after the
call. The homology leg emitted a finding per surviving cell, so a write-heavy function (Morpho.liquidate
writes ~15 state vars after a call) produced ~15 identical-to-triage findings — pure noise. An auditor
reviews the function once. Recall-safe: one finding still flags the function.
"""
import pytest

from lattice.ingest.solidity import _solc_ast
from lattice.ingest.solidity_typed import typed_audit


def _parses(tmp_path) -> bool:
    (tmp_path / "_probe.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract P { function f() public pure returns (uint){ return 1; } }\n")
    return _solc_ast(tmp_path / "_probe.sol") is not None


_MULTI_WRITE = """pragma solidity ^0.8.0;
contract C {
    uint a; uint b; uint c; uint d;
    function f() public {
        uint x = a + b + c + d;                              // reads a,b,c,d
        (bool ok, ) = msg.sender.call{value: x}(""); require(ok);
        a = 1; b = 2; c = 3; d = 4;                          // 4 writes after the call
    }
}
"""


def test_homology_reentrancy_one_per_function(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    (tmp_path / "C.sol").write_text(_MULTI_WRITE)
    r = [f for f in typed_audit(str(tmp_path)) if f.get("kind") == "reentrancy" and f.get("function") == "f"]
    assert len(r) == 1, f"reentrancy must be one-per-function (4 writes -> 1 finding), got {len(r)}"
