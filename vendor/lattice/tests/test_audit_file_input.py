"""solidity_audit / typed_audit / reentrancy_obstructions must accept a single FILE path, not only a
directory. They glob with rglob("*.sol") internally, which silently returns EMPTY on a file path — so an
audit of one file returned [] with no error, which reads as "no bugs found" (the measurement hazard that
made a cold recall test mis-measure to zero). The economic-tier audits already handle is_file(); these
structural/typed legs must too. File input and dir-with-only-that-file input must agree.
"""
import pytest

from lattice.ingest.solidity import solidity_audit, reentrancy_obstructions, _solc_ast
from lattice.ingest.solidity_typed import typed_audit

_REENTRANT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Reentrance {
    mapping(address => uint) bal;
    function deposit() public payable { bal[msg.sender] += msg.value; }
    function withdraw() public {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}("");   // external call ...
        require(ok);
        bal[msg.sender] = 0;                                          // ... state write AFTER -> reentrancy
    }
}
"""


def _parses(tmp_path) -> bool:
    (tmp_path / "_probe.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract P { function f() public pure returns (uint){ return 1; } }\n")
    return _solc_ast(tmp_path / "_probe.sol") is not None


def test_solidity_audit_accepts_file(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    f = tmp_path / "R.sol"
    f.write_text(_REENTRANT)
    on_file = solidity_audit(f)
    assert any(x["kind"] == "reentrancy" for x in on_file), \
        f"a single-file audit must find the bug, not silently return []; got {on_file}"


def test_typed_audit_accepts_file(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    f = tmp_path / "R.sol"
    f.write_text(_REENTRANT)
    assert any(x.get("kind") == "reentrancy" for x in typed_audit(str(f)))


def test_reentrancy_obstructions_accepts_file(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    f = tmp_path / "R.sol"
    f.write_text(_REENTRANT)
    assert any(x.get("kind") == "reentrancy" for x in reentrancy_obstructions(f))


def test_file_and_dir_agree(tmp_path):
    """A file path and a directory containing only that file must yield the same finding kinds."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    d = tmp_path / "sub"
    d.mkdir()
    (d / "R.sol").write_text(_REENTRANT)
    on_file = {x["kind"] for x in solidity_audit(d / "R.sol")}
    on_dir = {x["kind"] for x in solidity_audit(d)}
    assert on_file and on_file == on_dir, f"file {on_file} != dir {on_dir}"
