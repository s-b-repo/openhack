"""The typed reentrancy leg must not treat a low-level ETH `.transfer`/`.send` as a reentrancy boundary:
it forwards a fixed 2300-gas stipend, so the callee CANNOT make another call or write storage — it is
provably reentrancy-safe (the structural leg already excludes them via _REENTRANT_CALLS={call,delegatecall}).
But a high-level `token.transfer(to, amount)` (2 args) is an ERC20 method call at FULL gas that CAN reenter
(ERC777 hooks) — it must stay a boundary. The argument count discriminates them (1-arg = ETH send, 2-arg =
ERC20). Recall-safe: real reentrancy uses `.call{value:}` / a gas-forwarding call, never a 2300-gas send.
"""
import pytest

from lattice.ingest.solidity import _solc_ast
from lattice.ingest.solidity_typed import typed_audit


def _parses(tmp_path) -> bool:
    (tmp_path / "_probe.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract P { function f() public pure returns (uint){ return 1; } }\n")
    return _solc_ast(tmp_path / "_probe.sol") is not None


def _audit(tmp_path, src):
    (tmp_path / "C.sol").write_text(src)
    return [f for f in typed_audit(str(tmp_path)) if f.get("kind") == "reentrancy"]


def test_lowlevel_eth_transfer_not_reentrancy(tmp_path):
    """`payable(x).transfer(amt)` (1 arg) forwards 2300 gas — cannot reenter — NOT a reentrancy boundary."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    src = ("pragma solidity ^0.8.0;\ncontract C { mapping(address => uint) bal;\n"
           "  function withdraw() public {\n"
           "    uint amt = bal[msg.sender];\n"
           "    payable(msg.sender).transfer(amt);\n"     # 2300-gas ETH send
           "    bal[msg.sender] = 0; } }\n")
    assert _audit(tmp_path, src) == [], "low-level .transfer (2300 gas) cannot reenter"


def test_lowlevel_eth_send_not_reentrancy(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    src = ("pragma solidity ^0.8.0;\ncontract C { mapping(address => uint) bal;\n"
           "  function withdraw() public {\n"
           "    uint amt = bal[msg.sender];\n"
           "    payable(msg.sender).send(amt);\n"
           "    bal[msg.sender] = 0; } }\n")
    assert _audit(tmp_path, src) == [], "low-level .send (2300 gas) cannot reenter"


def test_erc20_transfer_stays_reentrancy(tmp_path):
    """`token.transfer(to, amt)` (2 args) is a full-gas ERC20 call — CAN reenter (ERC777) — stays flagged."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    src = ("pragma solidity ^0.8.0;\n"
           "interface IERC20 { function transfer(address,uint) external returns (bool); }\n"
           "contract C { mapping(address => uint) bal; IERC20 token;\n"
           "  function withdraw() public {\n"
           "    uint amt = bal[msg.sender];\n"
           "    token.transfer(msg.sender, amt);\n"        # full-gas ERC20, can reenter
           "    bal[msg.sender] = 0; } }\n")
    assert _audit(tmp_path, src), "ERC20 token.transfer can reenter — must stay flagged"


def test_lowlevel_call_stays_reentrancy(tmp_path):
    """The classic `.call{value:}` is gas-forwarding — stays a boundary (recall guard)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    src = ("pragma solidity ^0.8.0;\ncontract C { mapping(address => uint) bal;\n"
           "  function withdraw() public {\n"
           "    (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(\"\"); require(ok);\n"
           "    bal[msg.sender] = 0; } }\n")
    assert _audit(tmp_path, src), ".call{value:} is gas-forwarding — must stay flagged"
