"""ACCESS-CONTROL + TARGET-TRUST downgrade (cold Fei FP reduction, recall-safe).

The cold Fei run's remaining FPs were dominated by access-control blindness (reentrancy/oracle behind
onlyGovernor / require(msg.sender==admin)) and target-trust (an arbitrary call whose target is allow-list
validated). These are DOWNGRADED to low confidence — NOT suppressed — so no silent-FN: a real bug behind a
(possibly bypassable) gate still surfaces, just deprioritized. The load-bearing guarantee: a PERMISSIONLESS
bug (the cold not-so-smart-contracts class) stays HIGH.
"""
import pytest

from lattice.ingest.solidity import solidity_audit, _solc_ast
from lattice.ingest.solidity_taint import oracle_taint_audit
from lattice.ingest.solidity_arbitrary_call import arbitrary_call_audit


def _parses(tmp_path) -> bool:
    (tmp_path / "_probe.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract P { function f() public pure returns (uint){ return 1; } }\n")
    return _solc_ast(tmp_path / "_probe.sol") is not None


def _write(tmp_path, sub, src):
    d = tmp_path / sub
    d.mkdir()
    (d / "C.sol").write_text(src)
    return d


_REENTRANT_AC = """pragma solidity ^0.8.0;
contract C {
    mapping(address => uint) bal; address gov;
    modifier onlyGovernor(){ require(msg.sender == gov, "!gov"); _; }
    function withdraw() public onlyGovernor {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
"""
_REENTRANT_OPEN = """pragma solidity ^0.8.0;
contract C {
    mapping(address => uint) bal;
    function withdraw() public {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
"""
_REENTRANT_SENDER_REQUIRE = """pragma solidity ^0.8.0;
contract C {
    mapping(address => uint) bal; address admin;
    function withdraw() public {
        require(msg.sender == admin, "Call must come from admin.");
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
"""


def test_reentrancy_access_controlled_downgraded(tmp_path):
    """A reentrancy behind onlyGovernor is only reachable by the governor — downgrade to low."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in solidity_audit(_write(tmp_path, "ac", _REENTRANT_AC)) if f["kind"] == "reentrancy"]
    assert r and all(f.get("confidence") == "low" and f["severity"] == "low" for f in r), r


def test_reentrancy_sender_require_downgraded(tmp_path):
    """A reentrancy behind a body-level require(msg.sender == admin) is also access-gated (Fei Timelock)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in solidity_audit(_write(tmp_path, "sr", _REENTRANT_SENDER_REQUIRE)) if f["kind"] == "reentrancy"]
    assert r and all(f.get("confidence") == "low" for f in r), r


_REENTRANT_BENEFICIARY = """pragma solidity ^0.8.0;
contract C {
    mapping(address => uint) bal; address beneficiary;
    modifier onlyBeneficiary(){ require(msg.sender == beneficiary); _; }
    function undelegate() public onlyBeneficiary {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
"""


def test_reentrancy_beneficiary_role_downgraded(tmp_path):
    """`onlyBeneficiary` is authorization (the Fei undelegate FP) — a DeFi access role beyond owner/gov."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in solidity_audit(_write(tmp_path, "ben", _REENTRANT_BENEFICIARY)) if f["kind"] == "reentrancy"]
    assert r and all(f.get("confidence") == "low" for f in r), r


def test_reentrancy_permissionless_stays_high(tmp_path):
    """The recall guarantee: a PERMISSIONLESS reentrancy (the cold known-bug class) stays HIGH."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in solidity_audit(_write(tmp_path, "open", _REENTRANT_OPEN)) if f["kind"] == "reentrancy"]
    assert r and all(f["severity"] == "high" and f.get("confidence") != "low" for f in r), r


_REENTRANT_INTERNAL_AC = """pragma solidity ^0.8.0;
contract C {
    mapping(address => uint) bal; address gov;
    modifier onlyGovernor(){ require(msg.sender == gov); _; }
    function addDeposit() external onlyGovernor { _addDeposit(); }   // only governor reaches the internal fn
    function _addDeposit() internal {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
"""
_REENTRANT_INTERNAL_OPEN = """pragma solidity ^0.8.0;
contract C {
    mapping(address => uint) bal;
    function deposit() external { _addDeposit(); }                   // PERMISSIONLESS reaches the internal fn
    function _addDeposit() internal {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
"""


def test_reentrancy_internal_only_reached_by_access_control_downgraded(tmp_path):
    """INTERPROCEDURAL access control: an internal function reachable ONLY via an onlyGovernor entry
    (the Fei CollateralizationOracle._addDeposit residual) is effectively access-controlled — downgrade."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in solidity_audit(_write(tmp_path, "intac", _REENTRANT_INTERNAL_AC)) if f["kind"] == "reentrancy"]
    assert r and all(f.get("confidence") == "low" for f in r), r


def test_reentrancy_internal_reached_by_permissionless_stays_high(tmp_path):
    """The recall guarantee: an internal function reachable from a PERMISSIONLESS external entry stays
    HIGH — a missed-edge / wrong downgrade would bury a real bug."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in solidity_audit(_write(tmp_path, "intopen", _REENTRANT_INTERNAL_OPEN)) if f["kind"] == "reentrancy"]
    assert r and all(f.get("confidence") != "low" for f in r), r


_REENTRANT_INTERNAL_MIXED = """pragma solidity ^0.8.0;
contract C {
    mapping(address => uint) bal; address gov;
    modifier onlyGovernor(){ require(msg.sender == gov); _; }
    function adminPath() external onlyGovernor { _withdraw(); }
    function publicPath() external { _withdraw(); }                  // a PERMISSIONLESS path ALSO reaches it
    function _withdraw() internal {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
"""


def test_reentrancy_internal_mixed_reachability_stays_high(tmp_path):
    """If ANY permissionless path reaches the internal function, it stays HIGH — the access-controlled
    path does not make it safe (the recall-critical case for the reachability logic)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in solidity_audit(_write(tmp_path, "mixed", _REENTRANT_INTERNAL_MIXED))
         if f["kind"] == "reentrancy" and f["function"] == "_withdraw"]
    assert r and all(f.get("confidence") != "low" for f in r), r


_REENTRANT_USER_ROLE = """pragma solidity ^0.8.0;
contract Channel {
    mapping(address => uint) bal; address partyA;
    function reclaim() public {
        require(msg.sender == partyA, "only partyA");   // a USER role, NOT a trust boundary
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
"""


def test_reentrancy_user_role_sender_check_stays_high(tmp_path):
    """The SpankChain lesson: `require(msg.sender == partyA)` is NOT a trust boundary — the attacker can
    BE partyA. A user-role sender check must NOT downgrade a real reentrancy (no silent-by-deprioritize)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in solidity_audit(_write(tmp_path, "usr", _REENTRANT_USER_ROLE)) if f["kind"] == "reentrancy"]
    assert r and all(f.get("confidence") != "low" for f in r), \
        f"a user-role sender check is not a trust boundary — must stay HIGH: {r}"


# ── oracle behind access control ──
_ORACLE_AC = """pragma solidity ^0.8.0;
interface IPair { function getReserves() external view returns (uint112,uint112,uint32); }
contract Lend {
    IPair pair; address gov;
    modifier onlyGovernor(){ require(msg.sender == gov); _; }
    function rebalance(address payable to) public onlyGovernor {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint price = uint(r0) * 1e18 / uint(r1);
        require(price > 1000); to.transfer(price);
    }
}
"""
_ORACLE_OPEN = _ORACLE_AC.replace(" onlyGovernor {", " {").replace("modifier onlyGovernor(){ require(msg.sender == gov); _; }\n", "")


def test_oracle_access_controlled_downgraded(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in oracle_taint_audit(_write(tmp_path, "oac", _ORACLE_AC)) if f["kind"] == "untrusted_flow"]
    assert r and all(f.get("confidence") == "low" for f in r), r


def test_oracle_permissionless_stays_high(tmp_path):
    """A permissionless spot-priced loan (the puppet class) stays a real finding."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in oracle_taint_audit(_write(tmp_path, "oopen", _ORACLE_OPEN)) if f["kind"] == "untrusted_flow"]
    assert r and any(f.get("confidence") != "low" for f in r), r


# ── arbitrary_call to an ALLOW-LIST validated target ──
_ARB_ALLOWLISTED = """pragma solidity ^0.8.0;
contract Registry {
    mapping(address => bool) public allowed;
    function exec(address target, bytes calldata data) external {
        require(allowed[target], "not allowlisted");
        target.call(data);
    }
}
"""
_ARB_OPEN = """pragma solidity ^0.8.0;
contract Registry {
    function exec(address target, bytes calldata data) external {
        target.call(data);
    }
}
"""


def test_arbitrary_call_allowlisted_target_downgraded(tmp_path):
    """A call whose target param is validated by require(allowed[target]) is allow-list gated (Fei
    PCVSentinel) — downgrade, not the full truster severity."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in arbitrary_call_audit(_write(tmp_path, "arbal", _ARB_ALLOWLISTED)) if f["kind"] == "arbitrary_external_call"]
    assert all(f.get("confidence") == "low" for f in r), r


def test_arbitrary_call_unvalidated_target_stays_high(tmp_path):
    """The recall guarantee: an unvalidated attacker-target (truster) stays HIGH."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    r = [f for f in arbitrary_call_audit(_write(tmp_path, "aropen", _ARB_OPEN)) if f["kind"] == "arbitrary_external_call"]
    assert r and all(f.get("confidence") != "low" for f in r), r
