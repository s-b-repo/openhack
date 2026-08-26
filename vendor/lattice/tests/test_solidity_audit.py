import shutil
import pytest
from lattice.ingest.solidity import solidity_audit

pytestmark = pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed")


def test_audit_finds_tx_origin_and_unprotected_critical(tmp_path):
    (tmp_path / "V.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract V {\n"
        "    address owner;\n"
        "    modifier onlyOwner() { require(msg.sender == owner); _; }\n"
        "    function auth() public view returns (bool) { return tx.origin == owner; }\n"   # tx.origin
        "    function nuke() public { selfdestruct(payable(owner)); }\n"                     # unprotected selfdestruct
        "    function safeNuke() public onlyOwner { selfdestruct(payable(owner)); }\n"       # protected -> no flag
        "    function proxy(address t, bytes calldata d) public { t.delegatecall(d); }\n"    # unprotected delegatecall
        "}\n")
    f = solidity_audit(str(tmp_path))
    kinds = {(x["kind"], x["function"]) for x in f}
    assert ("tx_origin_auth", "auth") in kinds, f
    assert ("unprotected_selfdestruct", "nuke") in kinds, f
    assert ("unprotected_selfdestruct", "safeNuke") not in kinds, f      # modifier guards it
    assert ("unprotected_delegatecall", "proxy") in kinds, f


def test_audit_includes_reentrancy(tmp_path):
    (tmp_path / "R.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract R {\n"
        "    mapping(address=>uint) bal;\n"
        "    function withdraw() public {\n"
        "        (bool ok,) = msg.sender.call{value: bal[msg.sender]}(\"\");\n"
        "        bal[msg.sender] = 0;\n"
        "    }\n"
        "}\n")
    assert any(x["kind"] == "reentrancy" for x in solidity_audit(str(tmp_path)))


def test_audit_unchecked_call_and_dos_loop(tmp_path):
    """P1: a low-level call whose return is discarded (bare ExpressionStatement). P2: an
    external transfer inside a loop (one revert griefs everyone). Both from the workflow's
    grounded specs. Captured returns and loop-free transfers must NOT flag."""
    (tmp_path / "U.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract U {\n"
        "    function bad(address payable to, uint a) public {\n"
        "        to.call{value: a}(\"\");\n"                              # unchecked (return dropped)
        "    }\n"
        "    function good(address payable to, uint a) public {\n"
        "        (bool ok,) = to.call{value: a}(\"\");\n"                 # captured -> safe
        "        require(ok);\n"
        "    }\n"
        "    function payAll(address[] calldata rs, uint a) public {\n"
        "        for (uint i=0; i<rs.length; i++) {\n"
        "            payable(rs[i]).send(a);\n"                            # external call in loop -> DoS
        "        }\n"
        "    }\n"
        "}\n")
    f = lambda: __import__("lattice.ingest.solidity", fromlist=["solidity_audit"]).solidity_audit(str(tmp_path))
    kinds = {(x["kind"], x["function"]) for x in f()}
    assert ("unchecked_external_call", "bad") in kinds, kinds
    assert ("unchecked_external_call", "good") not in kinds, kinds      # captured return
    assert ("dos_gas_griefing", "payAll") in kinds, kinds


def test_audit_recognizes_if_revert_and_modifier_guards_no_fp(tmp_path):
    """Adversarial FP fix: a sink guarded by `if(msg.sender!=admin) revert` or by a custom
    modifier must NOT be flagged. And `require(msg.sender==tx.origin)` is the SAFE anti-
    contract pattern, not a tx.origin auth bug."""
    (tmp_path / "G.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract G {\n"
        "    address admin;\n"
        "    function kill() public {\n"
        "        if (msg.sender != admin) revert();\n"          # inline guard
        "        selfdestruct(payable(admin));\n"
        "    }\n"
        "    function notAContract() public view returns (bool) {\n"
        "        require(msg.sender == tx.origin);\n"           # SAFE anti-contract check
        "        return true;\n"
        "    }\n"
        "}\n")
    from lattice.ingest.solidity import solidity_audit
    f = solidity_audit(str(tmp_path))
    kinds = {x["kind"] for x in f}
    assert "unprotected_selfdestruct" not in kinds, f      # if/revert guard recognized
    assert "tx_origin_auth" not in kinds, f                # msg.sender==tx.origin is safe


def test_audit_escalates_assembly_as_blind_spot(tmp_path):
    """Adversarial blind-spot honesty: a function with inline assembly can hide sinks the
    AST can't see — flag it as a blind spot rather than silently passing."""
    (tmp_path / "A.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract A {\n"
        "    function raw(address t, bytes calldata d) public {\n"
        "        assembly { let ok := call(gas(), t, 0, 0, 0, 0, 0) }\n"
        "    }\n"
        "}\n")
    from lattice.ingest.solidity import solidity_audit
    assert any(x["kind"] == "contains_assembly" for x in solidity_audit(str(tmp_path)))


def test_sheaf_reentrancy_catches_cross_function_and_kills_fp(tmp_path):
    """The obstruction firing: glue per-function read/write sections across the call graph.
    Catches helper-deferred reentrancy (write in a callee after the call) that per-function
    CEI misses, AND requires the written var to be READ before the call — so CEI-correct
    code with unrelated bookkeeping writes after the call does NOT false-positive."""
    from lattice.ingest.solidity import reentrancy_obstructions
    (tmp_path / "X.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vuln {\n"                                    # helper-deferred (cross-function)
        "    mapping(address=>uint) bal;\n"
        "    function withdraw() external {\n"
        "        uint a = bal[msg.sender];\n"                   # READ before
        "        (bool ok,) = msg.sender.call{value:a}(\"\");\n"
        "        _settle(msg.sender);\n"                        # write deferred to callee
        "    }\n"
        "    function _settle(address w) internal { bal[w] = 0; }\n"
        "}\n"
        "contract Safe {\n"                                    # CEI-correct + unrelated writes
        "    mapping(address=>uint) bal; uint count;\n"
        "    function withdraw() external {\n"
        "        uint a = bal[msg.sender];\n"
        "        bal[msg.sender] = 0;\n"                        # effect FIRST
        "        (bool ok,) = msg.sender.call{value:a}(\"\");\n"
        "        count = count + 1;\n"                          # unrelated write AFTER (not read before)
        "    }\n"
        "}\n")
    obs = reentrancy_obstructions(str(tmp_path))
    flagged = {o["contract"] for o in obs}
    assert "Vuln" in flagged, obs            # cross-function obstruction caught
    assert "Safe" not in flagged, obs        # no FP: bal written before call; count not read-before


def _kinds(tmp_path):
    return {f["kind"] for f in solidity_audit(str(tmp_path))}


def test_audit_old_style_call_value_unchecked(tmp_path):
    """CORPUS FN: pre-0.8 `addr.call.value(x)()` as a discarded-return statement must be caught."""
    (tmp_path / "U.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract U { function pay(address a) public { a.call.value(1)(); } }\n")
    assert "unchecked_external_call" in _kinds(tmp_path)


def test_audit_unprotected_authority_write(tmp_path):
    """access_control: a public fn setting owner with no guard (SWC-105/118)."""
    (tmp_path / "A.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract A { address owner; function setOwner(address o) public { owner = o; } }\n")
    assert "unprotected_state_write" in _kinds(tmp_path)


def test_audit_weak_randomness(tmp_path):
    """bad_randomness: a block property used as a randomness seed (SWC-120)."""
    (tmp_path / "R.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract R { function win() public view returns (uint) { return uint(block.timestamp) % 100; } }\n")
    assert "weak_randomness" in _kinds(tmp_path)


def test_audit_dos_unbounded_loop(tmp_path):
    """denial_of_service: a state array grown inside a loop."""
    (tmp_path / "D.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract D { address[] xs; function fill() public { for (uint i=0;i<350;i++){ xs.push(msg.sender); } } }\n")
    assert "dos_unbounded_loop" in _kinds(tmp_path)


def test_audit_unchecked_arithmetic_pre08(tmp_path):
    """arithmetic: pre-0.8 state-var arithmetic with no SafeMath (SWC-101)."""
    (tmp_path / "M.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract M { mapping(address=>uint) bal; function add(uint a) public { bal[msg.sender] += a; } }\n")
    assert "unchecked_arithmetic" in _kinds(tmp_path)


def test_audit_modern_arithmetic_not_flagged(tmp_path):
    """FP control: 0.8+ has built-in overflow checks — no unchecked_arithmetic finding."""
    (tmp_path / "N.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract N { mapping(address=>uint) bal; function add(uint a) public { bal[msg.sender] += a; } }\n")
    assert "unchecked_arithmetic" not in _kinds(tmp_path)
