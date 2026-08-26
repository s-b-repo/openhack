"""Regression tests pinning the corpus-detection-audit's ranked gap fixes.

Each test encodes ONE structural idiom the SWC corpus exercised that the analyzer
previously went blind to (or only escalated a blindspot for). Written test-first;
each must FAIL before the corresponding fix lands."""
import shutil
import pytest
from lattice.ingest.solidity import solidity_audit

pytestmark = pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed")


def _kinds(tmp_path):
    return {f["kind"] for f in solidity_audit(str(tmp_path))}


def _reentrancy(tmp_path):
    return [f for f in solidity_audit(str(tmp_path)) if f["kind"] == "reentrancy"]


# ── Fix #4: storage-pointer alias ────────────────────────────────────────────
def test_reentrancy_through_storage_pointer_alias(tmp_path):
    """`Account storage acc = accounts[msg.sender]; ... acc.balance -= amt` mutates the
    SAME slot as accounts[msg.sender] — a storage reference, not a copy. The write-after-call
    must be seen through the alias."""
    (tmp_path / "Bank.sol").write_text(
        "pragma solidity ^0.6.0;\n"
        "contract Bank {\n"
        "    struct Account { uint balance; }\n"
        "    mapping(address => Account) accounts;\n"
        "    function withdraw(uint amt) public {\n"
        "        Account storage acc = accounts[msg.sender];\n"
        "        require(acc.balance >= amt);\n"
        "        (bool ok,) = msg.sender.call{value: amt}(\"\");\n"
        "        acc.balance -= amt;\n"
        "    }\n"
        "}\n")
    assert _reentrancy(tmp_path), "storage-pointer-aliased write-after-call not detected"


# ── legacy .call.value() must reach the OBSTRUCTION engine, not just the flat leg ──
def test_reentrancy_legacy_call_value_in_obstruction(tmp_path):
    """Pre-0.8 `msg.sender.call.value(amt)()` is the dominant historical external-call form;
    the sheaf-obstruction engine (_fn_effects) must recognise it as an external boundary."""
    (tmp_path / "Old.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Old {\n"
        "    mapping(address => uint) bal;\n"
        "    function withdraw() public {\n"
        "        uint amt = bal[msg.sender];\n"
        "        require(msg.sender.call.value(amt)());\n"
        "        bal[msg.sender] = 0;\n"
        "    }\n"
        "}\n")
    assert _reentrancy(tmp_path), "legacy .call.value() not seen by obstruction engine"


# ── Fix #8: interprocedural — external call lives in a callee ─────────────────
def test_reentrancy_external_call_in_callee(tmp_path):
    """The external call is made by a helper the public fn invokes BEFORE its state write.
    The callee's external boundary must lift to the call site."""
    (tmp_path / "Inter.sol").write_text(
        "pragma solidity ^0.6.0;\n"
        "contract Inter {\n"
        "    mapping(address => uint) bal;\n"
        "    function _send(address to, uint amt) internal {\n"
        "        (bool ok,) = to.call{value: amt}(\"\");\n"
        "        require(ok);\n"
        "    }\n"
        "    function withdraw() public {\n"
        "        uint amt = bal[msg.sender];\n"
        "        _send(msg.sender, amt);\n"
        "        bal[msg.sender] = 0;\n"
        "    }\n"
        "}\n")
    assert _reentrancy(tmp_path), "external call inside a callee not lifted to call site"


# ── Fix #9: modifier-embedded external call ──────────────────────────────────
def test_reentrancy_external_call_in_modifier(tmp_path):
    """A modifier runs an external callback around `_`; the state write after `_` is reentrant."""
    (tmp_path / "Mod.sol").write_text(
        "pragma solidity ^0.6.0;\n"
        "contract Mod {\n"
        "    mapping(address => uint) bal;\n"
        "    modifier notify() {\n"
        "        (bool ok,) = msg.sender.call{value: 0}(\"\");\n"
        "        _;\n"
        "    }\n"
        "    function withdraw() public notify {\n"
        "        uint amt = bal[msg.sender];\n"
        "        bal[msg.sender] = amt - 1;\n"
        "    }\n"
        "}\n")
    assert _reentrancy(tmp_path), "external call embedded in a modifier not inlined"


# ── Fix #6-other: uninitialized storage pointer ──────────────────────────────
def test_uninitialized_storage_pointer(tmp_path):
    """A local `T storage p;` with no initializer aliases slot 0 — writing through it
    corrupts whatever lives at the low slots (classic pre-0.5 footgun, SWC-109)."""
    (tmp_path / "Uninit.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Uninit {\n"
        "    struct Bid { uint amount; address who; }\n"
        "    address public owner;\n"
        "    function bid() public {\n"
        "        Bid storage b;\n"
        "        b.amount = 1;\n"
        "        b.who = msg.sender;\n"
        "    }\n"
        "}\n")
    assert "uninitialized_storage_pointer" in _kinds(tmp_path)


def test_uninitialized_storage_pointer_implicit_pre05(tmp_path):
    """The REAL corpus idiom (name_registrar.sol): a pre-0.5 struct local with NO `storage`
    keyword is IMPLICITLY a storage pointer (storageLocation 'default'). This is the actual
    footgun — the developer forgot it defaults to storage, not memory."""
    (tmp_path / "Reg.sol").write_text(
        "pragma solidity ^0.4.15;\n"
        "contract Reg {\n"
        "    struct Record { address who; }\n"
        "    mapping(address => Record) public records;\n"
        "    function register(address a) public {\n"
        "        Record newRecord;\n"
        "        newRecord.who = a;\n"
        "        records[msg.sender] = newRecord;\n"
        "    }\n"
        "}\n")
    assert "uninitialized_storage_pointer" in _kinds(tmp_path)


def test_value_type_local_not_flagged_as_storage_pointer(tmp_path):
    """FP control: a plain `uint x;` local is a stack value, never a storage pointer."""
    (tmp_path / "Val.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Val { function f() public pure returns (uint) { uint x; return x; } }\n")
    assert "uninitialized_storage_pointer" not in _kinds(tmp_path)


# ── SWC-116: timestamp-dependence (distinct from randomness-modulo) ──────────
def test_timestamp_dependence_gates_transfer(tmp_path):
    """block.timestamp used in a require/if that gates a value transfer — manipulable by
    the miner within ~15s (SWC-116). Distinct from the modulo-seed randomness case."""
    (tmp_path / "Lock.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Lock {\n"
        "    uint deadline;\n"
        "    function claim() public {\n"
        "        require(block.timestamp > deadline);\n"
        "        payable(msg.sender).transfer(address(this).balance);\n"
        "    }\n"
        "}\n")
    assert "timestamp_dependence" in _kinds(tmp_path)


def test_timestamp_dependence_not_flagged_without_gate(tmp_path):
    """FP control: storing block.timestamp as a record (not gating control flow) is benign."""
    (tmp_path / "Stamp.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Stamp {\n"
        "    uint public lastSeen;\n"
        "    function ping() public { lastSeen = block.timestamp; }\n"
        "}\n")
    assert "timestamp_dependence" not in _kinds(tmp_path)


# ════════════════════════════════════════════════════════════════════════════
# FIXES from the fresh-GitHub generalization audit (ToB + DVD adversarial pass)
# ════════════════════════════════════════════════════════════════════════════

# ── #1 parse failure must ESCALATE, never silently skip (no-silent-FN footing) ──
def test_parse_failure_escalates_not_silent(tmp_path):
    """A file that fails to parse under every installed solc must surface a LOUD
    blindspot — not return byte-identical output to a genuinely clean contract.
    (The DAO / Parity WalletLibrary / SpankChain currently vanish silently.)"""
    (tmp_path / "Broken.sol").write_text(
        "pragma solidity ^0.4.19;\n"
        "contract Broken { function f() public { uint a = ; } }\n")  # syntax error: no RHS
    assert "parse_failure" in _kinds(tmp_path)


def test_clean_contract_has_no_parse_failure(tmp_path):
    """FP control: a normal parseable contract must NOT carry a parse_failure finding."""
    (tmp_path / "Fine.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Fine { uint x; function set(uint v) public { x = v; } }\n")
    assert "parse_failure" not in _kinds(tmp_path)


# ── #2 correctly-named 0.4.x constructor is NOT a public takeover ──────────────
def test_correctly_named_constructor_not_takeover(tmp_path):
    """`function Owned()` inside `contract Owned` is the constructor — runs once at
    deploy, not publicly callable. Firing 'anyone can become owner' is a false positive."""
    (tmp_path / "Owned.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Owned { address owner; function Owned() public { owner = msg.sender; } }\n")
    assert "unprotected_state_write" not in _kinds(tmp_path)


def test_misnamed_constructor_still_flagged(tmp_path):
    """The REAL wrong-constructor bug (Rubixi): function name != contract name, so it is a
    normal public function anyone can call to seize ownership — must STAY caught."""
    (tmp_path / "Rubixi.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Rubixi { address owner; function DynamicPyramid() public { owner = msg.sender; } }\n")
    assert "unprotected_state_write" in _kinds(tmp_path)


# ── #3 uninitialized_storage_pointer must be pragma-gated to <0.5 ──────────────
def test_uninit_storage_pointer_pragma_gated(tmp_path):
    """In solc >=0.5 a default-location reference local is a COMPILE ERROR, and in
    parse-mode 'default' merely means 'unresolved' — so it must NOT fire on modern code."""
    (tmp_path / "Modern.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "interface IERC20 { function transfer(address,uint256) external; }\n"
        "contract Modern { function f() public { IERC20 token; } }\n")
    assert "uninitialized_storage_pointer" not in _kinds(tmp_path)


# ── #4 gas-limited .transfer/.send cannot reenter (2300-gas stipend) ───────────
def test_transfer_then_write_is_not_reentrancy(tmp_path):
    """`.transfer()` forwards only 2300 gas — the callee cannot make another call or write
    storage, so a write after it is NOT reentrant. Flagging it mislabels safe/DoS code."""
    (tmp_path / "Xfer.sol").write_text(
        "pragma solidity ^0.6.0;\n"
        "contract Xfer { mapping(address=>uint) bal; function w() public {\n"
        "    uint a = bal[msg.sender]; payable(msg.sender).transfer(a); bal[msg.sender] = 0; } }\n")
    assert "reentrancy" not in _kinds(tmp_path)


def test_call_then_write_still_reentrancy(tmp_path):
    """Control: `.call{value:}` forwards all gas — write-after IS reentrant, must stay caught."""
    (tmp_path / "Cal.sol").write_text(
        "pragma solidity ^0.6.0;\n"
        "contract Cal { mapping(address=>uint) bal; function w() public {\n"
        "    uint a = bal[msg.sender]; (bool ok,) = msg.sender.call{value:a}(\"\"); bal[msg.sender] = 0; } }\n")
    assert "reentrancy" in _kinds(tmp_path)


# ── auth-guard precision: a param NAMED _owner is not an access guard ──────────
def test_param_named_owner_is_not_an_access_guard(tmp_path):
    """`require(_owner != 0)` is a null-check; the parameter name '_owner' must NOT mark the
    function as access-protected. The unprotected authority write must STILL fire (this is the
    real multiowned_vulnerable bug, previously masked by a substring-'owner' false guard)."""
    (tmp_path / "Multi.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Multi { mapping(address=>address) owners;\n"
        "  function newOwner(address _owner) external { require(_owner != 0); owners[_owner] = msg.sender; } }\n")
    assert "unprotected_state_write" in _kinds(tmp_path)


def test_real_msgsender_guard_still_suppresses(tmp_path):
    """Control: a genuine `require(msg.sender == admin)` guard DOES protect the write."""
    (tmp_path / "Guarded.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Guarded { address admin; address owner;\n"
        "  function setOwner(address o) public { require(msg.sender == admin); owner = o; } }\n")
    assert "unprotected_state_write" not in _kinds(tmp_path)


# ── parse ROBUSTNESS: recover the analyzable parse-fails (don't just flag them) ──
def test_exact_pin_uncached_version_recovered(tmp_path):
    """`pragma solidity 0.4.15;` (not in the solc cache) must route to a nearby 0.4.x with the
    pragma relaxed — SpankChain's case. It should be ANALYZED, not left a parse_failure."""
    (tmp_path / "Pin.sol").write_text(
        "pragma solidity 0.4.15;\n"
        "contract Pin { uint x; function set(uint v) public { var y = v; x = y; } }\n")  # `var`: 0.4-only
    assert "parse_failure" not in _kinds(tmp_path)


def test_no_pragma_old_contract_recovered(tmp_path):
    """A contract with NO pragma and pre-0.5 syntax (`constant` fn, same-name constructor) must
    fall back to an old compiler — theRun/Lottery's case — not parse-fail under default 0.8.x."""
    (tmp_path / "NoPragma.sol").write_text(
        "contract NoPragma { uint y;\n"
        "  function NoPragma() public { y = 1; }\n"
        "  function foo() constant returns (uint) { return y; } }\n")
    assert "parse_failure" not in _kinds(tmp_path)


# ── SafeMath presence must NOT blanket-suppress raw arithmetic (SolidiFI Overflow) ──
def test_raw_arithmetic_in_safemath_contract_flagged(tmp_path):
    """A contract that imports SafeMath but does a RAW `+=` on a state var is still unchecked
    there — SafeMath only protects ops routed through .add()/.sub(). A blanket 'contains SafeMath
    → safe' gate hides exactly the bug SolidiFI injects into ERC20 tokens (27/50 were suppressed)."""
    (tmp_path / "Tok.sol").write_text(
        "pragma solidity ^0.5.0;\n"
        "library SafeMath { function add(uint a, uint b) internal pure returns (uint) { return a + b; } }\n"
        "contract Tok { using SafeMath for uint; mapping(address=>uint) bal;\n"
        "  function buggy(uint x) public { bal[msg.sender] += x; } }\n")   # raw +=, NOT .add
    assert "unchecked_arithmetic" in _kinds(tmp_path)


# ── reentrancy through the 0.4.x `var` implicit storage alias (7 mainnet contracts) ──
def test_reentrancy_through_var_storage_alias_pre05(tmp_path):
    """0.4.x `var acc = Acc[msg.sender]` is an IMPLICIT storage pointer (storageLocation
    'default'); `acc.balance -= _am` after an external call mutates Acc — reentrant. This is
    the exact idiom in the 7 missed mainnet smartbugs reentrancy contracts (U_BANK et al.)."""
    (tmp_path / "UBank.sol").write_text(
        "pragma solidity ^0.4.19;\n"
        "contract UBank {\n"
        "  struct A { uint balance; }\n"
        "  mapping(address => A) public Acc;\n"
        "  function Collect(uint _am) public {\n"
        "    var acc = Acc[msg.sender];\n"
        "    if (acc.balance >= _am) {\n"
        "      if (msg.sender.call.value(_am)()) { acc.balance -= _am; }\n"
        "    }\n"
        "  }\n"
        "}\n")
    assert _reentrancy(tmp_path), "0.4.x var storage-pointer alias reentrancy not detected"


# ── modifier-embedded HIGH-LEVEL external call (the real modifier_reentrancy.sol) ──
def test_reentrancy_highlevel_call_in_modifier(tmp_path):
    """A modifier that calls a method on a msg.sender-derived CONTRACT (`Bank(msg.sender).f()`)
    before `_` hands control to an attacker; the body's read+written state var is reentrant.
    This is the exact SWC modifier_reentrancy idiom — a HIGH-LEVEL call, not low-level."""
    (tmp_path / "ModEntr.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract ModEntr {\n"
        "  mapping(address => uint) public tokenBalance;\n"
        "  function airDrop() hasNoBalance supportsToken public { tokenBalance[msg.sender] += 20; }\n"
        "  modifier supportsToken() { require(keccak256('X') == Bank(msg.sender).supportsToken()); _; }\n"
        "  modifier hasNoBalance() { require(tokenBalance[msg.sender] == 0); _; }\n"
        "}\n"
        "contract Bank { function supportsToken() external pure returns (bytes32) { return keccak256('X'); } }\n")
    assert _reentrancy(tmp_path), "high-level external call in a modifier not detected"


def test_onlyowner_modifier_not_flagged_reentrant(tmp_path):
    """FP control: a plain `require(msg.sender == owner)` modifier makes NO external call —
    a guarded write must not be called reentrant."""
    (tmp_path / "Own.sol").write_text(
        "pragma solidity ^0.6.0;\n"
        "contract Own { address owner; uint x;\n"
        "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
        "  function set(uint v) public onlyOwner { x = v; } }\n")
    assert not _reentrancy(tmp_path), "onlyOwner modifier wrongly flagged reentrant"



# ════════════════════════════════════════════════════════════════════════════
# "do all of them" — the remaining BUILDABLE structural SWC detectors
# ════════════════════════════════════════════════════════════════════════════

# ── SWC-132 forced ether: strict equality on this.balance ─────────────────────
def test_forced_ether_balance_invariant(tmp_path):
    """`this.balance == X` (SWC-132): an attacker force-sends ether via selfdestruct to break
    the invariant — balance can only be assumed >=, never ==. (coin.sol:180)"""
    (tmp_path / "Game.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Game { function finalize() public { if (this.balance == 10 ether) { msg.sender.transfer(1); } } }\n")
    assert "forced_ether_invariant" in _kinds(tmp_path)


def test_balance_ge_not_flagged_forced_ether(tmp_path):
    """FP control: `require(this.balance >= amount)` is a legitimate sufficiency check."""
    (tmp_path / "Ok.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Ok { function w(uint a) public { require(address(this).balance >= a);"
        " payable(msg.sender).transfer(a); } }\n")
    assert "forced_ether_invariant" not in _kinds(tmp_path)


# ── SWC-113 DoS: value push to a STORED address (a stored party can revert) ────
def test_dos_push_to_stored_address(tmp_path):
    """A value push to a STORED address: a malicious previous party reverts and blocks everyone.
    (auction.sol: `require(currentFrontrunner.send(currentBid))`)"""
    (tmp_path / "Auc.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Auc { address currentFrontrunner; uint currentBid;\n"
        "  function bid() public payable { require(msg.value > currentBid);\n"
        "    require(currentFrontrunner.send(currentBid)); currentFrontrunner = msg.sender; currentBid = msg.value; } }\n")
    assert "dos_push_payment" in _kinds(tmp_path)


def test_push_to_msgsender_not_flagged(tmp_path):
    """FP control: pushing to msg.sender (the safe pull pattern) is not the DoS anti-pattern."""
    (tmp_path / "Pull.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Pull { mapping(address=>uint) refunds;\n"
        "  function withdraw() public { uint r = refunds[msg.sender]; refunds[msg.sender]=0; msg.sender.transfer(r); } }\n")
    assert "dos_push_payment" not in _kinds(tmp_path)


# ── SWC-119 variable shadowing: derived re-declares a base state var ───────────
def test_variable_shadowing(tmp_path):
    """A derived contract re-declaring a base state var (SWC-119) splits the slot — the base's
    access-control read sees a different value than the derived write. (inherited_state.sol)"""
    (tmp_path / "Sh.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Base { address owner; function kill() public { require(owner==msg.sender); selfdestruct(owner); } }\n"
        "contract Derived is Base { address owner; function Derived() public { owner = msg.sender; } }\n")
    assert "variable_shadowing" in _kinds(tmp_path)


def test_no_shadowing_distinct_vars(tmp_path):
    """FP control: distinct var names across an inheritance chain are not shadowing."""
    (tmp_path / "Ok.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Base { address admin; }\n"
        "contract Derived is Base { address user; }\n")
    assert "variable_shadowing" not in _kinds(tmp_path)


# ════════════════════════════════════════════════════════════════════════════
# whole-project strategy test: lift per-file maps to the inheritance closure
# ════════════════════════════════════════════════════════════════════════════

# ── cross-FILE inheritance shadowing (map must be project-wide, not per-file) ──
def test_cross_file_variable_shadowing(tmp_path):
    """Base in file 1, `contract Derived is Base` re-declaring a base state var in file 2.
    The shadowing map must span the whole project, not a single file."""
    (tmp_path / "Base.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Base { address owner; function kill() public { require(owner==msg.sender); selfdestruct(owner); } }\n")
    (tmp_path / "Derived.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "import './Base.sol';\n"
        "contract Derived is Base { address owner; function Derived() public { owner = msg.sender; } }\n")
    assert "variable_shadowing" in _kinds(tmp_path)


# ── inherited authority var written with no guard (authority model must see inherited vars) ──
def test_inherited_owner_unprotected_write(tmp_path):
    """An INHERITED `owner` written by an unguarded public derived fn must fire
    unprotected_state_write — the authority model must include inherited state vars."""
    (tmp_path / "Own.sol").write_text(
        "pragma solidity ^0.5.16;\ncontract Ownable { address owner; }\n")
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.5.16;\n"
        "import './Own.sol';\n"
        "contract Vault is Ownable { function setOwner(address o) public { owner = o; } }\n")
    assert "unprotected_state_write" in _kinds(tmp_path)


def test_inherited_var_no_false_shadowing(tmp_path):
    """FP control: merely INHERITING a base var (not re-declaring it) is not shadowing."""
    (tmp_path / "B.sol").write_text("pragma solidity ^0.5.16;\ncontract B { address owner; }\n")
    (tmp_path / "D.sol").write_text(
        "pragma solidity ^0.5.16;\nimport './B.sol';\ncontract D is B { uint x; function f() public { x = 1; } }\n")
    assert "variable_shadowing" not in _kinds(tmp_path)
