import shutil
import pytest
from lattice.ingest.solidity_typed import typed_audit

pytestmark = pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed")


def _legs(findings, leg):
    return [f for f in findings if f["leg"] == leg]


def test_homology_leg_catches_cross_function_reentrancy(tmp_path):
    """The read-before-call cell is written in a DIFFERENT function (_settle) called after the
    external call — the cross-function CEI bug a per-function detector misses. The homology leg
    closes the loop in cell space and fires; the nonReentrant version bounds it."""
    (tmp_path / "Vuln.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vuln {\n"
        "    mapping(address => uint) bal;\n"
        "    function withdraw(uint a) public {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        _settle(msg.sender, a);\n"
        "    }\n"
        "    function _settle(address u, uint a) internal { bal[u] -= a; }\n"
        "}\n")
    (tmp_path / "Safe.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Safe {\n"
        "    mapping(address => uint) bal;\n"
        "    bool locked;\n"
        "    modifier nonReentrant() { require(!locked); locked = true; _; locked = false; }\n"
        "    function withdraw(uint a) public nonReentrant {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        _settle(msg.sender, a);\n"
        "    }\n"
        "    function _settle(address u, uint a) internal { bal[u] -= a; }\n"
        "}\n")
    findings = typed_audit(str(tmp_path))
    h = _legs(findings, "homology")
    assert any(f["contract"] == "Vuln" for f in h), findings
    assert not any(f["contract"] == "Safe" for f in h), "a real nonReentrant body must bound the loop"


def test_collision_leg_catches_proxy_storage_collision(tmp_path):
    """Unstructured-storage proxy: Proxy slot0 = owner(address), Logic slot0 = value(uint256).
    Proxy delegatecalls, aliasing Logic's layout onto its own storage — slot0 is reinterpreted."""
    (tmp_path / "Proxy.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Logic { uint256 value; function set(uint256 v) external { value = v; } }\n"
        "contract Proxy {\n"
        "    address owner;\n"
        "    function fwd(address impl) external { impl.delegatecall(msg.data); }\n"
        "}\n")
    findings = typed_audit(str(tmp_path))
    c = _legs(findings, "typed_collision")
    assert c, "expected a storage collision finding"
    assert any("address" in f["detail"] and "uint256" in f["detail"] for f in c), c


def test_collision_leg_silent_on_matching_layout(tmp_path):
    """Both contracts interpret slot0 as the same type (address) — a well-formed layout. No
    collision, even with a delegatecall present."""
    (tmp_path / "Good.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract LogicGood { address admin; function set(address a) external { admin = a; } }\n"
        "contract ProxyGood {\n"
        "    address owner;\n"
        "    function fwd(address impl) external { impl.delegatecall(msg.data); }\n"
        "}\n")
    findings = typed_audit(str(tmp_path))
    assert _legs(findings, "typed_collision") == [], findings


def test_conservation_leg_catches_unbacked_mint(tmp_path):
    """Supply inflation: reward() credits balances but forgets totalSupply — the conserved
    quantity q = totalSupply − Σbalances drifts. The correct mint (both updated) stays silent."""
    (tmp_path / "Token.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Token {\n"
        "    mapping(address => uint256) balances;\n"
        "    uint256 totalSupply;\n"
        "    function reward(address u, uint256 amt) external { balances[u] += amt; }\n"
        "    function mint(address u, uint256 amt) external { balances[u] += amt; totalSupply += amt; }\n"
        "}\n")
    findings = typed_audit(str(tmp_path))
    cons = _legs(findings, "conservation")
    assert any(f["function"] == "reward" for f in cons), findings
    assert not any(f["function"] == "mint" for f in cons), "balanced mint must not fire"


def test_conservation_split_across_internal_helpers_does_not_false_positive(tmp_path):
    """CERT FP: a correct mint split across two internal helpers (_credit updates supply, _account
    updates balance) must NOT fire — internal helpers are sub-steps, folded into the public entry
    point, not modeled as standalone unbalanced ops."""
    (tmp_path / "Split.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Split {\n"
        "    mapping(address=>uint256) balances; uint256 totalSupply;\n"
        "    function _credit(uint256 a) internal { totalSupply += a; }\n"
        "    function _account(address u, uint256 a) internal { balances[u] += a; }\n"
        "    function mintSplit(address u, uint256 a) external { _credit(a); _account(u, a); }\n"
        "}\n")
    assert _legs(typed_audit(str(tmp_path)), "conservation") == [], "correct split mint must not fire"


# ── hardening from the adversarial red-team (verdict wokhhz0yg) ────────────────────────────

def test_homology_recognizes_working_mutex_by_body_not_name(tmp_path):
    """RANK 6: a genuine reentrancy lock named `guard` (no 'reentran' substring) must be
    recognized by its BODY (require+flag-set), not its name — so it does NOT false-positive."""
    (tmp_path / "Ev2.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Ev2 {\n"
        "    mapping(address=>uint) bal; bool entered;\n"
        "    modifier guard() { require(!entered); entered = true; _; entered = false; }\n"
        "    function withdraw(uint a) public guard {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        bal[msg.sender] -= a;\n"
        "    }\n"
        "}\n")
    assert not _legs(typed_audit(str(tmp_path)), "homology"), "working mutex must bound the loop"


def test_homology_fires_on_dead_modifier_named_nonreentrant(tmp_path):
    """RANK 6 (other side): a dead modifier merely NAMED nonReentrant (body is just `_;`) must
    NOT suppress a real bug — recognition is semantic, so it fires."""
    (tmp_path / "Fake.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Fake {\n"
        "    mapping(address=>uint) bal;\n"
        "    modifier nonReentrant() { _; }\n"
        "    function withdraw(uint a) public nonReentrant {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        bal[msg.sender] -= a;\n"
        "    }\n"
        "}\n")
    assert any(f["contract"] == "Fake" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_detects_literal_slot_assembly_write(tmp_path):
    """RANK 4: a post-call stale write via Yul `sstore(0, ...)` to a LITERAL slot is resolved to
    the state var at that slot and fed to the homology leg — so the assembly-hidden reentrancy
    that was a confirmed silent FN now actually FIRES (not merely escalated)."""
    (tmp_path / "AsmLit.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract AsmLit {\n"
        "    uint256 bal;\n"                                   # slot 0
        "    function withdraw(uint a) public {\n"
        "        require(bal >= a);\n"                          # read bal before the call
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        assembly { sstore(0, 0) }\n"                   # write slot0=bal after -> resolved
        "    }\n"
        "}\n")
    assert any(f["contract"] == "AsmLit" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def _withdraw_body():
    return ("        require(bal[msg.sender] >= a);\n"
            "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
            "        bal[msg.sender] -= a;\n")


def test_homology_onlyowner_with_telemetry_still_fires(tmp_path):
    """REGRESSION (re-validation c5): an onlyOwner modifier carrying an incidental write
    (callCount += 1) is NOT a mutex and must NOT bound a real reentrancy — guard recognition must
    be SELF-REFERENTIAL (the same var checked and written), not bare check+write co-presence."""
    (tmp_path / "OW.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract OW {\n"
        "    mapping(address=>uint) bal; address owner; uint callCount;\n"
        "    modifier onlyOwner() { require(msg.sender == owner); callCount += 1; _; }\n"
        "    function withdraw(uint a) public onlyOwner {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "OW" for f in _legs(typed_audit(str(tmp_path)), "homology")), \
        "onlyOwner+telemetry must NOT suppress reentrancy"


def test_homology_tracker_modifier_still_fires(tmp_path):
    """REGRESSION (c4): a trackCaller modifier (require on msg.sender + write to a different var)
    is not a mutex and must not bound a real reentrancy."""
    (tmp_path / "TC.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract TC {\n"
        "    mapping(address=>uint) bal; address lastCaller;\n"
        "    modifier track() { require(msg.sender != address(0)); lastCaller = msg.sender; _; }\n"
        "    function withdraw(uint a) public track {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "TC" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_self_referential_mutex_still_bounds(tmp_path):
    """A genuine self-referential mutex (checks and writes the SAME flag) must still bound."""
    (tmp_path / "MX.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract MX {\n"
        "    mapping(address=>uint) bal; uint _g;\n"
        "    modifier guard() { require(_g == 1); _g = 2; _; _g = 1; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert not any(f["contract"] == "MX" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_old_style_call_value_is_an_external_boundary(tmp_path):
    """CORPUS FN: the classic pre-0.8 reentrancy vector `msg.sender.call.value(amt)("")` wraps the
    `.call` indicator inside a `.value()` FunctionCall — it must still be recognized as an external
    call, or the entire SWC reentrancy corpus is missed."""
    (tmp_path / "Old.sol").write_text(
        "pragma solidity ^0.5.0;\n"
        "contract Old {\n"
        "    mapping(address=>uint) userBalances;\n"
        "    function withdraw() public {\n"
        "        uint amt = userBalances[msg.sender];\n"
        "        (bool ok,) = msg.sender.call.value(amt)(\"\");\n"   # old-style external call
        "        require(ok);\n"
        "        userBalances[msg.sender] = 0;\n"
        "    }\n"
        "}\n")
    assert any(f["contract"] == "Old" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_interface_method_call_is_an_external_boundary(tmp_path):
    """CERT BLOCKER (cardinal): a high-level interface call IReceiver(x).onTokens() between a
    balance read and write is the DOMINANT modern reentrancy syntax — it must be an external
    boundary, not missed because it isn't .call/.transfer/.send."""
    (tmp_path / "Hook.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "interface IReceiver { function onTokens(uint256) external; }\n"
        "contract Hook {\n"
        "    mapping(address=>uint256) bal;\n"
        "    function claim(uint256 a) public {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        IReceiver(msg.sender).onTokens(a);\n"            # high-level external call (cast)
        "        bal[msg.sender] -= a;\n"
        "    }\n"
        "}\n")
    assert any(f["contract"] == "Hook" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_interface_call_via_stored_var_is_external(tmp_path):
    """A call through a stored contract-typed var (cb.hook()) is external too."""
    (tmp_path / "CB.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "interface ICB { function hook() external; }\n"
        "contract CB {\n"
        "    mapping(address=>uint256) bal; ICB cb;\n"
        "    function claim(uint256 a) public {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        cb.hook();\n"
        "        bal[msg.sender] -= a;\n"
        "    }\n"
        "}\n")
    assert any(f["contract"] == "CB" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_arithmetic_counter_is_not_a_mutex(tmp_path):
    """CERT BLOCKER: a checked counter bumped via +=/-= (clamp / fee-tier / depth meter) is NOT a
    mutex — a lock toggles a flag to opposing CONSTANTS, it does not do arithmetic. Must FIRE."""
    (tmp_path / "Clamp.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Clamp {\n"
        "    mapping(address=>uint) bal; uint level;\n"
        "    modifier clamp() { require(level <= 5); level = level + 1; _; level = level - 1; }\n"
        "    function withdraw(uint a) public clamp {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "Clamp" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_enum_status_mutex_still_bounds(tmp_path):
    """Regression guard: the OZ enum-status mutex (toggle to constants) must still bound."""
    (tmp_path / "ES.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract ES {\n"
        "    mapping(address=>uint) bal; uint256 status;\n"
        "    modifier nonReentrant() { require(status != 2); status = 2; _; status = 1; }\n"
        "    function withdraw(uint a) public nonReentrant {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert not any(f["contract"] == "ES" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_hex_literal_yul_slot_resolves(tmp_path):
    """CERT BLOCKER: solc emits Yul literals verbatim ('0x1'), but slot keys are decimal — a
    hex-slot sstore to a real var must resolve (and fire), not be dropped as 'touches nothing'."""
    (tmp_path / "Hex.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Hex {\n"
        "    uint256 pad; uint256 bal;\n"                        # bal at slot 1 == 0x1
        "    function withdraw(uint a) public {\n"
        "        require(bal >= a);\n"
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        assembly { sstore(0x1, 0) }\n"                  # hex slot 1 -> bal
        "    }\n"
        "}\n")
    assert any(f["contract"] == "Hex" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_parenthesized_mutex_check_still_bounds(tmp_path):
    """CERT R9 FP: a real mutex whose check is parenthesized — require((!locked)) — must still be
    recognized (parens are a TupleExpression that must be unwrapped), or a safe guard false-positives."""
    (tmp_path / "Par.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Par {\n"
        "    mapping(address=>uint) bal; bool locked;\n"
        "    modifier guard() { require((!locked)); locked = true; _; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert not any(f["contract"] == "Par" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_collision_unresolvable_target_blindspot_survives_coincidental_pairing(tmp_path):
    """CERT R9 (cardinal): a proxy that delegatecalls a RUNTIME target (not an explicit type ref)
    co-located with a matching-layout contract gets coincidentally paired (no collision found) — its
    unresolvable-target blindspot must still fire; a heuristic pairing is not proof of the target."""
    (tmp_path / "App.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract App {\n"
        "    address impl;\n"
        "    function run() external { address t = impl; assembly { let r := delegatecall(gas(), t, 0, 0, 0, 0) } }\n"
        "}\n"
        "contract Other { address impl; function s(address a) external { impl = a; } }\n")  # same layout
    blinds = _legs(typed_audit(str(tmp_path)), "blindspot")
    assert any(b["kind"] == "unresolvable_delegatecall_target" for b in blinds), blinds


def test_homology_disjunctive_guard_check_is_not_a_mutex(tmp_path):
    """CERT R8 (cardinal): require(bypass || !locked); locked=true; ... — because the check is a
    DISJUNCTION, !locked is not actually required (it passes whenever bypass holds), so locked=true
    does not guarantee re-entry reverts. A mutex check must be a CONJUNCTION. Must FIRE."""
    (tmp_path / "OrG.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract OrG {\n"
        "    mapping(address=>uint) bal; bool locked; bool bypass;\n"
        "    modifier guard() { require(bypass || !locked); locked = true; _; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "OrG" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_conservation_struct_nested_total_escalates_blindspot(tmp_path):
    """CERT R8 (cardinal): a total* hidden in a struct field (ERC-7201 / diamond storage) escapes
    the top-level recognizer — it must escalate a blindspot, not pass silently."""
    (tmp_path / "NS.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract NS {\n"
        "    struct Layout { uint256 totalSupply; mapping(address=>uint256) balances; }\n"
        "    Layout data;\n"
        "    function mint(address u, uint256 a) external { data.balances[u] += a; }\n"
        "}\n")
    assert _legs(typed_audit(str(tmp_path)), "blindspot"), "struct-hidden accounting must escalate"


def test_conservation_scalar_overwrite_escalates_blindspot(tmp_path):
    """CERT R11 (last documented FN, now escalated): a conserved scalar mutated only via `=` (a
    rebase / setSupply) has an unknown delta in the sign-only model — it must escalate a blindspot,
    not pass silently."""
    (tmp_path / "Rb.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Rb {\n"
        "    mapping(address=>uint256) balances; uint256 totalSupply;\n"
        "    function rebase(uint256 v) external { totalSupply = v; }\n"   # overwrite, delta unknown
        "}\n")
    blinds = _legs(typed_audit(str(tmp_path)), "blindspot")
    assert any(b["kind"] == "conserved_scalar_overwrite" for b in blinds), blinds


def test_conservation_burn_via_delete_fires(tmp_path):
    """CERT R8 (cardinal): a burn done via `delete balances[u]` (a UnaryOperation, not an Assignment)
    decreases Σbalance with no supply decrement — a conservation break that must FIRE, not be missed
    because `delete` isn't an assignment node."""
    (tmp_path / "Del.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Del {\n"
        "    mapping(address=>uint256) balances; uint256 totalSupply;\n"
        "    function burn(address u) external { delete balances[u]; }\n"   # supply not decremented
        "}\n")
    assert any(f["function"] == "burn" for f in _legs(typed_audit(str(tmp_path)), "conservation"))


def test_homology_inherited_variable_reentrancy_fires(tmp_path):
    """CERT R10 (cardinal): a normal reentrancy on an INHERITED state var must fire — state-var
    recognition must include inherited vars (the flattened layout), not just the contract's own."""
    (tmp_path / "Inh.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Base { mapping(address=>uint) bal; }\n"
        "contract Derived is Base {\n"
        "    function withdraw(uint a) public {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        bal[msg.sender] -= a;\n"
        "    }\n"
        "}\n")
    assert any(f["contract"] == "Derived" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_transient_data_does_not_mask_persistent_reentrancy(tmp_path):
    """CERT R10 (cardinal): an UNRELATED function-body tstore (transient data, not a guard) must not
    demote a genuine PERSISTENT-storage reentrancy to a blindspot — the persistent obstruction fires."""
    (tmp_path / "TM.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract TM {\n"
        "    mapping(address=>uint) bal;\n"
        "    function withdraw(uint a) public {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        assembly { tstore(5, 1) }\n"                  # unrelated transient data
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        bal[msg.sender] -= a;\n"
        "    }\n"
        "}\n")
    assert any(f["contract"] == "TM" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_helper_param_controlled_set_is_not_a_mutex(tmp_path):
    """CERT R10 (cardinal): a helper that sets the lock from its OWN parameter — _lock(bool v){
    locked=v; } invoked _lock(false) — provably runs unlocked. The set value must be checked
    against the HELPER's params, not the modifier's, or it's wrongly treated as a fixed lock."""
    (tmp_path / "HP.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract HP {\n"
        "    mapping(address=>uint) bal; bool locked;\n"
        "    function _lock(bool v) internal { require(!locked); locked = v; }\n"
        "    modifier guard() { _lock(false); _; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "HP" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_dynamic_set_value_is_not_a_mutex(tmp_path):
    """CERT R7 (cardinal): require(!locked); locked = paused; ... — the lock is SET from another
    state var, not a fixed sentinel, so it may never engage. The set value must be FIXED (symmetric
    with the check side). Must FIRE."""
    (tmp_path / "DS.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract DS {\n"
        "    mapping(address=>uint) bal; bool locked; bool paused;\n"
        "    modifier guard() { require(!locked); locked = paused; _; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "DS" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_param_controlled_lock_set_is_not_a_mutex(tmp_path):
    """CERT R7 (cardinal): modifier guard(bool engage){ require(!locked); locked = engage; ... }
    invoked guard(false) provably runs unlocked. A param-controlled set is not a fixed lock."""
    (tmp_path / "PS.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract PS {\n"
        "    mapping(address=>uint) bal; bool locked;\n"
        "    modifier guard(bool engage) { require(!locked); locked = engage; _; locked = false; }\n"
        "    function withdraw(uint a) public guard(false) {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "PS" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_conditional_set_in_helper_is_not_a_mutex(tmp_path):
    """CERT R6 (cardinal): a lock SET inside an if-branch of a ONE-HOP helper is not guaranteed —
    the helper walker must be branch-aware like the modifier walker, or the call runs unlocked."""
    (tmp_path / "HC.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract HC {\n"
        "    mapping(address=>uint) bal; bool locked; bool feature;\n"
        "    function _lock() internal { require(!locked); if (feature) { locked = true; } }\n"
        "    modifier guard() { _lock(); _; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "HC" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_unconditional_set_in_helper_still_bounds(tmp_path):
    """Regression control: an UNCONDITIONAL helper set is still a genuine lock and must bound."""
    (tmp_path / "HU.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract HU {\n"
        "    mapping(address=>uint) bal; bool locked;\n"
        "    function _lock() internal { require(!locked); locked = true; }\n"
        "    modifier guard() { _lock(); _; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert not any(f["contract"] == "HU" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_conservation_path_dependent_write_escalates_blindspot(tmp_path):
    """CERT R6 (cardinal): balance credited unconditionally but supply only after an early return —
    the flat sum nets to zero yet leaks on the paused path. Must escalate a blindspot, not pass."""
    (tmp_path / "PD.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract PD {\n"
        "    mapping(address=>uint256) balances; uint256 totalSupply; bool paused;\n"
        "    function mint(address u, uint256 a) external {\n"
        "        balances[u] += a;\n"
        "        if (paused) { return; }\n"
        "        totalSupply += a;\n"
        "    }\n"
        "}\n")
    blinds = _legs(typed_audit(str(tmp_path)), "blindspot")
    assert any(b["kind"] == "path_dependent_accounting" for b in blinds), blinds


def test_homology_enum_member_sentinel_mutex_bounds(tmp_path):
    """CERT R5 FP: a genuine OZ-style enum mutex (status != Status.ENTERED; = ENTERED; _; =
    NOT_ENTERED) uses MemberAccess sentinels — these must be recognized as fixed values and bound."""
    (tmp_path / "EnumG.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract EnumG {\n"
        "    mapping(address=>uint) bal;\n"
        "    enum Status { NOT_ENTERED, ENTERED }\n"
        "    Status status;\n"
        "    modifier guard() { require(status != Status.ENTERED); status = Status.ENTERED; _; status = Status.NOT_ENTERED; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert not any(f["contract"] == "EnumG" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_key_mismatch_mapping_mutex_fires(tmp_path):
    """CERT R5 (cardinal): require(!locked[msg.sender]); locked[address(0)]=true; _; locked[msg.sender]
    =false — the SET targets a DIFFERENT key than the check, so the caller's lock is never taken.
    The flag identity must include the key; mismatched keys must FIRE."""
    (tmp_path / "KM.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract KM {\n"
        "    mapping(address=>uint) bal; mapping(address=>bool) locked;\n"
        "    modifier guard() { require(!locked[msg.sender]); locked[address(0)] = true; _; locked[msg.sender] = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "KM" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_branch_conditional_lock_set_is_not_a_mutex(tmp_path):
    """CERT R4 (cardinal): a lock set inside an if-branch (if(feature){locked=true;} _;) is not
    guaranteed — when the branch is skipped, `_` runs unlocked. A conditional set must NOT confer a
    bounding mutex. Must FIRE."""
    (tmp_path / "F8.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract F8 {\n"
        "    mapping(address=>uint) bal; bool locked; bool feature;\n"
        "    modifier guard() { require(!locked); if (feature) { locked = true; } _; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "F8" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_per_key_mapping_mutex_bounds(tmp_path):
    """CERT R4 FP: a legitimate per-caller lock (require(!locked[msg.sender]); locked[msg.sender]=
    true; _; locked[msg.sender]=false) must be recognized (IndexAccess lvalue) and bound."""
    (tmp_path / "F9.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract F9 {\n"
        "    mapping(address=>uint) bal; mapping(address=>bool) locked;\n"
        "    modifier guard() { require(!locked[msg.sender]); locked[msg.sender] = true; _; locked[msg.sender] = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert not any(f["contract"] == "F9" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_collision_interface_reference_resolves_to_implementation(tmp_path):
    """CERT R4 (cardinal): a proxy that references an INTERFACE (ILogic(impl)) must not fake-resolve
    to the cell-less interface and mask the real collision — it must compare against the concrete
    contract that implements the interface."""
    (tmp_path / "Proxy.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "interface ILogic { function s(uint256) external; }\n"
        "contract BProxy { address owner; ILogic impl; function f() external { address(impl).delegatecall(msg.data); } }\n")
    (tmp_path / "Logic.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract RealLogic is ILogic { uint256 value; function s(uint256 v) external { value = v; } }\n")
    coll = _legs(typed_audit(str(tmp_path)), "typed_collision")
    assert any("RealLogic" in f["contract"] for f in coll), coll


def test_homology_storage_pointer_slot_to_local_escalates_blindspot(tmp_path):
    """CERT R4 (cardinal): sstore to a local storage-pointer's .slot (p.slot, p a local alias) can't
    be traced to a state cell — it must escalate a blindspot, not be silently dropped."""
    (tmp_path / "Ptr.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Ptr {\n"
        "    struct S { uint256 v; }\n"
        "    S data; mapping(address=>uint) bal;\n"
        "    function withdraw(uint a) public {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        S storage p = data;\n"
        "        assembly { sstore(p.slot, 0) }\n"
        "    }\n"
        "}\n")
    assert _legs(typed_audit(str(tmp_path)), "blindspot"), "untraceable storage-pointer write must escalate"


def test_conservation_mismatched_total_and_mapping_does_not_assert_conservation(tmp_path):
    """CERT R4 FP: a lending pool's totalDebt and a deposits mapping are INDEPENDENT — q must not
    assert totalDebt = Σdeposits and fire on every borrow. No name affinity -> no functional ->
    blindspot, not a conservation break."""
    (tmp_path / "Lend.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Lend {\n"
        "    mapping(address=>uint256) deposits; uint256 totalDebt;\n"
        "    function borrow(uint256 a) external { totalDebt += a; }\n"
        "}\n")
    assert _legs(typed_audit(str(tmp_path)), "conservation") == [], "independent debt/deposits must not fire"


def test_conservation_array_ledger_with_total_escalates_blindspot(tmp_path):
    """CERT R4 (cardinal): a total* scalar with an ARRAY/struct balance ledger (not a mapping) is
    not modeled by q (which needs a mapping) — it must escalate a blindspot, not pass silently."""
    (tmp_path / "Arr.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Arr {\n"
        "    uint256[] ledger; uint256 totalSupply;\n"
        "    function reward(uint256 i, uint256 a) external { ledger[i] += a; }\n"
        "}\n")
    assert _legs(typed_audit(str(tmp_path)), "blindspot"), "array-ledger accounting must escalate a blindspot"


def test_homology_set_to_check_passing_value_is_not_a_mutex(tmp_path):
    """CERT BLOCKER G2 (cardinal): require(!locked); locked=false; _; locked=false — the set value
    (false) PASSES the check (!false==true), so re-entry is not excluded. A real mutex's set value
    must TRIP its own check. Must FIRE."""
    (tmp_path / "G2.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract G2 {\n"
        "    mapping(address=>uint) bal; bool locked;\n"
        "    modifier guard() { require(!locked); locked = false; _; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "G2" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_flipped_sentinel_guard_is_not_a_mutex(tmp_path):
    """CERT BLOCKER G3 (cardinal): require(status==1); status=1; _; status=1 — set to the passing
    value, no exclusion. Must FIRE. (The correct form sets a DIFFERENT value before `_`.)"""
    (tmp_path / "G3.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract G3 {\n"
        "    mapping(address=>uint) bal; uint status;\n"
        "    modifier guard() { require(status == 1); status = 1; _; status = 1; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "G3" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_attacker_keyed_pseudo_mutex_fires(tmp_path):
    """CERT BLOCKER P1: require(lastCaller != msg.sender); lastCaller = msg.sender — compares the
    state var to an ATTACKER-CONTROLLED value, not a fixed sentinel; a second attacker contract
    (different msg.sender) bypasses it. Not a real mutex. Must FIRE."""
    (tmp_path / "P1.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract P1 {\n"
        "    mapping(address=>uint) bal; address lastCaller;\n"
        "    modifier guard() { require(lastCaller != msg.sender); lastCaller = msg.sender; _; lastCaller = address(0); }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "P1" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_correct_sentinel_set_trips_check_still_bounds(tmp_path):
    """Regression: the correct form (set a value that TRIPS the check) must still bound."""
    (tmp_path / "OK.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract OK {\n"
        "    mapping(address=>uint) bal; uint status;\n"
        "    modifier guard() { require(status == 1); status = 2; _; status = 1; }\n"   # set 2 trips ==1
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert not any(f["contract"] == "OK" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_lock_set_after_body_is_not_a_mutex(tmp_path):
    """CERT BLOCKER c11 (cardinal): a modifier that sets the lock AFTER the placeholder
    (require(!locked); _; locked=true; locked=false) leaves locked==false during the external
    call — re-entry passes. A real mutex sets BEFORE `_` and resets after. Must FIRE."""
    (tmp_path / "LA.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract LA {\n"
        "    mapping(address=>uint) bal; bool locked;\n"
        "    modifier guard() { require(!locked); _; locked = true; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "LA" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_inequality_clamp_with_passing_set_is_not_a_mutex(tmp_path):
    """CERT BLOCKER c8 (cardinal): require(level<10); level=1; _; level=0 — the set value 1 still
    satisfies level<10, so re-entry is NOT excluded. A mutex uses an EQUALITY/boolean check whose
    set value trips it; an inequality clamp does not. Must FIRE."""
    (tmp_path / "C8.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract C8 {\n"
        "    mapping(address=>uint) bal; uint level;\n"
        "    modifier clamp() { require(level < 10); level = 1; _; level = 0; }\n"
        "    function withdraw(uint a) public clamp {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "C8" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_conservation_two_hop_unbacked_mint_fires(tmp_path):
    """CERT BLOCKER c13 (cardinal): an unbacked mint whose effect lives TWO internal-call hops deep
    must still fire — the fold of internal-helper deltas into the public entry must be transitive."""
    (tmp_path / "TH.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract TH {\n"
        "    mapping(address=>uint256) balances; uint256 totalSupply;\n"
        "    function _inner(address u, uint256 a) internal { balances[u] += a; }\n"   # leak, no supply
        "    function _mid(address u, uint256 a) internal { _inner(u, a); }\n"
        "    function mint(address u, uint256 a) external { _mid(u, a); }\n"
        "}\n")
    assert any(f["function"] == "mint" for f in _legs(typed_audit(str(tmp_path)), "conservation"))


def test_conservation_two_hop_balanced_does_not_fire(tmp_path):
    """The two-hop FP control: a correct mint whose compensating write is two hops deep must net to
    zero under the transitive fold and NOT fire."""
    (tmp_path / "THB.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract THB {\n"
        "    mapping(address=>uint256) balances; uint256 totalSupply;\n"
        "    function _credit(uint256 a) internal { totalSupply += a; }\n"
        "    function _inner(address u, uint256 a) internal { balances[u] += a; }\n"
        "    function _mid(address u, uint256 a) internal { _inner(u, a); }\n"
        "    function mint(address u, uint256 a) external { _credit(a); _mid(u, a); }\n"
        "}\n")
    assert _legs(typed_audit(str(tmp_path)), "conservation") == []


def test_collision_unresolvable_delegatecall_target_escalates_blindspot(tmp_path):
    """CERT BLOCKER M_lone: a contract that provably delegatecalls to an unresolvable runtime target
    (selector router / EIP-2535 diamond) with no resolvable impl pair must escalate a blindspot —
    we KNOW it forwards storage to foreign code, we just can't see where. Silence is the cardinal sin."""
    (tmp_path / "Lone.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Lone {\n"
        "    mapping(bytes4=>address) routes; address admin;\n"
        "    fallback() external {\n"
        "        address t = routes[msg.sig];\n"
        "        assembly { let r := delegatecall(gas(), t, 0, calldatasize(), 0, 0) }\n"
        "    }\n"
        "}\n")
    blinds = _legs(typed_audit(str(tmp_path)), "blindspot")
    assert any(b["kind"] == "unresolvable_delegatecall_target" for b in blinds), blinds


def test_homology_rate_limiter_modifier_is_not_a_mutex(tmp_path):
    """REGRESSION (3rd-order): a rate-limiter (require(count<max); count+=1) checks AND writes the
    same var, but with ONE write (no reset) it is not a reentrancy mutex. A mutex needs set+reset
    (the flag written twice); a single-write counter must NOT bound a real reentrancy."""
    (tmp_path / "RL.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract RL {\n"
        "    mapping(address=>uint) bal; uint count;\n"
        "    modifier rateLimit() { require(count < 100); count += 1; _; }\n"
        "    function withdraw(uint a) public rateLimit {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert any(f["contract"] == "RL" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_helper_delegated_guard_check_still_bounds(tmp_path):
    """REGRESSION (RANK 5): a mutex whose CHECK is factored into an internal helper (_checkLock()
    containing the require) while the modifier writes the flag is recognized via one call hop, so
    a safe guarded function does not false-positive."""
    (tmp_path / "DG.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract DG {\n"
        "    mapping(address=>uint) bal; bool locked;\n"
        "    function _checkLock() internal view { require(!locked); }\n"
        "    modifier guard() { _checkLock(); locked = true; _; locked = false; }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    assert not any(f["contract"] == "DG" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_packed_slot_assembly_attributes_all_vars(tmp_path):
    """REGRESSION (RANK 3): a literal sstore writes the whole slot word, so it must be attributed to
    EVERY var packed there — the stale-read victim being the SECOND packed var must still fire,
    not be silently missed by first-var-only attribution."""
    (tmp_path / "PK.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract PK {\n"
        "    uint128 x; uint128 y;\n"                          # both packed in slot 0
        "    function withdraw(uint a) public {\n"
        "        require(y >= uint128(a));\n"                   # reads the SECOND packed var
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        assembly { sstore(0, 0) }\n"                   # writes slot0 (x AND y) after call
        "    }\n"
        "}\n")
    assert any(f["contract"] == "PK" for f in _legs(typed_audit(str(tmp_path)), "homology"))


def test_homology_transient_guard_is_not_a_confident_fire(tmp_path):
    """REGRESSION (RANK 1): an EIP-1153 transient-storage reentrancy guard (tstore/tload) is the
    construct that PREVENTS reentrancy. It must NOT be reported as a confident high-severity
    homology FIRE — at most an honest blindspot (it's an unverifiable assembly guard)."""
    (tmp_path / "TG.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract TG {\n"
        "    mapping(address=>uint) bal;\n"
        "    modifier guard() { assembly { if tload(0) { revert(0,0) } tstore(0,1) } _; assembly { tstore(0,0) } }\n"
        "    function withdraw(uint a) public guard {\n" + _withdraw_body() + "    }\n"
        "}\n")
    findings = typed_audit(str(tmp_path))
    assert not any(f["contract"] == "TG" for f in _legs(findings, "homology")), \
        "transient guard must not be a confident reentrancy FIRE"


def test_homology_escalates_computed_slot_assembly_as_blindspot(tmp_path):
    """RANK 4 (other half): a write to a COMPUTED (keccak-derived) slot cannot be resolved to a
    var, so it is honestly escalated as a blindspot rather than passed silently."""
    (tmp_path / "AsmC.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract AsmC {\n"
        "    mapping(address=>uint) bal;\n"
        "    function withdraw(uint a) public {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        assembly { mstore(0, caller()) let s := keccak256(0, 64) sstore(s, 0) }\n"
        "    }\n"
        "}\n")
    assert any(f["contract"] == "AsmC" for f in _legs(typed_audit(str(tmp_path)), "blindspot"))


def test_conservation_blindspot_on_unrecognized_accounting_shape(tmp_path):
    """RANK 1: token-shaped state (a balance-like mapping + a supply-like scalar) whose names the
    heuristic does not recognize must emit a blindspot, not pass clean (the dead-code fix)."""
    (tmp_path / "Lend.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Lend {\n"
        "    mapping(address => uint256) collateralOf;\n"
        "    uint256 backing;\n"
        "    function deposit(address u, uint256 amt) external { collateralOf[u] += amt; }\n"
        "}\n")
    assert any(f["contract"] == "Lend" for f in _legs(typed_audit(str(tmp_path)), "blindspot"))


def test_collision_finding_is_needs_confirmation_not_unverified_critical(tmp_path):
    """RANK 5: because the delegatecall target is not statically resolved to the aliased contract,
    a collision is labeled needs-confirmation (unproven), not an unverified 'critical'."""
    (tmp_path / "P.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Logic { uint256 value; function s(uint256 v) external { value = v; } }\n"
        "contract Proxy { address owner; function f(address i) external { i.delegatecall(msg.data); } }\n")
    coll = _legs(typed_audit(str(tmp_path)), "typed_collision")
    assert coll
    assert coll[0]["confidence"] == "unproven"
    assert coll[0]["severity"] != "critical"


# ── RANK 3: cross-file / stateless-proxy collision coverage (resolved pairs, FP-gated) ─────

def test_collision_cross_file_naming_convention(tmp_path):
    """The canonical real deployment: proxy and implementation in SEPARATE files, paired by the
    `XProxy` ↔ `X` naming convention. VaultProxy slot0=owner(address) vs Vault slot0=total(uint256)."""
    (tmp_path / "VaultProxy.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract VaultProxy { address owner; function f(address i) external { i.delegatecall(msg.data); } }\n")
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault { uint256 total; function s(uint256 v) external { total = v; } }\n")
    coll = _legs(typed_audit(str(tmp_path)), "typed_collision")
    assert coll, "cross-file proxy/impl pair must be compared"
    assert any("Vault" in f["contract"] for f in coll)


def test_collision_version_family_upgrade_shift(tmp_path):
    """Upgrade corruption in a REAL proxy/upgrade system: a TokenProxy delegatecalls, corroborating
    that TokenV1/TokenV2 are an upgrade chain; V2 inserts a full-word var, shifting a slot to a
    conflicting type. The delegating member is what distinguishes this from coincidental V1/V2 names."""
    (tmp_path / "TokenProxy.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract TokenProxy { address admin; function f(address i) external { i.delegatecall(msg.data); } }\n")
    (tmp_path / "TokenV1.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract TokenV1 { address a; uint256 b; function f() external {} }\n")
    (tmp_path / "TokenV2.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract TokenV2 { uint256 inserted; address a; uint256 b; function f() external {} }\n")
    coll = _legs(typed_audit(str(tmp_path)), "typed_collision")
    assert coll, "a corroborated upgrade chain must be compared for layout divergence"


def test_collision_coincidental_versions_without_proxy_stay_silent(tmp_path):
    """REGRESSION (RANK 4): two INDEPENDENT contracts that merely share a V1/V2 naming suffix, with
    NO delegatecall anywhere, must NOT be paired on lexical coincidence alone."""
    (tmp_path / "PriceV1.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract PriceV1 { address oracle; function p() external view returns (uint) { return 1; } }\n")
    (tmp_path / "PriceV2.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract PriceV2 { uint256 price; function set(uint256 v) external { price = v; } }\n")
    assert _legs(typed_audit(str(tmp_path)), "typed_collision") == [], "lexical V1/V2 with no proxy must not fire"


def test_collision_assembly_delegatecall_proxy_is_recognized(tmp_path):
    """CERT BLOCKER: a proxy that forwards via a Yul `delegatecall` opcode (EIP-1967/1167/2535 —
    the dominant production proxy) was invisible because only high-level `.delegatecall` was seen.
    It must now be recognized as a delegating proxy and paired with its implementation."""
    (tmp_path / "AsmProxy.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract AsmProxy {\n"
        "    address owner;\n"
        "    fallback() external { assembly { let r := delegatecall(gas(), sload(0), 0, calldatasize(), 0, 0) } }\n"
        "}\n")
    (tmp_path / "AsmLogic.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract AsmLogic { uint256 value; function s(uint256 v) external { value = v; } }\n")
    assert _legs(typed_audit(str(tmp_path)), "typed_collision"), "assembly-forwarding proxy must pair"


def test_conservation_second_total_scalar_escalates_blindspot(tmp_path):
    """CERT FN: a vault with TWO conserved scalars (totalAssets AND totalShares) binds only one
    into q; the other must be escalated as a blindspot, not silently dropped."""
    (tmp_path / "Vault4626.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault4626 {\n"
        "    mapping(address=>uint256) shares;\n"
        "    uint256 totalShares; uint256 totalAssets;\n"
        "    function dep(uint256 a) external { totalAssets += a; }\n"
        "}\n")
    blinds = _legs(typed_audit(str(tmp_path)), "blindspot")
    assert any(b["kind"] == "multi_quantity_accounting" for b in blinds), blinds


def test_collision_severity_keyed_to_basis(tmp_path):
    """REGRESSION (RANK 7): a needs-confirmation collision (naming/same-file basis) must carry a
    severity that matches its unproven confidence, not a bare 'high' a severity-keyed triage trusts."""
    (tmp_path / "VaultProxy.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract VaultProxy { address owner; function f(address i) external { i.delegatecall(msg.data); } }\n")
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault { uint256 total; function s(uint256 v) external { total = v; } }\n")
    coll = _legs(typed_audit(str(tmp_path)), "typed_collision")
    assert coll and coll[0]["severity"] != "high", coll      # naming-family is not high-confidence


def test_collision_cross_file_unrelated_does_not_fire(tmp_path):
    """The FP-control that makes cross-file safe: a delegatecaller and an UNRELATED contract in a
    different file (no explicit reference, no shared naming family) must NOT collide just because
    they happen to use slot0 differently. Resolution gates the comparison, not co-location."""
    (tmp_path / "Forwarder.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Forwarder { address admin; function f(address i) external { i.delegatecall(msg.data); } }\n")
    (tmp_path / "Unrelated.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Unrelated { uint256 counter; function inc() external { counter += 1; } }\n")
    assert _legs(typed_audit(str(tmp_path)), "typed_collision") == [], "unrelated cross-file must not collide"


def test_collision_cross_file_explicit_reference(tmp_path):
    """A proxy that names its implementation's type resolves the pair explicitly, even across files
    and even when an interface shares the impl's name (the comparison targets the stateful contract,
    not the cell-less interface)."""
    (tmp_path / "MyProxy.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "interface Logic { function s(uint256) external; }\n"
        "contract MyProxy { address owner; Logic impl; function f() external { address(impl).delegatecall(msg.data); } }\n")
    (tmp_path / "Logic.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Logic { uint256 value; function s(uint256 v) external { value = v; } }\n")
    coll = _legs(typed_audit(str(tmp_path)), "typed_collision")
    assert coll and any(f.get("basis") == "explicit-reference" for f in coll), coll
