"""ARBITRARY-EXTERNAL-CALL detector — reuses the trust/taint OPERATOR (lattice.taint.trust_obstructions)
with a new ingest classification: SOURCE = untrusted address PARAMETERS, SINK = the callee-address of an
external call (`X.call/.delegatecall/.functionCall(...)`). When an attacker-chosen address is the target
of a call, they can make the contract call anything on their behalf.

THE BUG CLASS (Damn-Vulnerable-DeFi `truster`): `function flashLoan(..., address target, bytes data) {
target.functionCall(data); }` — the attacker passes target=token, data=approve(attacker, balance); the
pool calls token.approve(attacker, ...) and the attacker drains it. The signature is structural and
high-signal: the callee ADDRESS derives from a function parameter (not a fixed state var / address(this)).

The TOGGLE: a call whose target is an attacker-supplied PARAMETER fires; the byte-identical call to a
FIXED state-variable target is silent (the function selector space is then bounded by that contract).
"""
import pathlib

import pytest

from lattice.ingest.solidity import _solc_ast
from lattice.ingest.solidity_arbitrary_call import arbitrary_call_audit


def _parses(tmp_path) -> bool:
    (tmp_path / "_probe.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract P { function f() public pure returns (uint){ return 1; } }\n")
    return _solc_ast(tmp_path / "_probe.sol") is not None


_HEAD = ("pragma solidity ^0.8.0;\n"
         "library Address { function functionCall(address t, bytes memory d) internal returns (bytes memory){} }\n")


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return arbitrary_call_audit(p)


def test_arbitrary_call_to_param_target_FIRES(tmp_path):
    """The truster idiom: callee address is an untrusted parameter — fires."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = _HEAD + ("contract Pool { using Address for address;\n"
                   "  function flashLoan(address target, bytes calldata data) external { target.functionCall(data); } }\n")
    findings = _audit(tmp_path, "p.sol", src)
    assert "arbitrary_external_call" in [f["kind"] for f in findings], findings
    assert "flashLoan" in {f["function"] for f in findings}


def test_call_to_fixed_state_target_SILENT(tmp_path):
    """The byte-identical call to a FIXED state-variable target is not attacker-chosen — silent."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = _HEAD + ("contract Pool { using Address for address; address token;\n"
                   "  function exec(bytes calldata data) external { token.functionCall(data); } }\n")
    assert _audit(tmp_path, "s.sol", src) == []


def test_lowlevel_call_to_param_FIRES(tmp_path):
    """A low-level `target.call(data)` to a parameter address also fires."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = ("pragma solidity ^0.8.0;\ncontract C {\n"
           "  function run(address target, bytes calldata data) external { target.call(data); } }\n")
    assert "flashLoan" not in {f["function"] for f in _audit(tmp_path, "c.sol", src)}  # name check
    assert "run" in {f["function"] for f in _audit(tmp_path, "c.sol", src)}


def test_delegatecall_to_param_FIRES(tmp_path):
    """delegatecall to a parameter address is the most critical form — fires."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = ("pragma solidity ^0.8.0;\ncontract C {\n"
           "  function run(address target, bytes calldata data) external { target.delegatecall(data); } }\n")
    assert "run" in {f["function"] for f in _audit(tmp_path, "d.sol", src)}


def test_call_with_no_param_target_silent(tmp_path):
    """A call to address(this) / msg.sender (not attacker-chosen) is silent."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = ("pragma solidity ^0.8.0;\ncontract C {\n"
           "  function run(bytes calldata data) external { address(this).call(data); } }\n")
    assert _audit(tmp_path, "t.sol", src) == []


def test_empty_calldata_value_send_SILENT(tmp_path):
    """`to.call{value: x}("")` is a PAYMENT to a recipient — empty calldata forces no function selector,
    so it is not a coercible arbitrary call (the Fei PSMRouter._redeem FP). Must NOT fire."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    src = ("pragma solidity ^0.8.0;\ncontract Router {\n"
           "  function redeem(uint amount, address payable to) external {\n"
           "    (bool ok, ) = to.call{value: amount}(\"\"); require(ok); } }\n")
    assert _audit(tmp_path, "pay.sol", src) == [], "empty-calldata value send is a payment, not arbitrary call"


def test_call_with_real_calldata_to_param_still_FIRES(tmp_path):
    """A call to a param target WITH real calldata is still the truster shape — must still fire."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    src = ("pragma solidity ^0.8.0;\ncontract C {\n"
           "  function exec(address target, bytes calldata data) external { target.call(data); } }\n")
    assert any(f["kind"] == "arbitrary_external_call" for f in _audit(tmp_path, "rc.sol", src))


def test_onlyOwner_arbitrary_call_silent(tmp_path):
    """An access-controlled (onlyOwner) arbitrary call is a TRUSTED admin escape hatch (DVD
    `unstoppable`'s `execute`) — the owner is trusted, so it must NOT fire. The discriminator between
    this and truster (which is callable by ANYONE) is the access-control modifier."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = ("pragma solidity ^0.8.0;\ncontract C { address owner;\n"
           "  modifier onlyOwner(){ require(msg.sender==owner); _; }\n"
           "  function run(address target, bytes calldata data) external onlyOwner { target.delegatecall(data); } }\n")
    assert _audit(tmp_path, "ao.sol", src) == [], "onlyOwner-gated arbitrary call must not fire"


def test_msg_sender_require_arbitrary_call_silent(tmp_path):
    """A body-level `require(msg.sender == owner)` gate is also access control — silent."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = ("pragma solidity ^0.8.0;\ncontract C { address owner;\n"
           "  function run(address target, bytes calldata data) external {\n"
           "    require(msg.sender == owner, \"!owner\"); target.call(data); } }\n")
    assert _audit(tmp_path, "ms.sol", src) == [], "msg.sender==owner gated arbitrary call must not fire"


# ── deep-sweep wk01jvye5: container writes + high-level interface calls ──
def test_mapping_roundtrip_FIRES(tmp_path):
    """Attacker address routed through a mapping write then read into a call target — the container write
    `store[id]=target` must taint the container (was a silent FN: IndexAccess LHS was dropped)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = _HEAD + ("contract C { mapping(uint=>address) store;\n"
                   "  function exec(uint id, address target, bytes calldata data) external {\n"
                   "    store[id]=target; address t=store[id]; t.call(data); } }\n")
    assert "arbitrary_external_call" in [f["kind"] for f in _audit(tmp_path, "m.sol", src)]


def test_array_push_index_FIRES(tmp_path):
    """`targets.push(target); targets[0].call(data)` — the .push write must taint the array (was a silent
    FN: push is a FunctionCall, not an Assignment)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = _HEAD + ("contract C { address[] targets;\n"
                   "  function exec(address target, bytes calldata data) external {\n"
                   "    targets.push(target); targets[0].call(data); } }\n")
    assert "arbitrary_external_call" in [f["kind"] for f in _audit(tmp_path, "a.sol", src)]


def test_highlevel_interface_call_FIRES_downgraded(tmp_path):
    """A high-level interface call to a param target `IRouter(target).swap(data)` is a genuine arbitrary
    call (attacker picks the callee), but downgraded (low) — high-level param calls are common, so it is a
    dismissible lead, not high-severity."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = _HEAD + ("interface IR { function swap(bytes calldata) external; }\n"
                   "contract C { function exec(address target, bytes calldata data) external {\n"
                   "    IR(target).swap(data); } }\n")
    findings = [f for f in _audit(tmp_path, "h.sol", src) if f["kind"] == "arbitrary_external_call"]
    assert findings, "high-level call to an attacker target must FIRE"
    assert all(f["severity"] == "low" for f in findings), "high-level calls are downgraded leads"


def test_highlevel_call_to_constant_SILENT(tmp_path):
    """A high-level call to a NON-source receiver (a fixed state var) must stay silent."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = _HEAD + ("interface IR { function swap(bytes calldata) external; }\n"
                   "contract C { IR router;\n"
                   "  function exec(bytes calldata data) external { router.swap(data); } }\n")
    assert _audit(tmp_path, "hc.sol", src) == []


# ── cross-function / cross-file state-var taint (deep-sweep wk01jvye5) ──
def test_crossfile_statevar_delegatecall_FIRES(tmp_path):
    """Attacker addr stored in a state var in a DERIVED contract's permissionless fn, then delegatecall'd
    on that state var in a BASE-contract helper in ANOTHER FILE. Strictly intraprocedural analysis missed
    it entirely — needs cross-function state-var taint over the inheritance closure."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Vault { address impl;\n"
        "  function _exec(bytes memory d) internal { impl.delegatecall(d); } }\n")
    (tmp_path / "Proxy.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Proxy is Vault {\n"
        "  function upgrade(address newImpl, bytes calldata d) external { impl = newImpl; _exec(d); } }\n")
    findings = arbitrary_call_audit(tmp_path)
    hits = [f for f in findings if f["kind"] == "arbitrary_external_call"]
    assert hits, findings
    assert any(f["severity"] == "critical" for f in hits), "delegatecall on attacker state var is critical"


def test_statevar_constant_SILENT(tmp_path):
    """A state var assigned only a CONSTANT (not a source) must not become tainted — no fire."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    (tmp_path / "V2.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract V2 { address impl;\n"
        "  function setup() external { impl = address(0x1234); }\n"
        "  function run(bytes calldata d) external { impl.delegatecall(d); } }\n")
    assert arbitrary_call_audit(tmp_path) == []


def test_statevar_set_only_by_owner_SILENT(tmp_path):
    """A state var written ONLY in an access-controlled (onlyOwner) function is owner-trusted — consistent
    with the intra-pass AC handling; must not taint."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    (tmp_path / "V3.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract V3 { address impl; address owner;\n"
        "  modifier onlyOwner(){ require(msg.sender == owner); _; }\n"
        "  function setImpl(address a) external onlyOwner { impl = a; }\n"
        "  function run(bytes calldata d) external { impl.delegatecall(d); } }\n")
    assert arbitrary_call_audit(tmp_path) == []


def test_struct_library_method_call_SILENT(tmp_path):
    """A `using`-library method call on a struct/storage param (`s.get()`) is INTERNAL, not an external
    arbitrary call — must stay silent (the OpenZeppelin EnumerableMap/Heap/RLP FP flood)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = ("pragma solidity ^0.8.0;\n"
           "library Lib { struct S { uint x; } function get(S storage s) internal view returns (uint){ return s.x; } }\n"
           "contract C { using Lib for Lib.S; Lib.S store;\n"
           "  function f(Lib.S storage s) internal view returns (uint){ return s.get(); } }\n")
    assert _audit(tmp_path, "lib.sol", src) == []
