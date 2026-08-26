"""TIER-3 ingest proof: oracle / spot-price taint reaches the trust operator on REAL solc-parsed
Solidity. The load-bearing test is the TOGGLE: a lending contract that prices collateral from a SPOT
read (getReserves) and gates a transfer on it must FIRE 'untrusted_flow'; the byte-identical contract
that prices via a TWAP/chainlink read (a sanitizer) must be SILENT.

These run against the real compiler via _solc_ast; they skip if no usable solc is installed rather than
pass vacuously.
"""
import pathlib

import pytest

from lattice.ingest.solidity import _solc_ast
from lattice.ingest.solidity_taint import (
    oracle_taint_audit, _names_in, _is_spot_priced, _is_sanitized,
)


def _parses(tmp_path) -> bool:
    """Guard: confirm the local solc actually parses a trivial contract; skip if not."""
    (tmp_path / "_probe.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract P { function f() public pure returns (uint){ return 1; } }\n")
    return _solc_ast(tmp_path / "_probe.sol") is not None


# A lending contract priced off a SPOT AMM reserve read, gating a transfer on the valuation. BUGGY.
_SPOT = """pragma solidity ^0.8.0;
interface IPair { function getReserves() external view returns (uint112, uint112, uint32); }
contract LendSpot {
    IPair pair;
    function borrow(uint collateral, address payable to) public {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint price = uint(r0) * 1e18 / uint(r1);
        uint value = collateral * price;
        require(value > 1000, "undercollateralized");
        to.transfer(value);
    }
}
"""

# Byte-identical EXCEPT the price comes from a TWAP oracle (a sanitizer). CORRECT.
_TWAP = """pragma solidity ^0.8.0;
interface IOracle { function consult(address token, uint amountIn) external view returns (uint); }
contract LendTwap {
    IOracle oracle;
    function borrow(uint collateral, address payable to) public {
        uint price = oracle.consult(address(this), 1e18);
        uint value = collateral * price;
        require(value > 1000, "undercollateralized");
        to.transfer(value);
    }
}
"""

# Chainlink-style feed — also a sanitizer (latestRoundData). CORRECT.
_CHAINLINK = """pragma solidity ^0.8.0;
interface IFeed { function latestRoundData() external view returns (uint80, int, uint, uint, uint80); }
contract LendChainlink {
    IFeed feed;
    function borrow(uint collateral, address payable to) public {
        (, int answer, , , ) = feed.latestRoundData();
        uint price = uint(answer);
        uint value = collateral * price;
        require(value > 1000, "undercollateralized");
        to.transfer(value);
    }
}
"""


def _audit_src(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return oracle_taint_audit(p)


# ---------------------------------------------------------------------------- the TOGGLE (end-to-end)

def test_spot_priced_lending_FIRES(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    findings = _audit_src(tmp_path, "spot.sol", _SPOT)
    kinds = [f["kind"] for f in findings]
    assert "untrusted_flow" in kinds, f"expected oracle-manipulation finding, got {findings}"
    fn = {f["function"] for f in findings if f["kind"] == "untrusted_flow"}
    assert "borrow" in fn


def test_twap_priced_lending_SILENT(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    findings = _audit_src(tmp_path, "twap.sol", _TWAP)
    assert findings == [], f"TWAP-sanitized price must NOT fire, got {findings}"


def test_chainlink_priced_lending_SILENT(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    findings = _audit_src(tmp_path, "chainlink.sol", _CHAINLINK)
    assert findings == [], f"chainlink-sanitized price must NOT fire, got {findings}"


def test_toggle_is_genuine(tmp_path):
    """The contracts differ ONLY in the price source; the audit must discriminate them."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    spot = _audit_src(tmp_path, "s.sol", _SPOT)
    twap = _audit_src(tmp_path, "t.sol", _TWAP)
    assert spot and not twap


# ---------------------------------------------------------------------------- structural unit tests

def test_names_in_collects_idents_and_member_calls(tmp_path):
    """The dependency footprint must include plain identifiers AND called member/function names."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = ("pragma solidity ^0.8.0;\n"
           "interface I { function getReserves() external view returns (uint,uint); }\n"
           "contract C { I pair; function f() public view returns (uint){\n"
           "  (uint a, uint b) = pair.getReserves(); return a + b; } }\n")
    p = tmp_path / "n.sol"
    p.write_text(src)
    ast = _solc_ast(p)
    # find the VariableDeclarationStatement initialValue (the getReserves call)
    from lattice.ingest.solidity import _iter
    init = next(_iter(ast, "VariableDeclarationStatement")).get("initialValue")
    names = _names_in(init)
    assert "pair" in names and "getReserves" in names


def test_spot_and_sanitizer_classifiers():
    assert _is_spot_priced({"pair", "getReserves"})
    assert _is_spot_priced({"reserve0", "reserve1"})        # reserve-named vars => spot
    assert not _is_spot_priced({"oracle", "consult"})
    assert _is_sanitized({"oracle", "consult"})
    assert _is_sanitized({"feed", "latestRoundData"})
    assert not _is_sanitized({"pair", "getReserves"})


def test_view_only_require_does_not_fire(tmp_path):
    """A require gate with NO payout in the function is not a loan decision — must stay silent."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = ("pragma solidity ^0.8.0;\n"
           "interface IPair { function getReserves() external view returns (uint112,uint112,uint32); }\n"
           "contract V { IPair pair;\n"
           "  function check() public view returns (bool){\n"
           "    (uint112 r0, uint112 r1, ) = pair.getReserves();\n"
           "    uint price = uint(r0) * 1e18 / uint(r1);\n"
           "    require(price > 0, \"zero\"); return true; } }\n")
    p = tmp_path / "v.sol"
    p.write_text(src)
    assert oracle_taint_audit(p) == []


# ── flesh-out: INTERPROCEDURAL — follow price helpers across the call graph ──
_IFACE = ("pragma solidity ^0.8.0;\n"
          "interface IPair { function getReserves() external view returns (uint,uint); }\n"
          "interface IOracle { function consult(uint) external view returns (uint); }\n"
          "contract Lend { IPair pair; IOracle oracle; uint debt;\n")


def _taint_fns(tmp_path, body):
    import pathlib
    from lattice.ingest.solidity_taint import oracle_taint_audit
    (tmp_path / "L.sol").write_text(_IFACE + body + "\n}")
    return {f.get("function") for f in oracle_taint_audit(str(tmp_path))}


def test_interprocedural_spot_helper_fires(tmp_path):
    """A spot price computed in a HELPER and used by borrow() must fire — previously a silent FN."""
    got = _taint_fns(tmp_path,
        "function _spotPrice() internal view returns (uint) { (uint r0,uint r1)=pair.getReserves(); return r0/r1; }\n"
        "function borrow(uint c) public { uint v=_spotPrice()*c; require(v>debt); payable(msg.sender).transfer(c); }")
    assert "borrow" in got


def test_interprocedural_twap_helper_silent(tmp_path):
    """The same shape but priced via a TWAP helper must stay silent (the helper sanitizes)."""
    got = _taint_fns(tmp_path,
        "function _twapPrice() internal view returns (uint) { return oracle.consult(1e18); }\n"
        "function borrow(uint c) public { uint v=_twapPrice()*c; require(v>debt); payable(msg.sender).transfer(c); }")
    assert "borrow" not in got


# ── flesh-out: fixpoint across CONTRACT INHERITANCE (base-contract price helpers) ──
def test_inherited_spot_helper_fires(tmp_path):
    """A spot price helper defined in a BASE contract, called by a derived loan function, fires."""
    import pathlib
    from lattice.ingest.solidity_taint import oracle_taint_audit
    (tmp_path / "A.sol").write_text(_IFACE.replace("contract Lend { IPair pair; IOracle oracle; uint debt;\n", "") +
        "contract Base { IPair pair; function _spotPrice() internal view returns(uint){ (uint r0,uint r1)=pair.getReserves(); return r0/r1; } }\n"
        "contract Lend is Base { uint debt; function borrow(uint c) public { uint v=_spotPrice()*c; require(v>debt); payable(msg.sender).transfer(c); } }")
    assert "borrow" in {f.get("function") for f in oracle_taint_audit(str(tmp_path))}


def test_inherited_twap_helper_silent(tmp_path):
    """The same shape but the base helper prices via a TWAP read stays silent."""
    import pathlib
    from lattice.ingest.solidity_taint import oracle_taint_audit
    (tmp_path / "A.sol").write_text(_IFACE.replace("contract Lend { IPair pair; IOracle oracle; uint debt;\n", "") +
        "contract Base { IOracle oracle; function _price() internal view returns(uint){ return oracle.consult(1e18); } }\n"
        "contract Lend is Base { uint debt; function borrow(uint c) public { uint v=_price()*c; require(v>debt); payable(msg.sender).transfer(c); } }")
    assert "borrow" not in {f.get("function") for f in oracle_taint_audit(str(tmp_path))}


def test_cross_file_inherited_spot_helper_fires(tmp_path):
    """A base price helper in a SEPARATE file (the project-wide pre-pass) is still followed."""
    import pathlib
    from lattice.ingest.solidity_taint import oracle_taint_audit
    (tmp_path / "Base.sol").write_text(
        "pragma solidity ^0.8.0;\ninterface IPair { function getReserves() external view returns (uint,uint); }\n"
        "contract Base { IPair pair; function _spotPrice() internal view returns(uint){ (uint r0,uint r1)=pair.getReserves(); return r0/r1; } }")
    (tmp_path / "Lend.sol").write_text(
        "pragma solidity ^0.8.0;\nimport './Base.sol';\n"
        "contract Lend is Base { uint debt; function borrow(uint c) public { uint v=_spotPrice()*c; require(v>debt); payable(msg.sender).transfer(c); } }")
    assert "borrow" in {f.get("function") for f in oracle_taint_audit(str(tmp_path))}


# ── close the last 3 limits: external modules, C3 override, name-mix, path gate ──
_PIF = ("pragma solidity ^0.8.0;\n"
        "interface IPair { function getReserves() external view returns (uint,uint); }\n"
        "interface IOracle { function consult(uint) external view returns (uint); }\n")


def _audit_fns(tmp_path, files):
    from lattice.ingest.solidity_taint import oracle_taint_audit
    for fn, src in files.items():
        (tmp_path / fn).write_text(src)
    return {f.get("function") for f in oracle_taint_audit(str(tmp_path))}


def test_external_spot_price_module_fires(tmp_path):
    """A spot price read in a SEPARATE composed contract (not a base) is followed (cross-contract)."""
    got = _audit_fns(tmp_path, {"A.sol": _PIF +
        "contract PriceModule { IPair pair; function getPrice() external view returns(uint){ (uint a,uint b)=pair.getReserves(); return a/b; } }\n"
        "contract Lend { PriceModule pm; uint debt; function borrow(uint c) public { uint v=pm.getPrice()*c; require(v>debt); payable(msg.sender).transfer(c); } }"})
    assert "borrow" in got


def test_c3_derived_twap_override_silent(tmp_path):
    """A base spot getPrice() OVERRIDDEN in a derived contract by a TWAP read: C3 picks the derived
    (twap) — silent. (Name-keyed last-wins would have been order-dependent.)"""
    got = _audit_fns(tmp_path, {"A.sol": _PIF +
        "contract A { IPair pair; function getPrice() internal view virtual returns(uint){ (uint a,uint b)=pair.getReserves(); return a/b; } }\n"
        "contract B is A { IOracle oracle; function getPrice() internal view virtual override returns(uint){ return oracle.consult(1); } }\n"
        "contract Lend is B { uint debt; function borrow(uint c) public { uint v=getPrice()*c; require(v>debt); payable(msg.sender).transfer(c); } }"})
    assert "borrow" not in got


def test_min_spot_twap_mix_fires(tmp_path):
    """min(spot, twap) is still manipulable (skew spot below twap) — transitive-footprint
    classification taints it despite the 'twap' name, so it fires."""
    got = _audit_fns(tmp_path, {"L.sol": _PIF +
        "contract Lend { IPair pair; IOracle oracle; uint debt; function borrow(uint c) public {"
        " (uint a,uint b)=pair.getReserves(); uint spot=a/b; uint twap=oracle.consult(1);"
        " uint price=spot<twap?spot:twap; require(price>debt); payable(msg.sender).transfer(c); } }"})
    assert "borrow" in got


def test_unrelated_refund_before_spot_require_silent(tmp_path):
    """Path gate: an unrelated guarded refund BEFORE a read-only spot require (no payout after it)
    no longer over-flags."""
    got = _audit_fns(tmp_path, {"L.sol": _PIF +
        "contract Lend { IPair pair; uint debt; address refund; function f(uint c) public {"
        " payable(refund).transfer(c); (uint a,uint b)=pair.getReserves(); uint ratio=a/b; require(ratio>0); } }"})
    assert got == set()


# ── DVD ground-truth gap: a helper that DIRECTLY returns a spot read (no intermediate local) ──
def test_inline_return_spot_helper_fires(tmp_path):
    """The Damn-Vulnerable-DeFi `puppet` idiom: a price helper RETURNS the spot read inline
    (`return pair.balance * 1e18 / token.balanceOf(pair);`) rather than binding it to a local first.
    The existing interprocedural test bound reserves to locals (r0,r1) — so `_graph` saw them as
    sources. With an inline return there is no assigned local, so the old `_return_taint_of` (which
    only looked for a tainted LOCAL in the return) classified the helper as clean — a silent FN that
    cascaded through the whole call chain. The two-hop chain (borrow → calc → _price) must FIRE."""
    got = _taint_fns(tmp_path,
        "function _price() internal view returns (uint) { return pair.getReserves(); }\n"
        "function _calc(uint a) internal view returns (uint) { return a * _price(); }\n"
        "function borrow(uint c) public { uint v=_calc(c); require(msg.value>=v); payable(msg.sender).transfer(c); }")
    assert "borrow" in got, "inline-return spot price (the puppet idiom) must fire"


def test_own_balance_amount_downgraded_low(tmp_path):
    """balanceOf(address(this)) is the contract's OWN balance used as an AMOUNT, not a manipulable spot
    price (a price reads ANOTHER address's balance / a reserve). Sweeping it must NOT be a HIGH-severity
    oracle-manipulation claim — the dominant Fei FP class. Footing-safe: it still surfaces (no silent-FN),
    honestly labeled low-confidence so the adjudicator can deprioritize it."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    src = ("pragma solidity ^0.8.0;\n"
           "interface IERC20 { function balanceOf(address) external view returns (uint); }\n"
           "contract Vault { IERC20 token;\n"
           "  function sweep(address payable to) public {\n"
           "    uint bal = token.balanceOf(address(this));\n"
           "    require(bal > 0); to.transfer(bal); } }\n")
    findings = _audit_src(tmp_path, "own.sol", src)
    flows = [f for f in findings if f["kind"] == "untrusted_flow"]
    assert all(f.get("confidence") == "low" and f.get("severity") == "low" for f in flows), \
        f"own-balance amount must be downgraded to low-confidence, not high oracle manipulation: {flows}"


def test_other_address_balance_price_stays_high(tmp_path):
    """balanceOf of ANOTHER address (the pool) reaching a payout IS oracle-manipulable (the puppet
    class) — must stay a real (non-downgraded) finding."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc")
    src = ("pragma solidity ^0.8.0;\n"
           "interface IERC20 { function balanceOf(address) external view returns (uint); }\n"
           "contract Lend { IERC20 token; address pair;\n"
           "  function borrow(address payable to) public {\n"
           "    uint price = token.balanceOf(pair) * 1e18 / 1000;\n"
           "    require(price > 1); to.transfer(price); } }\n")
    flows = [f for f in _audit_src(tmp_path, "pool.sol", src) if f["kind"] == "untrusted_flow"]
    assert flows and any(f.get("confidence") != "low" for f in flows), \
        "another address's balance as a price must stay a real (non-downgraded) finding"


def test_inline_return_twap_helper_silent(tmp_path):
    """Same inline-return shape but priced via a TWAP read stays silent — the inline-return fix must
    not over-fire on the sanitized version (the genuine toggle)."""
    got = _taint_fns(tmp_path,
        "function _price() internal view returns (uint) { return oracle.consult(1e18); }\n"
        "function _calc(uint a) internal view returns (uint) { return a * _price(); }\n"
        "function borrow(uint c) public { uint v=_calc(c); require(msg.value>=v); payable(msg.sender).transfer(c); }")
    assert "borrow" not in got, "inline-return TWAP price must stay silent"


# ── DVD ground-truth gap: oracle-priced COLLATERAL lands in transferFrom (the pull), not transfer ──
def test_oracle_priced_collateral_transferFrom_fires(tmp_path):
    """The Damn-Vulnerable-DeFi `puppet-v2` idiom: the manipulable spot price sets the COLLATERAL the
    borrower must deposit, and that tainted amount lands in `weth.transferFrom(msg.sender, this, amount)`
    — a value-moving primitive that is a collateral PULL, not a payout. `_TRANSFER_MEMBERS` only knew
    `transfer`/`send`, so the tainted `amount` never reached a recognised sink and the bug was silent.
    transferFrom moves value too; a spot-tainted amount reaching it is the oracle-manipulation sink."""
    got = _taint_fns(tmp_path,
        "function _quote(uint amt) internal view returns (uint) { (uint a,uint b)=pair.getReserves(); return amt*a/b; }\n"
        "function borrow(uint borrowAmount) public {"
        " uint amount=_quote(borrowAmount);"
        " weth.transferFrom(msg.sender, address(this), amount);"
        " token.transfer(msg.sender, borrowAmount); }")
    assert "borrow" in got, "oracle-priced collateral in transferFrom must fire"


def test_untainted_transferFrom_silent(tmp_path):
    """transferFrom of a NON-spot amount (a plain user-supplied value) must stay silent — the
    transferFrom recognition is taint-gated, not a blanket fire on every transferFrom."""
    got = _taint_fns(tmp_path,
        "function deposit(uint amt) public {"
        " token.transferFrom(msg.sender, address(this), amt);"
        " debt += amt; }")
    assert "deposit" not in got, "a transferFrom with no spot-tainted amount must stay silent"
