"""DONATION / EXTERNAL-BALANCE griefing detector — the Tier-3 external-manipulation slice the
economic-invariant-probe named but had not yet built ("donation-inflation via direct transfer;
token.balanceOf(this) is externally writable").

The bug class (Damn-Vulnerable-DeFi `unstoppable`, and the general ERC4626 inflation/donation attack):
a contract treats `token.balanceOf(address(this))` — which ANYONE can change by a direct transfer —
as accounting truth, comparing it against an INTERNAL supply variable (`totalSupply`/`totalShares`).
A 1-wei donation breaks the equality, so the invariant assertion either DoS-reverts every call or
inflates the share price. The structural signature: a require/if comparison with OWN-BALANCE on one
side and INTERNAL accounting on the other.

The load-bearing test is the TOGGLE: a vault that asserts `f(balanceOf(this)) <op> g(totalSupply)`
must FIRE; the byte-identical vault that compares two INTERNAL accounting variables (no
externally-writable own-balance read) must be SILENT.
"""
import pathlib

import pytest

from lattice.ingest.solidity import _solc_ast
from lattice.ingest.solidity_donation import donation_griefing_audit


def _parses(tmp_path) -> bool:
    (tmp_path / "_probe.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract P { function f() public pure returns (uint){ return 1; } }\n")
    return _solc_ast(tmp_path / "_probe.sol") is not None


_IFACE = ("pragma solidity ^0.8.0;\n"
          "interface IERC20 { function balanceOf(address) external view returns (uint); }\n")

# OWN-BALANCE read (via a totalAssets() helper) asserted against the INTERNAL totalSupply. BUGGY —
# a direct donation to the vault breaks `convertToShares(totalSupply) == balanceOf(this)` → DoS.
_DONATION = _IFACE + (
    "contract Vault {\n"
    "  IERC20 asset; uint256 public totalSupply;\n"
    "  function totalAssets() public view returns (uint) { return asset.balanceOf(address(this)); }\n"
    "  function convertToShares(uint a) public view returns (uint) { return a; }\n"
    "  function flashLoan(uint amount) external {\n"
    "    uint balanceBefore = totalAssets();\n"
    "    if (convertToShares(totalSupply) != balanceBefore) revert();\n"
    "  }\n"
    "}\n")

# Byte-identical EXCEPT it tracks its own accounting var (updated on deposit/withdraw) instead of
# reading balanceOf(this). No externally-writable own-balance => NOT donation-griefable. CORRECT.
_TRACKED = _IFACE + (
    "contract Vault {\n"
    "  uint256 public totalSupply; uint256 public reserves;\n"
    "  function flashLoan(uint amount) external {\n"
    "    uint balanceBefore = reserves;\n"
    "    if (totalSupply != balanceBefore) revert();\n"
    "  }\n"
    "}\n")


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return donation_griefing_audit(p)


def test_donation_invariant_FIRES(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    findings = _audit(tmp_path, "donation.sol", _DONATION)
    kinds = [f["kind"] for f in findings]
    assert "balance_invariant_griefable" in kinds, f"expected donation-griefing finding, got {findings}"
    fns = {f["function"] for f in findings}
    assert "flashLoan" in fns


def test_tracked_accounting_SILENT(tmp_path):
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    findings = _audit(tmp_path, "tracked.sol", _TRACKED)
    assert findings == [], f"two internal accounting vars must NOT fire, got {findings}"


def test_toggle_is_genuine(tmp_path):
    """The two vaults differ ONLY in own-balance-read vs tracked-var; the audit must discriminate."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    assert _audit(tmp_path, "d.sol", _DONATION) and not _audit(tmp_path, "t.sol", _TRACKED)


def test_own_balance_helper_alone_silent(tmp_path):
    """A function that READS balanceOf(this) but does not compare it to internal accounting (just a
    plain getter like totalAssets) is not an invariant assertion — must stay silent (no over-flag)."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = _IFACE + ("contract V { IERC20 asset;\n"
                    "  function totalAssets() public view returns (uint){ return asset.balanceOf(address(this)); } }\n")
    assert _audit(tmp_path, "g.sol", src) == []


def test_balanceof_other_address_silent(tmp_path):
    """balanceOf of ANOTHER address (not this) compared to a supply var is not donation-griefable —
    own-balance is specifically `balanceOf(address(this))`. Must stay silent."""
    if not _parses(tmp_path):
        pytest.skip("no usable solc installed")
    src = _IFACE + ("contract V { IERC20 asset; address other; uint256 public totalSupply;\n"
                    "  function f() external { uint b = asset.balanceOf(other);\n"
                    "    if (totalSupply != b) revert(); } }\n")
    assert _audit(tmp_path, "o.sol", src) == []
