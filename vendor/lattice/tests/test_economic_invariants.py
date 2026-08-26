"""Economic-invariant tiers. Tier 1: LINEAR accounting via the existing conservation leg (real
Solidity). Tier 2: NONLINEAR via a symbolic operator. Tier 3: the TRUST/TAINT operator (external
manipulation). Each toggles — fires on the bug, silent on the safe version."""
import shutil, tempfile, pathlib
import pytest

pytestmark = pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed")
from lattice.intake import agent_intake


def _kinds(src):
    with tempfile.TemporaryDirectory() as td:
        (pathlib.Path(td) / "P.sol").write_text(src)
        return {f.get("kind") or f.get("type") for f in agent_intake(td, language="solidity").get("findings", [])}


_H = "pragma solidity ^0.8.0;\ncontract Pool { uint public totalBorrows; mapping(address=>uint) public debt;\n"


def test_tier1_lending_accounting_leak_fires():
    assert "value_conservation" in _kinds(_H + " function borrow(uint a) public { debt[msg.sender]+=a; } }\n")


def test_tier1_correct_lending_silent():
    assert "value_conservation" not in _kinds(
        _H + " function borrow(uint a) public { debt[msg.sender]+=a; totalBorrows+=a; } }\n")


# ── Tier 2: NONLINEAR (symbolic) — AMM constant product x*y=k ──
def test_tier2_amm_product_break_fires():
    sp = pytest.importorskip("sympy", reason="symbolic extra not installed")
    from lattice.symbolic_conservation import symbolic_conservation
    x, y, dx = sp.symbols("x y dx", positive=True)
    q = x * y
    fair = {"op": "fair_swap", "update": {x: x + dx, y: x * y / (x + dx)}}   # preserves x*y
    drain = {"op": "draining_swap", "update": {x: x + dx, y: y - dx}}        # linear payout — drains
    fired = {r["op"] for r in symbolic_conservation(q, [fair, drain])}
    assert "draining_swap" in fired and "fair_swap" not in fired


def test_tier2_subsumes_linear():
    sp = pytest.importorskip("sympy", reason="symbolic extra not installed")
    from lattice.symbolic_conservation import symbolic_conservation
    s, b, a = sp.symbols("totalSupply balance amt")
    q = s - b
    ok = {"op": "mint", "update": {s: s + a, b: b + a}}        # both move — conserved
    bad = {"op": "freemint", "update": {s: s + a}}             # supply up, balance not
    fired = {r["op"] for r in symbolic_conservation(q, [ok, bad])}
    assert "freemint" in fired and "mint" not in fired


# ── Tier 3: TRUST/TAINT — oracle manipulation reaching a valuation sink ──
def test_tier3_manipulable_oracle_reaches_sink():
    from lattice.taint import trust_obstructions
    deps = {"spot_price": ["amm_reserves"], "collateral_value": ["spot_price", "amount"],
            "loan_approved": ["collateral_value"]}
    hit = trust_obstructions(deps, sources={"amm_reserves"}, sinks={"loan_approved"})
    assert any(h["sink"] == "loan_approved" for h in hit)


def test_tier3_twap_sanitizer_breaks_flow():
    from lattice.taint import trust_obstructions
    deps = {"twap": ["amm_reserves"], "collateral_value": ["twap", "amount"],
            "loan_approved": ["collateral_value"]}
    hit = trust_obstructions(deps, sources={"amm_reserves"}, sinks={"loan_approved"}, sanitizers={"twap"})
    assert hit == []
