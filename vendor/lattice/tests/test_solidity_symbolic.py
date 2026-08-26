"""TIER-2 INGEST — symbolic-execution-lite for the AMM constant-product invariant.

DISCIPLINE: a happy-path toggle passing is not proof. The two end-to-end tests parse REAL Solidity
through solc 0.8.x and assert the ingest is SILENT on the correct constant-product swap (x*y is
preserved) and FIRES on the buggy linear swap (x*y drifts). Plus unit tests for the translator
and the reserve-pair detector so a regression is localised."""
import shutil
import tempfile
import pathlib

import pytest

sp = pytest.importorskip("sympy", reason="symbolic extra not installed")

pytestmark = pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed")

from lattice.ingest.solidity_symbolic import (
    amm_invariant_audit, _translate, _unwrap_tuple, _find_reserve_updates,
    _state_vars, _Untranslatable,
)
from lattice.ingest.solidity import _solc_ast, _iter


# CORRECT: constant-product swap. amountOut = (reserveOut*amountIn)/(reserveIn+amountIn). x*y preserved.
_CORRECT = """pragma solidity ^0.8.0;
contract Pool {
    uint256 public reserveIn;
    uint256 public reserveOut;
    function swap(uint256 amountIn) public {
        uint256 amountOut = (reserveOut * amountIn) / (reserveIn + amountIn);
        reserveIn += amountIn;
        reserveOut -= amountOut;
    }
}
"""

# BUGGY: linear swap. amountOut = amountIn (1:1 payout). x*y is NOT preserved -> drains the pool.
_BUGGY = """pragma solidity ^0.8.0;
contract Pool {
    uint256 public reserveIn;
    uint256 public reserveOut;
    function swap(uint256 amountIn) public {
        uint256 amountOut = amountIn;
        reserveIn += amountIn;
        reserveOut -= amountOut;
    }
}
"""


def _audit(src):
    with tempfile.TemporaryDirectory() as td:
        (pathlib.Path(td) / "P.sol").write_text(src)
        return amm_invariant_audit(td)


# ── End-to-end TOGGLE on REAL solc-parsed Solidity ──────────────────────────────────────────────
def test_correct_constant_product_swap_is_silent():
    findings = _audit(_CORRECT)
    assert findings == [], f"correct constant-product swap should preserve x*y; got {findings}"


def test_buggy_linear_swap_fires():
    findings = _audit(_BUGGY)
    assert len(findings) == 1, f"buggy linear swap should break x*y exactly once; got {findings}"
    f = findings[0]
    assert f["kind"] == "invariant_break"
    assert f["function"] == "swap"
    assert set(f["reserves"]) == {"reserveIn", "reserveOut"}
    assert sp.simplify(f["drift"]) != 0    # nonzero symbolic drift = value created/destroyed


def test_toggle_distinguishes_the_two():
    """The whole point: same shape, one math change, opposite verdicts."""
    assert _audit(_CORRECT) == []
    assert len(_audit(_BUGGY)) == 1


# ── Unit: the translator handles the lite grammar ───────────────────────────────────────────────
def _expr_ast(src_expr):
    """Parse `uint256 r = <expr>;` and return the initialValue node, for translator unit tests."""
    src = ("pragma solidity ^0.8.0;\ncontract C {\n uint256 a; uint256 b;\n"
           " function f(uint256 c) public { uint256 r = " + src_expr + "; a += c; b -= r; } }\n")
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "C.sol"
        p.write_text(src)
        ast = _solc_ast(p)
    fn = next(f for f in _iter(ast, "FunctionDefinition") if f.get("name") == "f")
    for stmt in fn["body"]["statements"]:
        if stmt.get("nodeType") == "VariableDeclarationStatement":
            return stmt["initialValue"]
    raise AssertionError("no decl found")


def test_translate_arithmetic_and_parens():
    a, b, c = sp.symbols("a b c", positive=True)
    syms = {}
    expr = _translate(_expr_ast("(b * c) / (a + c)"), {}, syms)
    assert sp.simplify(expr - (b * c) / (a + c)) == 0


def test_translate_resolves_locals_through_env():
    a, c = sp.symbols("a c", positive=True)
    syms = {}
    # env binds local `t` to a+c; referencing t must resolve to a+c, not a free symbol
    expr = _translate(_expr_ast("t + a"), {"t": a + c}, syms)
    assert sp.simplify(expr - (2 * a + c)) == 0


def test_translate_literal():
    syms = {}
    assert _translate(_expr_ast("a * 2"), {}, syms) == sp.Symbol("a", positive=True) * 2


def test_translate_rejects_unmodeled_shape():
    # a function call (e.g. sqrt(x)) is outside the lite grammar -> _Untranslatable, caller skips
    node = _expr_ast("a + c")
    fake_call = {"nodeType": "FunctionCall", "expression": node}
    with pytest.raises(_Untranslatable):
        _translate(fake_call, {}, {})


def test_unwrap_single_component_tuple():
    inner = {"nodeType": "Identifier", "name": "x"}
    wrapped = {"nodeType": "TupleExpression", "components": [inner]}
    assert _unwrap_tuple(wrapped) is inner


# ── Unit: the reserve-pair detector ─────────────────────────────────────────────────────────────
def _contract_ast(src):
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "P.sol"
        p.write_text(src)
        ast = _solc_ast(p)
    return next(_iter(ast, "ContractDefinition"))


def test_detects_opposite_direction_reserve_pair():
    c = _contract_ast(_BUGGY)
    sv = _state_vars(c)
    assert sv == {"reserveIn", "reserveOut"}
    fn = next(f for f in c["nodes"]
              if f.get("nodeType") == "FunctionDefinition" and f.get("name") == "swap")
    pair = _find_reserve_updates(fn, sv)
    assert pair is not None
    plus_var, _, minus_var, _ = pair
    assert plus_var == "reserveIn" and minus_var == "reserveOut"


def test_no_pair_when_both_same_direction():
    # both '+=' -> not an opposite-direction swap; detector returns None (not a reserve pair)
    src = """pragma solidity ^0.8.0;
contract P { uint256 x; uint256 y;
 function f(uint256 a) public { x += a; y += a; } }
"""
    c = _contract_ast(src)
    fn = next(f for f in c["nodes"] if f.get("nodeType") == "FunctionDefinition")
    assert _find_reserve_updates(fn, _state_vars(c)) is None


def test_no_pair_when_three_state_writes():
    # three compound writes (not exactly one '+=' and one '-=') -> ambiguous, returns None
    src = """pragma solidity ^0.8.0;
contract P { uint256 x; uint256 y; uint256 z;
 function f(uint256 a) public { x += a; y -= a; z -= a; } }
"""
    c = _contract_ast(src)
    fn = next(f for f in c["nodes"] if f.get("nodeType") == "FunctionDefinition")
    assert _find_reserve_updates(fn, _state_vars(c)) is None


# ── regression: the false positive adversarial verification caught (untranslatable-via-local) ──
def _amm_fires(tmp_path, body):
    import pathlib
    from lattice.ingest.solidity_symbolic import amm_invariant_audit
    (tmp_path / "A.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract AMM { uint public reserveIn; uint public reserveOut;\n" + body + "\n}")
    return bool(amm_invariant_audit(str(tmp_path)))


def test_correct_swap_payout_via_cast_local_is_silent(tmp_path):
    """A CORRECT constant-product swap whose payout flows through an untranslatable local (a cast)
    must NOT fire — the poisoned local must skip the update, not mint a free symbol (the FP)."""
    assert not _amm_fires(tmp_path,
        "function swap(uint a) public { uint o=uint128((reserveOut*a)/(reserveIn+a)); reserveIn+=a; reserveOut-=o; }")


def test_correct_swap_payout_via_call_local_is_silent(tmp_path):
    """Same, via an oracle/helper call local — this is the prescribed Tier-3 fix shape; must be silent."""
    assert not _amm_fires(tmp_path,
        "function swap(uint a) public { uint o=quote(a); reserveIn+=a; reserveOut-=o; }\n"
        " function quote(uint a) internal returns(uint){ return (reserveOut*a)/(reserveIn+a); }")


# ── flesh-out: fee-bearing AMMs (invariant is x*y NON-DECREASING, not == k) ──
def test_uniswap_fee_swap_is_silent(tmp_path):
    """A correct 0.3%-fee Uniswap-style swap GROWS x*y (fee accrues) — it must NOT fire. The
    exact-equality check used to false-positive on every real fee-bearing swap."""
    assert not _amm_fires(tmp_path,
        "function swap(uint a) public {\n"
        "  uint f = a * 997; uint num = f * reserveOut; uint den = reserveIn * 1000 + f;\n"
        "  uint o = num / den; reserveIn += a; reserveOut -= o; }")


def test_draining_swap_fires_with_witness(tmp_path):
    """A draining swap DECREASES x*y for some input — it fires, and the operator returns a concrete
    positive witness input that drains the pool."""
    import pathlib
    from lattice.ingest.solidity_symbolic import amm_invariant_audit
    (tmp_path / "A.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract AMM { uint public reserveIn; uint public reserveOut;\n"
        " function swap(uint a) public { uint o=a; reserveIn+=a; reserveOut-=o; } }")
    findings = amm_invariant_audit(str(tmp_path))
    assert findings and findings[0]["witness"]   # a non-empty draining witness


def test_plain_assign_reserve_form(tmp_path):
    """A swap written with plain '=' (reserve = reserve + a) is recognized like '+='/'-='."""
    import pathlib
    from lattice.ingest.solidity_symbolic import amm_invariant_audit
    def fires(body):
        (tmp_path / "A.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract AMM { uint public r0; uint public r1;\n" + body + "\n}")
        return bool(amm_invariant_audit(str(tmp_path)))
    assert not fires("function swap(uint a) public { uint o=(r1*a)/(r0+a); r0=r0+a; r1=r1-o; }")  # correct
    assert fires("function swap(uint a) public { uint o=a; r0=r0+a; r1=r1-o; }")                   # drain
