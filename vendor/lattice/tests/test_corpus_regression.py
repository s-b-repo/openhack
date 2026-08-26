"""PERMANENT GROUND-TRUTH REGRESSION GATE.

Runs Footings against REAL vulnerable corpora (not synthetic unit tests) and asserts recall
FLOORS + an FP CEILING on audited code. This guards the one failure mode that recurred all
through development: a hand-written test passing while the real-world idiom slips through
(the explicit-`storage` alias vs the `var` alias, the `.send()` vs `.transfer()` uninit pointer,
the SafeMath suppression, the low-level vs high-level modifier call). Hand tests verify your
mental model; only ground truth verifies the model matches deployed code.

It is SLOW (hundreds of contracts) and OPT-IN — it does not run on a normal `pytest` invocation.
Run it deliberately before changing a detector:

    FOOTINGS_CORPUS_GATE=1 pytest tests/test_corpus_regression.py -v

Corpus locations are configurable via env (defaults point at the durable copies):
    FOOTINGS_SMARTBUGS  -> smartbugs-curated dataset dir
    FOOTINGS_CORPUS     -> dir holding solidifi/ and oz/ (default ~/.footings-corpus)
A corpus that is absent skips its own assertions, so the gate degrades gracefully.
"""
import os
import shutil
import tempfile
import pathlib
import pytest
from lattice.ingest.solidity import solidity_audit

_GATE = os.environ.get("FOOTINGS_CORPUS_GATE")
pytestmark = [
    pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed"),
    pytest.mark.skipif(not _GATE, reason="set FOOTINGS_CORPUS_GATE=1 to run the (slow) corpus gate"),
]

_CORPUS = pathlib.Path(os.environ.get("FOOTINGS_CORPUS", pathlib.Path.home() / ".footings-corpus"))
SMARTBUGS = pathlib.Path(os.environ.get(
    "FOOTINGS_SMARTBUGS",
    "/Users/hendrixx./Defi-github/defi-v2/datasets/raw/smartbugs-curated/dataset"))
SOLIDIFI = _CORPUS / "solidifi" / "buggy_contracts"
OZ = _CORPUS / "oz" / "contracts"


def _kinds(path: pathlib.Path) -> set:
    """Footings finding-kinds for one contract, analysed in isolation."""
    with tempfile.TemporaryDirectory() as td:
        shutil.copy(path, pathlib.Path(td) / path.name)
        try:
            return {f["kind"] for f in solidity_audit(td)}
        except Exception:
            return set()


def _recall(base: pathlib.Path, cat: str, expected: set, flat: bool) -> int:
    d = base / cat
    sols = sorted(d.glob("*.sol") if flat else d.rglob("*.sol"))
    return sum(bool(_kinds(s) & expected) for s in sols)


# ── recall FLOORS: the current validated numbers; dropping below any FAILS the gate ──
SB_FLOOR = {
    "reentrancy": ({"reentrancy"}, 30),
    "unchecked_low_level_calls": ({"unchecked_external_call"}, 52),
    "access_control": ({"unprotected_state_write", "unprotected_selfdestruct",
                        "unprotected_delegatecall", "tx_origin_auth"}, 12),
    "arithmetic": ({"unchecked_arithmetic"}, 13),
    "bad_randomness": ({"weak_randomness"}, 8),
    "denial_of_service": ({"dos_unbounded_loop", "dos_gas_griefing", "dos_push_payment"}, 5),
    "time_manipulation": ({"timestamp_dependence"}, 4),
    "other": ({"uninitialized_storage_pointer", "contains_assembly"}, 3),
}


@pytest.mark.skipif(not SMARTBUGS.is_dir(), reason="smartbugs corpus not present")
@pytest.mark.parametrize("cat", list(SB_FLOOR))
def test_smartbugs_recall_floor(cat):
    expected, floor = SB_FLOOR[cat]
    hit = _recall(SMARTBUGS, cat, expected, flat=False)
    assert hit >= floor, f"smartbugs {cat} recall {hit} < floor {floor} — RECALL REGRESSION"


SF_FLOOR = {
    "Re-entrancy": ({"reentrancy"}, 50),
    "Overflow-Underflow": ({"unchecked_arithmetic"}, 50),
    "Timestamp-Dependency": ({"timestamp_dependence"}, 50),
    "tx.origin": ({"tx_origin_auth"}, 50),
    "Unhandled-Exceptions": ({"unchecked_external_call"}, 50),
}


@pytest.mark.skipif(not SOLIDIFI.is_dir(), reason="SolidiFI corpus not present")
@pytest.mark.parametrize("cat", list(SF_FLOOR))
def test_solidifi_recall_floor(cat):
    expected, floor = SF_FLOOR[cat]
    hit = _recall(SOLIDIFI, cat, expected, flat=True)
    assert hit >= floor, f"SolidiFI {cat} recall {hit} < floor {floor} — RECALL REGRESSION"


# ── FP CEILING on audited OpenZeppelin: precise detectors stay silent, high-sev capped ──
_PRECISE = {"forced_ether_invariant", "dos_push_payment", "variable_shadowing"}
_HIGHSEV = {"reentrancy", "unprotected_state_write", "unprotected_selfdestruct",
            "unprotected_delegatecall", "tx_origin_auth", "unchecked_arithmetic",
            "weak_randomness", "uninitialized_storage_pointer"}


@pytest.mark.skipif(not OZ.is_dir(), reason="OpenZeppelin corpus not present")
def test_openzeppelin_fp_ceiling():
    files = [p for p in OZ.rglob("*.sol") if not any(x in p.parts for x in ("mocks", "test"))]
    precise = highsev = 0
    for p in files:
        k = _kinds(p)
        precise += len(k & _PRECISE)
        highsev += len(k & _HIGHSEV)
    # the precise structural detectors MUST NOT fire on audited code
    assert precise == 0, f"precise detectors fired {precise}x on audited OZ — FALSE-POSITIVE REGRESSION"
    # high-severity fires were 2 (both defensible); cap at 3 to catch a new-FP regression
    assert highsev <= 3, f"high-severity fires on OZ rose to {highsev} (>3) — likely FP REGRESSION"
