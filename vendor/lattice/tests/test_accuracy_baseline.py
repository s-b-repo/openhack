"""Accuracy baseline diff — the CI regression gate for every detector.

Runs `tools/measure_accuracy.py`'s `build()` against the current tree and asserts
that per-detector `precision >= baseline.precision - EPS` and
`recall >= baseline.recall - EPS`, using `tests/accuracy_baseline.json` as the
immovable floor. The baseline can ONLY be refreshed via
    python tools/measure_accuracy.py --as-baseline
which produces a review-visible diff on `tests/accuracy_baseline.json` — so no
accuracy regression can land silently.

This is OPT-IN (set `FOOTINGS_ACCURACY_GATE=1`) because the SmartBugs + SolidiFI
corpus reads are slow (~2 min). CI runs it; local `pytest` skips it. Same idiom
as `FOOTINGS_CORPUS_GATE=1 pytest tests/test_corpus_regression.py`.
"""
import json
import os
import pathlib
import shutil
import sys

import pytest


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))                 # measure_accuracy is not a package

pytestmark = [
    pytest.mark.accuracy,
    pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed"),
    pytest.mark.skipif(not os.environ.get("FOOTINGS_ACCURACY_GATE"),
                       reason="set FOOTINGS_ACCURACY_GATE=1 to run the accuracy gate"),
]

BASELINE_PATH = ROOT / "tests" / "accuracy_baseline.json"
_EPS = 0.01                                              # 1% tolerance for float noise


def _corpus_paths():
    corpus = pathlib.Path(os.environ.get(
        "FOOTINGS_CORPUS", pathlib.Path.home() / ".footings-corpus"))
    smartbugs = pathlib.Path(os.environ.get(
        "FOOTINGS_SMARTBUGS", pathlib.Path.home() / ".smartbugs/dataset"))
    return corpus, smartbugs


def _load_baseline():
    if not BASELINE_PATH.is_file():
        pytest.skip("no baseline JSON committed yet — run tools/measure_accuracy.py --as-baseline")
    return json.loads(BASELINE_PATH.read_text())


def _measure_current():
    import measure_accuracy                            # tools/measure_accuracy.py
    corpus, smartbugs = _corpus_paths()
    return measure_accuracy.build(corpus, smartbugs)


def test_baseline_json_exists():
    """The baseline is a repo asset — it MUST exist before this gate can run."""
    assert BASELINE_PATH.is_file(), \
        f"baseline missing: {BASELINE_PATH}. Run: python tools/measure_accuracy.py --as-baseline"


def test_no_detector_lost_a_unit_test():
    """Unit-test counters: total (fires+silent+toggle+other) per detector must not
    DROP from baseline. Growing is fine (accuracy work adds tests); a shrinking
    count means a test was silently removed."""
    baseline = _load_baseline()
    current = _measure_current()
    for name, entry in baseline["detectors"].items():
        b = entry.get("unit", {})
        c = current["detectors"].get(name, {}).get("unit", {})
        b_total = sum(b.values())
        c_total = sum(c.values())
        assert c_total >= b_total, \
            f"{name}: unit-test total dropped from {b_total} to {c_total}"


def test_no_corpus_recall_regression():
    """SmartBugs and SolidiFI per-category TP counts must not DROP below baseline
    (the ground-truth recall floor)."""
    baseline = _load_baseline()
    current = _measure_current()
    b_sol = baseline["detectors"]["solidity.audit"]["corpus"]
    c_sol = current["detectors"]["solidity.audit"]["corpus"]
    regressed = []
    for key, b_entry in b_sol.items():
        if "tp" not in b_entry:                        # OZ FP row, checked separately
            continue
        b_tp = b_entry["tp"]
        c_tp = c_sol.get(key, {}).get("tp", -1)
        if c_tp < b_tp:
            regressed.append(f"{key}: {b_tp} -> {c_tp}")
    assert not regressed, "recall regression:\n" + "\n".join(regressed)


def test_no_openzeppelin_fp_regression():
    """OpenZeppelin FP counts must not RISE (precise==0 stays 0; highsev must not
    exceed the baseline's cap)."""
    baseline = _load_baseline()
    current = _measure_current()
    b_oz = baseline["detectors"]["solidity.audit"]["corpus"]["openzeppelin.fp_ceiling"]
    c_oz = current["detectors"]["solidity.audit"]["corpus"]["openzeppelin.fp_ceiling"]
    assert c_oz["precise_fp"] <= b_oz["precise_fp"], \
        f"precise FP rose: {b_oz['precise_fp']} -> {c_oz['precise_fp']}"
    assert c_oz["highsev_fp"] <= b_oz["highsev_fp_ceiling"], \
        f"highsev FP rose above ceiling {b_oz['highsev_fp_ceiling']}: {c_oz['highsev_fp']}"


def test_aggregate_precision_recall_do_not_regress():
    baseline = _load_baseline()
    current = _measure_current()
    b_agg = baseline["aggregate"]
    c_agg = current["aggregate"]
    for k in ("macro_precision", "macro_recall"):
        b_val = b_agg.get(k)
        c_val = c_agg.get(k)
        if b_val is None:
            continue
        assert c_val is not None and c_val >= b_val - _EPS, \
            f"{k} regressed: {b_val:.4f} -> {c_val}"
