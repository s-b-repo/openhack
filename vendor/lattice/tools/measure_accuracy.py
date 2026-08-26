#!/usr/bin/env python3
"""Measure per-detector accuracy against unit tests + labeled corpora.

Produces the tests/accuracy_baseline.json shape defined in the accuracy sweep plan.
Two data sources today:
  1. Per-detector unit-test counts scraped from tests/test_*.py by pytest --collect-only
     (fires_pass / silent_clean / toggles_genuine — assertions grouped by function name suffix).
  2. Labeled corpus TP counts by re-running the same audit the corpus gate runs:
       - SmartBugs recall per SB_FLOOR category
       - SolidiFI  recall per SF_FLOOR category
       - OpenZeppelin FP count (precise + high-severity)

Emits JSON to --out (default: scratchpad path); --as-baseline atomically replaces
tests/accuracy_baseline.json, and is the only way that file is updated.

Env vars mirror tests/test_corpus_regression.py:
  FOOTINGS_CORPUS     -> dir with solidifi/ and oz/ (default ~/.footings-corpus)
  FOOTINGS_SMARTBUGS  -> smartbugs-curated dataset dir
"""
from __future__ import annotations
import argparse
import datetime as _dt
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _git_sha() -> str:
    try:
        return subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                       stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return "unknown"


# ────────────────────────────────────────────────────────────────────────────
# Unit-test counters: parse test node-ids, group by detector + suffix
# ────────────────────────────────────────────────────────────────────────────

# detector-name → glob(s) under tests/ (order matters; first match wins)
DETECTOR_TEST_FILES = {
    "python_taint.command_injection": ["tests/test_python_taint.py",
                                       "tests/test_python_taint_interproc.py"],
    "c_taint.command_injection":      ["tests/test_c_taint.py"],
    "go_taint.command_injection":     ["tests/test_go_taint.py"],
    "rust_taint.command_injection":   ["tests/test_rust_taint.py"],
    "ruby_taint.command_injection":   ["tests/test_ruby_taint.py"],
    "js_arbitrary_call":              ["tests/test_js_arbitrary_call.py"],
    "solidity.oracle_taint":          ["tests/test_solidity_taint.py"],
    "solidity.arbitrary_call":        ["tests/test_solidity_arbitrary_call.py"],
    "solidity.donation":              ["tests/test_solidity_donation.py"],
    "solidity.symbolic":              ["tests/test_solidity_symbolic.py"],
    "solidity.typed":                 ["tests/test_solidity_typed.py"],
    "solidity.audit":                 ["tests/test_solidity_audit.py",
                                       "tests/test_solidity.py",
                                       "tests/test_reentrancy.py",
                                       "tests/test_reentrancy_dedup.py",
                                       "tests/test_reentrancy_call_types.py",
                                       "tests/test_access_control_downgrade.py",
                                       "tests/test_economic_invariants.py",
                                       "tests/test_storage_layout.py"],
    "python_locks":                   ["tests/test_python_locks.py"],
    "python_resource":                ["tests/test_python_resource.py"],
    "c_unions":                       ["tests/test_c_unions.py"],
    "hunt":                           ["tests/test_hunt.py",
                                       "tests/test_hunt_precision.py"],
    "logic":                          ["tests/test_logic.py"],
    "security":                       ["tests/test_security.py",
                                       "tests/test_security_precision.py",
                                       "tests/test_security_taint.py",
                                       "tests/test_security_interproc.py",
                                       "tests/test_security_gates.py",
                                       "tests/test_secaudit_recall.py",
                                       "tests/test_sink_categorization.py"],
    "taxonomy":                       ["tests/test_secaudit_recall.py",
                                       "tests/test_source_selection.py"],
}


def _unit_counts(files: list[str]) -> dict:
    """Count test functions per suffix marker.

    A test with a name ending in `_FIRES` counts as fires_pass; `_SILENT` as
    silent_clean; `toggle_is_genuine` (any position) as toggles_genuine. Everything
    else falls under `other`.
    """
    fires = silent = toggle = other = 0
    for rel in files:
        p = ROOT / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            s = line.strip()
            if not s.startswith("def test_"):
                continue
            # extract just the name
            name = s[len("def "):].split("(", 1)[0]
            if name.endswith("_FIRES"):
                fires += 1
            elif name.endswith("_SILENT"):
                silent += 1
            elif "toggle_is_genuine" in name or name.endswith("_toggle_is_genuine"):
                toggle += 1
            else:
                other += 1
    return {"fires_pass": fires, "silent_clean": silent,
            "toggles_genuine": toggle, "other": other}


# ────────────────────────────────────────────────────────────────────────────
# Corpus counters: SmartBugs recall, SolidiFI recall, OZ FP count
# ────────────────────────────────────────────────────────────────────────────

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

SF_FLOOR = {
    "Re-entrancy": ({"reentrancy"}, 50),
    "Overflow-Underflow": ({"unchecked_arithmetic"}, 50),
    "Timestamp-Dependency": ({"timestamp_dependence"}, 50),
    "tx.origin": ({"tx_origin_auth"}, 50),
    "Unhandled-Exceptions": ({"unchecked_external_call"}, 50),
}

_PRECISE_OZ = {"forced_ether_invariant", "dos_push_payment", "variable_shadowing"}
_HIGHSEV_OZ = {"reentrancy", "unprotected_state_write", "unprotected_selfdestruct",
               "unprotected_delegatecall", "tx_origin_auth", "unchecked_arithmetic",
               "weak_randomness", "uninitialized_storage_pointer"}


def _kinds(sol_path: pathlib.Path) -> set:
    """Set of finding-kinds for one Solidity file, analysed in isolation."""
    from lattice.ingest.solidity import solidity_audit
    with tempfile.TemporaryDirectory() as td:
        shutil.copy(sol_path, pathlib.Path(td) / sol_path.name)
        try:
            return {f["kind"] for f in solidity_audit(td)}
        except Exception:
            return set()


def _corpus_recall(base: pathlib.Path, cat: str, expected: set, flat: bool) -> tuple[int, int]:
    d = base / cat
    if not d.is_dir():
        return (0, 0)
    sols = sorted(d.glob("*.sol") if flat else d.rglob("*.sol"))
    hit = sum(bool(_kinds(s) & expected) for s in sols)
    return (hit, len(sols))


def _oz_fp_counts(oz_root: pathlib.Path) -> dict:
    if not oz_root.is_dir():
        return {"precise_fp": 0, "highsev_fp": 0, "files_scanned": 0, "corpus_present": False}
    files = [p for p in oz_root.rglob("*.sol")
             if not any(x in p.parts for x in ("mocks", "test"))]
    precise = highsev = 0
    for p in files:
        k = _kinds(p)
        precise += len(k & _PRECISE_OZ)
        highsev += len(k & _HIGHSEV_OZ)
    return {"precise_fp": precise, "highsev_fp": highsev,
            "files_scanned": len(files), "corpus_present": True}


# ────────────────────────────────────────────────────────────────────────────
# Emit
# ────────────────────────────────────────────────────────────────────────────

def _aggregate(detectors: dict) -> dict:
    total_tp = total_fp = 0
    per_precision = []
    per_recall = []
    for d, entry in detectors.items():
        for cname, c in entry.get("corpus", {}).items():
            tp = c.get("tp", 0); fp = c.get("fp", 0); fn = c.get("fn", 0)
            total_tp += tp; total_fp += fp
            if (tp + fp) > 0:
                per_precision.append(tp / (tp + fp))
            if (tp + fn) > 0:
                per_recall.append(tp / (tp + fn))
    mp = sum(per_precision) / len(per_precision) if per_precision else None
    mr = sum(per_recall) / len(per_recall) if per_recall else None
    f1 = (2 * mp * mr / (mp + mr)) if (mp and mr) else None
    return {"total_tp": total_tp, "total_fp": total_fp,
            "macro_precision": mp, "macro_recall": mr, "f1": f1}


def build(corpus_root: pathlib.Path, smartbugs_root: pathlib.Path) -> dict:
    detectors: dict = {}

    # 1. Unit counts (all detectors)
    for name, files in DETECTOR_TEST_FILES.items():
        detectors[name] = {"unit": _unit_counts(files), "corpus": {}}

    # 2. SmartBugs recall → attributed to solidity.audit
    sol_audit = detectors["solidity.audit"]
    for cat, (expected, floor) in SB_FLOOR.items():
        hit, total = _corpus_recall(smartbugs_root, cat, expected, flat=False)
        sol_audit["corpus"][f"smartbugs.{cat}"] = {
            "expected_kinds": sorted(expected),
            "floor": floor,
            "tp": hit,
            "expected": floor,      # "expected floor" for baseline-diff test
            "total_files": total,
            "fp": 0, "fn": max(0, floor - hit),
            "recall": (hit / total) if total else None,
        }

    solidifi_root = corpus_root / "solidifi" / "buggy_contracts"
    for cat, (expected, floor) in SF_FLOOR.items():
        hit, total = _corpus_recall(solidifi_root, cat, expected, flat=True)
        sol_audit["corpus"][f"solidifi.{cat}"] = {
            "expected_kinds": sorted(expected),
            "floor": floor,
            "tp": hit,
            "expected": floor,
            "total_files": total,
            "fp": 0, "fn": max(0, floor - hit),
            "recall": (hit / total) if total else None,
        }

    # 3. OpenZeppelin FP ceiling → attributed to solidity.audit
    oz_root = corpus_root / "oz" / "contracts"
    oz = _oz_fp_counts(oz_root)
    sol_audit["corpus"]["openzeppelin.fp_ceiling"] = {
        "precise_fp_ceiling": 0,
        "highsev_fp_ceiling": 3,
        "precise_fp": oz["precise_fp"],
        "highsev_fp": oz["highsev_fp"],
        "files_scanned": oz["files_scanned"],
        "corpus_present": oz["corpus_present"],
    }

    return {
        "run_id": _dt.datetime.now(_dt.UTC).isoformat(),
        "lattice_git_sha": _git_sha(),
        "corpora": {
            "smartbugs": {"path": str(smartbugs_root),
                          "present": smartbugs_root.is_dir()},
            "solidifi":  {"path": str(solidifi_root),
                          "present": solidifi_root.is_dir()},
            "openzeppelin": {"path": str(oz_root),
                             "present": oz_root.is_dir()},
        },
        "detectors": detectors,
        "aggregate": _aggregate(detectors),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None,
                    help="output JSON path (default: scratchpad)")
    ap.add_argument("--as-baseline", action="store_true",
                    help="atomically replace tests/accuracy_baseline.json")
    ap.add_argument("--corpus", default=os.environ.get(
        "FOOTINGS_CORPUS", str(pathlib.Path.home() / ".footings-corpus")))
    ap.add_argument("--smartbugs", default=os.environ.get(
        "FOOTINGS_SMARTBUGS", str(pathlib.Path.home() / ".smartbugs/dataset")))
    args = ap.parse_args()

    corpus_root = pathlib.Path(args.corpus)
    smartbugs_root = pathlib.Path(args.smartbugs)

    payload = build(corpus_root, smartbugs_root)
    js = json.dumps(payload, indent=2, sort_keys=True)

    if args.as_baseline:
        target = ROOT / "tests" / "accuracy_baseline.json"
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(js + "\n")
        tmp.replace(target)
        print(f"wrote baseline: {target}")
    else:
        out = pathlib.Path(args.out) if args.out else (
            ROOT / "scratchpad" / f"measure_accuracy.{payload['lattice_git_sha'][:8]}.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(js + "\n")
        print(f"wrote: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
