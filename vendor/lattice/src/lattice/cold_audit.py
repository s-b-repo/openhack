"""Cold-target audit harness: point Footings at a real project (a directory of .sol files it has
never seen, no ground-truth labels) and produce a TRIAGE report — findings ranked by severity +
confidence, blind spots and parse failures surfaced separately so absence-of-finding is never
silently read as "safe".

    python -m lattice.cold_audit <project-dir>
    python -m lattice.cold_audit <project-dir> --json

This is the product (`agent_intake`): the per-file structural leg + the typed (cross-file) leg +
the honest blind-spot escalations. On a cold target you cannot measure recall/precision; the value
is (a) a ranked list of leads to investigate and (b) an explicit map of where the tool went blind.
"""
import sys
import json
import pathlib
from collections import Counter
from lattice.intake import agent_intake

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# directories that are dependencies / tests, not the project's own audited surface
_SKIP = {"node_modules", "lib", "vendor", ".git", "out", "artifacts", "cache",
         "test", "tests", "mock", "mocks", "script", "scripts"}


def _sol_count(root: pathlib.Path) -> int:
    if root.is_file():
        return int(root.suffix.lower() == ".sol")
    return sum(1 for p in root.rglob("*.sol")
               if not (_SKIP & {x.lower() for x in p.relative_to(root).parts}))


def _in_skip(loc) -> bool:
    """True if a finding's location lives under a dependency/test/script dir (not audited surface)."""
    path = (loc or "").split(":")[0]
    return bool(_SKIP & {x.lower() for x in pathlib.Path(path).parts})


def cold_audit(root) -> dict:
    """Run the full Footings product over a project directory and return a structured triage."""
    root = pathlib.Path(root)
    res = agent_intake(str(root), language="solidity")
    # the product scans every .sol; drop findings in test/mock/dependency dirs — they are not the
    # project's own audited surface (a test helper pushing ether is not a protocol DoS).
    findings = [f for f in res.get("findings", []) if not _in_skip(f.get("location"))]
    blinds = [b for b in res.get("blind_spots", [])
              if not _in_skip(b.get("location") or b.get("where"))]
    parse_fails = [f for f in findings if f.get("kind") == "parse_failure"]
    real = [f for f in findings if f.get("kind") != "parse_failure"]
    real.sort(key=lambda f: (_SEV_ORDER.get(f.get("severity", "info"), 9),
                             f.get("confidence", "") != "proven"))
    return {
        "root": str(root),
        "sol_files": _sol_count(root),
        "findings": real,
        "blind_spots": blinds,
        "parse_failures": parse_fails,
        "analysis_coverage": res.get("analysis_coverage", []),
        "by_severity": dict(Counter(f.get("severity", "?") for f in real)),
        "by_kind": dict(Counter(f.get("kind", "?") for f in real)),
    }


def format_report(r: dict) -> str:
    L = []
    L.append(f"COLD AUDIT — {r['root']}")
    L.append(f"  {r['sol_files']} source .sol  |  {len(r['findings'])} findings  "
             f"|  {len(r['blind_spots'])} blind spots  |  {len(r['parse_failures'])} parse failures")
    L.append(f"  severity: {r['by_severity'] or '(none)'}")
    coverage = r.get("analysis_coverage", [])
    if coverage:
        completed = [x["analysis"] for x in coverage if x.get("status") == "completed"]
        failed = [x["analysis"] for x in coverage if x.get("status") == "failed"]
        L.append(f"  analyses completed: {', '.join(completed) or '(none)'}")
        if failed:
            L.append(f"  analyses FAILED: {', '.join(failed)} — see blind spots")
    L.append("")
    if r["findings"]:
        L.append("FINDINGS (ranked: severity, then confidence) — leads to investigate:")
        for f in r["findings"]:
            L.append(f"  [{f.get('severity','?'):8s} {f.get('confidence','?'):9s}] "
                     f"{f.get('kind',''):26s} {f.get('location','')}  {f.get('subject','')}")
            L.append(f"      {f.get('detail','')}  ({f.get('analysis','')})")
    if r["parse_failures"]:
        L.append("")
        L.append("PARSE FAILURES — NOT analysed, do NOT assume clean:")
        for f in r["parse_failures"]:
            L.append(f"  {f.get('location', f.get('file',''))}")
    if r["blind_spots"]:
        L.append("")
        L.append("BLIND SPOTS — constructs the structural screen cannot see into (review manually):")
        for b in r["blind_spots"]:
            detail = b.get("why") or b.get("detail") or b.get("where") or ""
            analysis = f" [{b['analysis']}]" if b.get("analysis") else ""
            L.append(f"  {b.get('kind', b.get('type',''))}{analysis}: {str(detail)[:140]}")
    return "\n".join(L)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m lattice.cold_audit <project-dir> [--json]")
        return 2
    root = argv[0]
    r = cold_audit(root)
    if "--json" in argv:
        print(json.dumps(r, indent=1))
    else:
        print(format_report(r))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
