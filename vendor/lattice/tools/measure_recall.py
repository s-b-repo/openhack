"""Measure edge recall on a real codebase.

Ingests a TS project, reports the structural numbers, then cross-checks Footings'
reference edges against a grep-based ground-truth approximation of call sites:
for each exported function, how many files textually call it vs how many reference
edges Footings actually built. A large gap = an edge-recall problem.
"""
import re
import sys
import pathlib

from lattice.ingest.lsp_client import ingest
from lattice.graph.builder import build
from lattice.complete.gate import check
from lattice.graph.query import GraphView

root = pathlib.Path(sys.argv[1]).resolve()
net = build(ingest(root, "typescript"))
g = GraphView(net)
report = check(net)

kinds = {}
for e in net.hyperedges:
    kinds[e.kind] = kinds.get(e.kind, 0) + 1

funcs = [v for v in net.vertices if v.kind in ("function", "method")]  # incl. internal helpers
with_in = sum(1 for v in funcs if g.fan_in(v.id, kinds="references") > 0)

print(f"=== {root.name} ===")
print(f"vertices={len(net.vertices)} edges={len(net.hyperedges)} {kinds}")
print(f"verdict={report.verdict} resolution={report.resolution:.3f}")
print(f"exported functions/methods: {len(funcs)}  | with >=1 inbound reference edge: {with_in}"
      f"  ({100*with_in/max(1,len(funcs)):.0f}%)")

# --- grep ground truth: files that textually call name( , excluding the decl file ---
texts = {}
for p in root.rglob("*.ts"):
    if "node_modules" in p.parts:
        continue
    try:
        texts[str(p.relative_to(root))] = p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        pass

def grep_callers(name, decl_file):
    pat = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    return sum(1 for f, t in texts.items() if f != decl_file and pat.search(t))

print("\nrecall cross-check (sample of exported functions):")
print(f"{'function':28} {'grep_caller_files':>18} {'footings_refs':>14} {'recall':>8}")
# Cross-check EVERY function: grep says it's called from N files, does Footings have edges?
hits = misses = 0
miss_names = []
for v in funcs:
    grep_n = grep_callers(v.name, v.file)
    if grep_n == 0:
        continue                              # grep finds no external callers; nothing to recall
    foot_n = g.fan_in(v.id, kinds="references")
    if foot_n > 0:
        hits += 1
    else:
        misses += 1
        miss_names.append((v.name, grep_n))

total = hits + misses
print(f"functions grep says are called from >=1 other file: {total}")
print(f"  Footings has >=1 edge: {hits}  ({100*hits/max(1,total):.0f}%)")
print(f"  Footings has ZERO edges (recall failures): {misses}")
for name, gn in sorted(miss_names, key=lambda x: -x[1])[:12]:
    print(f"    MISS: {name}  (grep: {gn} caller files)")
