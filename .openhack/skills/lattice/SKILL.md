---
name: lattice
description: Structural code auditing with the Lattice CLI — use when auditing source code (any language) for structural bugs, injection sinks, dead code, cycles, or before/after editing code
---

# Lattice — structural code audit

Lattice ingests a source tree into a typed hypernetwork (symbols, imports, calls,
exports, entrypoints) and audits structure over it. It is a **shell tool**, not
guesswork: findings come from reachability over the graph, labeled with what was
actually verified.

## Commands

| Command | What it answers |
|---|---|
| `lattice-codeaudit <path>` | Full auto-audit: detects languages, runs hunt + secaudit + diagnose + triage, writes reports to `.openhack/codeaudit/<name>-<stamp>/` (+ `-latest` symlink). Exit 0 = clean, 1 = critical/high findings, 2 = could not run. Prints a `LATTICE_CODEAUDIT ...` summary line. |
| `lattice hunt <path> --lang <l>` | Ranked structural bugs (`public_path_to_stub`, `obstruction`, `broken_reference`, `dead_code`) |
| `lattice secaudit <path> --lang <l>` | Attack surface + source→sink reachability (command exec, SQLi, deserialization, XSS, SSRF), each finding `TAINTED` vs `reachable` |
| `lattice impact <path> <symbol> --lang <l>` | Blast radius of changing a symbol — run BEFORE editing |
| `lattice diagnose <path> --lang <l> --out d.json` | Cycles, dead code, stubs, hotspots, broken imports |
| `lattice verify <path> --against HEAD --lang <l>` | Did my change structurally regress anything? |

`--lang`: `ts js py go rs rb sol cpp cu c sh sql` or `auto`.

## When to use

- **Before editing code**: `impact` on the target symbol; check public-API crossings.
- **After editing code**: `verify` against HEAD, or `lattice-codeaudit` for the full sweep.
- **During engagements**: found an exposed repo / `.git` / source disclosure? Run
  `lattice-codeaudit` on it and turn TAINTED source→sink paths into findings.
- **Solidity targets**: use `lattice intake <path> --lang sol` for the full detector suite.

## Honesty rules

- Read the flagged file yourself before recording a finding — Lattice proves
  *reachability/taint*, not exploitability.
- A finding's `verified:` list says what was proven; everything else is a lead,
  not a conclusion.
- Missing native frontends (go/rs/rb/c need their toolchains) show up as blind
  spots in the report — report them, don't silently skip.
