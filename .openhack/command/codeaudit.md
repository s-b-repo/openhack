---
description: Auto-audit source code with the Lattice structural engine (hunt + secaudit + diagnose + triage)
---

Run a Lattice structural code audit on $ARGUMENTS.
If no args: audit the current working directory.

1. Run `lattice-codeaudit <path>` (shell tool; reports land in `.openhack/codeaudit/<name>-<stamp>/`, with `<name>-latest` pointing at the newest run). It auto-detects languages (`ts js py go rs rb sol c cpp cu sh sql`) and exits 0 = clean, 1 = critical/high findings, 2 = could not run.
2. Read `report.md` in the run directory. For every **critical/high** finding — especially secaudit findings labeled `TAINTED` (interprocedural input flow into the sink) — open the flagged file and confirm the flagged path yourself before recording it. Lattice proves reachability/taint, not exploitability.
3. Record each confirmed issue as a finding: severity from the report, CWE where it applies (`command_exec` → CWE-78, `sql_injection` → CWE-89, `deserialization` → CWE-502, ...), evidence = the source→sink path plus the code snippet.
4. Note any blind-spot languages listed in the report header as coverage gaps rather than clean results.
5. Summarize: counts by severity, top 5 findings with file:line, blind spots, and where the full JSON lives.
