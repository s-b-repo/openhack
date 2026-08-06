---
description: Run the full authorized-pentest orchestration loop against a target (real subagents)
---
Run the OpenHack multi-orchestrator assessment for $ARGUMENTS (a target — or "resume"/"status").

**Defaults (the full team, always on).** Auto mode runs, by default: a **planning** step first (map objectives + the vulnerability-class checklist to the surface); **multiple agents in parallel** — the same-priority orchestrators AND several diverse-lens instances of each, every one in its own context; **MoE routing** on every objective; a **council QA review after every phase** (multi-instance, cross-judging); finding **chaining** ("combine-with / what-missed / if-true-what-else"); and a final **report**. The shell CLI has parity: `openhack automode --target <t> --loop` runs this same loop with `--instances`, `--plan/--no-plan`, `--council/--no-council`, `--parallel`, `--coverage-target`, `--max-rounds`, `--cost-cap` (defaults: plan on, council on, instances 3). Use workflows (`openhack workflow …`) to persist/resume long runs.

**Preconditions.** Confirm an authorized, signed ROE and an in-scope target first (`openhack roe`, `openhack scope`). Everything below is gated by the runtime safety harness and ROE/scope: out-of-scope targets and destructive/DoS commands are blocked regardless of what a step asks for.

**Doctrine for every step.** Prioritize demonstrating risk through ACCESS and evidence — pursue authorized, in-scope testing thoroughly and do not stall out of caution. FORBIDDEN: denial-of-service, resource exhaustion, data destruction, or any irreversible/availability-impacting action. Before each step, read the current findings in `.openhack/findings/` and build on them; record every finding with evidence and note chaining opportunities for the next step.

Dispatch these orchestrators via the real `task` tool, in order, letting each inform the next:

1. **recon-depth** — `task(subagent_type: "recon")`: thoroughly map the authorized attack surface (hosts, ports, services and versions, endpoints/APIs, tech stack).
2. **internal-access** — `task(subagent_type: "exploit")`: gain a foothold — default/weak creds, auth/authz bypass, injection (SQL/command/template), SSRF-to-internal, exposed admin/API surfaces. Prove access with a minimal non-destructive PoC.
3. From any foothold, run these (in parallel):
   - **pii-exposure** — `task(subagent_type: "post-exploit")`: exposed sensitive data (open DBs/backups/buckets, `.git`/`.env`, directory listings, API responses leaking PII). Sample + evidence, never mass-exfiltrate.
   - **pivoting** — `task(subagent_type: "post-exploit")`: lateral movement — internal mapping, credential reuse, trust relationships.
   - **privesc** — `task(subagent_type: "post-exploit")`: local/domain privilege-escalation paths, least-impact only.
4. **chaining-planning** — `task(subagent_type: "general")`: read ALL findings, chain them into concrete end-to-end attack paths, and identify MISSING vectors/gaps plus a prioritized list of next objectives.
5. **council review** — run the `/council` review flow (fan out defense / severity-auditor / gap-analyst reviewers via `task`) to validate findings, eliminate false positives, and surface anything missed. A finding is only "verified" with a reproducible PoC **and** an on-disk evidence file — otherwise it stays "uncertain". Council MUST run before the report.
6. **Loop decision (do this explicitly every round).** After steps 4–5, compare the current findings in `.openhack/findings/` to the start of the round. **Loop back to step 2** for another round if this round produced any *new* finding — especially any new critical/high one — or if the chaining/gap step named concrete untested vectors. **STOP looping** when ANY of these is true: (a) a full round added **no new findings and no new high-value vectors** (converged); (b) the **cost budget** is reached; (c) the **ROE window** is closed/expired (`openhack roe`); or (d) you have completed a sane **round cap** (default 3). Do not loop forever, and do not stop early while concrete high-value vectors remain untested and in-budget.
7. **report** — `task(subagent_type: "report")`: synthesize all findings with CVSS v3.1 + CWE + prioritized remediation and the confirmed attack paths; save under `.openhack/reports/`. Run this exactly once, after the loop terminates.

Synthesize the subagents' outputs yourself between steps — base everything on their real results and the actual findings data; never fabricate. The specialist system prompts already carry per-agent objective focus, so keep each `task` prompt targeted.

**To run this loop non-interactively / for real from the shell**, use the CLI (which spawns real subagent sessions and owns the round/termination logic deterministically): `openhack automode --target <target> --loop [--max-rounds N] [--cost-cap USD]`. For a single real round use `--execute`; to only write the objective prompts without running, omit both (`--orchestrate` plan mode — never a fake "queued" run).
