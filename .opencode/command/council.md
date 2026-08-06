---
description: Multi-instance, cross-judging council — verdicts, weighted voting, meta-review, conflict escalation
---
Run a **Council review** (adversarial QA / peer review) of the findings for $ARGUMENTS.

Read the current findings from `.openhack/findings/` (`openhack findings --target <name>` or the JSON directly). If there are none, say so and stop. Read the tunables (defaults in parentheses): `openhack config get council.instances` (3), `council.rounds` (2), `council.threshold` (0.66). Use the defaults if unset.

## Round 1 — independent reviewers (run in parallel, each its OWN context)
Launch **`council.instances`** reviewers via the `task` tool (`subagent_type: council`), each over the SAME findings but with a DISTINCT lens so their errors aren't correlated (diverse lenses stand in for diverse models):
1. **Defense / skeptic** — challenge each finding: demand an independently reproducible PoC, look for benign explanations, question severity.
2. **Severity auditor** — re-rate each finding with CVSS v3.1; flag over- and under-rating.
3. **Gap analyst** — find MISSING vectors / untested surface (cross-check `openhack coverage --target <t> --gaps`) and also verdict the existing findings.
(If `council.instances` > 3, add more lenses: exploit-dev "can I actually weaponize this?", data-impact "what does this expose?", false-negative hunter.)
Each reviewer MUST return, for EVERY finding, a structured verdict:
`{ id, verdict: "confirmed" | "needs-evidence" | "false-positive", confidence: 0.0-1.0, reason }`.

## Round 2..N — cross-judging (meta-review)
Give each reviewer the OTHER reviewers' Round-1 verdicts and have them **challenge or revise** their own: "which of these verdicts is wrong, and why?" This is the anti-collusion step — models converge on the same wrong answer, so force them to attack each other's reasoning and re-vote with updated confidence. Repeat for `council.rounds` total rounds (or until verdicts stabilize).

## Tally (deterministic — do NOT eyeball it)
Aggregate the FINAL per-finding verdicts with the confidence-weighted rule (the `Council.tally` protocol in `packages/openhack/src/council.ts`):
- weight each verdict by its `confidence`; per finding compute the winning verdict + agreement share (winner-weight / total-weight).
- **Confirmed** only if winner is `confirmed` AND agreement ≥ `threshold` → keep.
- **False-positive** only if winner is `false-positive` AND agreement ≥ `threshold` → drop (mark `false_positive`).
- **ESCALATE** if reviewers split (no verdict ≥ threshold), the winner is `needs-evidence`, OR any reviewer's confidence < 0.4 — do NOT silently accept or drop. Re-review that finding with a fresh sharper `task`, or flag it to the operator as *"disputed — needs manual verification."*
- **Evidence beats votes** — never let agreement override contradicting hard evidence.

## Record
Record each finding's verdict trail into its `promotionChain` / `challengedByCouncils` (via `openhack finding-verify` for confirmed-with-evidence, or the findings store). Write the outcome (per-finding verdicts, confidence weights, agreement, every conflict, and the new gap vectors) to `.openhack/reviews/review-<YYYY-MM-DD>.md`, listing the **escalated/disputed** items and gap vectors prominently.

**Per-phase use:** the automode loop runs this council after EACH phase (recon → access → post-exploit) and once at the end — not just finally — so weak findings are caught early and gaps become the next round's objectives. Base everything on the reviewers' real returned verdicts and the actual finding data — never fabricate.
