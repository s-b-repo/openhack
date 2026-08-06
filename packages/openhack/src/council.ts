/**
 * Deterministic council aggregation. Multiple reviewer instances (diverse lenses +
 * temperatures) each return a per-finding verdict; this tallies them by
 * confidence-weighted majority and decides confirm / drop / ESCALATE. Keeping the
 * aggregation in code (not the model) makes the outcome reproducible and prevents
 * "blind consensus" — the well-known council failure where instances converge on the
 * same wrong answer. The macro (`.opencode/command/council.md`) runs the reviewers,
 * the cross-judge round, and feeds their verdicts here.
 */
export namespace Council {
  export type Verdict = "confirmed" | "needs-evidence" | "false-positive"

  export interface ReviewerVerdict {
    reviewer: string
    verdict: Verdict
    confidence: number // 0..1
    reason?: string
  }

  export type Outcome = "confirmed" | "false-positive" | "escalate"

  export interface Tally {
    findingId: string
    outcome: Outcome
    agreement: number // weighted share of the winning verdict (0..1)
    confirmWeight: number
    fpWeight: number
    needsEvidenceWeight: number
    conflict: boolean
    reason: string
  }

  export interface Config {
    /** min agreement to accept a non-conflict outcome (default 0.66). */
    threshold?: number
    /** any reviewer below this confidence forces escalation (default 0.4). */
    lowConfidence?: number
  }

  /**
   * Confidence-weighted tally. Confirms/drops only when the winning verdict clears
   * `threshold` and no reviewer is below `lowConfidence`; otherwise ESCALATES so a
   * split or an uncertain finding is surfaced, never silently averaged away.
   */
  export function tally(findingId: string, verdicts: ReviewerVerdict[], cfg: Config = {}): Tally {
    const threshold = cfg.threshold ?? 0.66
    const lowConfidence = cfg.lowConfidence ?? 0.4
    const w: Record<Verdict, number> = { confirmed: 0, "needs-evidence": 0, "false-positive": 0 }
    let total = 0
    let anyLow = false
    for (const v of verdicts) {
      const c = Math.max(0, Math.min(1, Number(v.confidence) || 0))
      if (w[v.verdict] === undefined) continue
      w[v.verdict] += c
      total += c
      if (c > 0 && c < lowConfidence) anyLow = true
    }
    if (total === 0 || verdicts.length === 0) {
      return { findingId, outcome: "escalate", agreement: 0, confirmWeight: 0, fpWeight: 0, needsEvidenceWeight: 0, conflict: true, reason: "no usable verdicts" }
    }
    const entries = (Object.entries(w) as Array<[Verdict, number]>).sort((a, b) => b[1] - a[1])
    const [winner, winnerW] = entries[0]
    const agreement = Math.round((winnerW / total) * 1000) / 1000
    const decisive = winner === "confirmed" || winner === "false-positive"
    const conflict = anyLow || agreement < threshold || !decisive
    let outcome: Outcome = "escalate"
    if (!conflict && winner === "confirmed") outcome = "confirmed"
    else if (!conflict && winner === "false-positive") outcome = "false-positive"
    const reason = conflict
      ? anyLow
        ? "escalate — a reviewer's confidence is below the floor"
        : !decisive
          ? "escalate — winning verdict is 'needs-evidence'"
          : `escalate — agreement ${agreement} below threshold ${threshold}`
      : `${outcome} — weighted agreement ${agreement}`
    return { findingId, outcome, agreement, confirmWeight: w.confirmed, fpWeight: w["false-positive"], needsEvidenceWeight: w["needs-evidence"], conflict, reason }
  }

  /** Summarize a set of tallies (for the review write-up). */
  export function summarize(tallies: Tally[]): { confirmed: number; falsePositive: number; escalate: number } {
    return {
      confirmed: tallies.filter((t) => t.outcome === "confirmed").length,
      falsePositive: tallies.filter((t) => t.outcome === "false-positive").length,
      escalate: tallies.filter((t) => t.outcome === "escalate").length,
    }
  }
}
