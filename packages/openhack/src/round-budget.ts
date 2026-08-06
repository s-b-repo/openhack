// Adaptive round budget — the loop's "should I run another round?" oracle.
//
// The naive fixed `--max-rounds N` is either:
//   (a) too low, and the loop stops with combos still open + budget unspent, or
//   (b) too high, and the loop wastes rounds burning cost on a converged surface.
//
// This module keeps the tail short but honest: we look at the JSONL round log
// on disk (the same stream the bench harness reads) and answer three questions
// per round:
//
//   • Should the loop terminate NOW even though maxRounds hasn't been reached?
//     (converged + no work left; stops early — cheap)
//
//   • Should the loop EXTEND past maxRounds because the last round was
//     productive AND we still have real work + budget to do it?
//     (auto-extend up to a hard ceiling — thoroughness)
//
//   • What's the current convergence rate — so the CLI can print it and the
//     controller heuristic can bias frontier selection.
//
// The math is deterministic and cheap. No LLM involvement. Every knob comes
// from `.openhack/openhack.jsonc` under `round_budget.*` so an operator can
// tune it per engagement.

import * as fs from "node:fs"
import * as path from "node:path"
import { ConfigStore } from "./config-store"

export namespace RoundBudget {
  /** Single round's snapshot as written to `.openhack/rounds/<target>.jsonl`. */
  export interface RoundRecord {
    round: number
    at: string
    findingsTotal: number
    findingsHigh: number
    newFindings: number
    newHigh: number
    totalCostUsd: number
    roundCostUsd: number
    coverage: { percent: number; tested: number; cells: number; vulnerable: number } | null
    combos: { open: number; universeSize: number; satisfiedSize: number } | null
    frontierSize: number
    rssMb: number
  }

  export interface Config {
    /** Never exceed this cap regardless of pace. Default 50. */
    hardCeiling: number
    /** Consecutive dry rounds before early termination. Default 2. */
    dryStreakLimit: number
    /** A round is "productive" if it produced ≥ this many new findings or closed ≥ this many combos. Default 1. */
    productiveMinDelta: number
    /** Extend past maxRounds only when the projected next-round cost < this fraction of remaining budget. Default 0.5. */
    budgetHeadroomFrac: number
  }

  const DEFAULT_CONFIG: Config = {
    hardCeiling: 50,
    dryStreakLimit: 2,
    productiveMinDelta: 1,
    budgetHeadroomFrac: 0.5,
  }

  export function config(): Config {
    const cfg = { ...DEFAULT_CONFIG }
    const overrides = {
      hardCeiling: ConfigStore.get("round_budget.hard_ceiling") as number | undefined,
      dryStreakLimit: ConfigStore.get("round_budget.dry_streak_limit") as number | undefined,
      productiveMinDelta: ConfigStore.get("round_budget.productive_min_delta") as number | undefined,
      budgetHeadroomFrac: ConfigStore.get("round_budget.budget_headroom_frac") as number | undefined,
    }
    if (typeof overrides.hardCeiling === "number" && overrides.hardCeiling > 0) cfg.hardCeiling = overrides.hardCeiling
    if (typeof overrides.dryStreakLimit === "number" && overrides.dryStreakLimit >= 0) cfg.dryStreakLimit = overrides.dryStreakLimit
    if (typeof overrides.productiveMinDelta === "number" && overrides.productiveMinDelta >= 0) cfg.productiveMinDelta = overrides.productiveMinDelta
    if (typeof overrides.budgetHeadroomFrac === "number" && overrides.budgetHeadroomFrac > 0) cfg.budgetHeadroomFrac = overrides.budgetHeadroomFrac
    return cfg
  }

  /** Read the round log for a target. Empty array if no log yet. */
  export function readRoundLog(target: string, dir: string = ".openhack/rounds"): RoundRecord[] {
    const safe = target.replace(/[^a-zA-Z0-9.-]/g, "_")
    const f = path.join(dir, `${safe}.jsonl`)
    try {
      const raw = fs.readFileSync(f, "utf-8")
      return raw.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as RoundRecord)
    } catch { return [] }
  }

  export interface Verdict {
    /** True → the loop must terminate this iteration, regardless of maxRounds. */
    terminate: boolean
    /** True → this round was productive (worth extending). Advisory. */
    productive: boolean
    /** Consecutive dry rounds INCLUDING this one. */
    dryStreak: number
    /** Combos closed this round (from last two records). */
    combosClosed: number
    /** Human-readable reason set when terminate=true. */
    reason?: string
  }

  /**
   * Compute the verdict from an in-memory list of round records. Prefer this
   * over `verdictFromDisk` in the hot loop — the caller already has the fresh
   * record, no reason to re-read the file we just wrote.
   */
  export function verdict(records: RoundRecord[], cfg: Config = config()): Verdict {
    if (records.length === 0) return { terminate: false, productive: false, dryStreak: 0, combosClosed: 0 }

    // Combo-close delta = drop in `open` between the last two records.
    const last = records[records.length - 1]!
    const prev = records.length >= 2 ? records[records.length - 2]! : null
    const combosClosed = prev && prev.combos && last.combos
      ? Math.max(0, prev.combos.open - last.combos.open)
      : 0

    const totalDelta = last.newFindings + combosClosed
    const productive = totalDelta >= cfg.productiveMinDelta

    // Dry streak = tail of records where nothing productive happened.
    let dry = 0
    for (let i = records.length - 1; i >= 0; i--) {
      const r = records[i]!
      const p = i > 0 ? records[i - 1]! : null
      const close = p && p.combos && r.combos ? Math.max(0, p.combos.open - r.combos.open) : 0
      if (r.newFindings + close < cfg.productiveMinDelta) dry++
      else break
    }

    // Termination path A: dry streak exceeded AND frontier + combos left aren't decreasing.
    if (dry >= cfg.dryStreakLimit) {
      const openLeft = last.combos?.open ?? 0
      const frontLeft = last.frontierSize
      // Only terminate if we've genuinely converged; if combos/frontier are non-zero
      // but simply too hard to close, the caller can override via a lower dryStreakLimit.
      if (openLeft === 0 && frontLeft === 0) {
        return { terminate: true, productive, dryStreak: dry, combosClosed, reason: `converged: ${dry} dry rounds, 0 combos + 0 frontier` }
      }
      // Non-zero work left but stalling — the loop still terminates (this is the
      // main behavior change vs. the old `newFindings <= 0 && newHigh <= 0` check),
      // but the reason names the leftover so an operator sees why.
      return { terminate: true, productive, dryStreak: dry, combosClosed, reason: `stalled: ${dry} dry rounds, ${openLeft} combos + ${frontLeft} frontier still open` }
    }

    return { terminate: false, productive, dryStreak: dry, combosClosed }
  }

  /**
   * Should the loop EXTEND its round budget past the caller-supplied maxRounds?
   * Answered "yes" only when all three hold:
   *   1. currentRound is at or past the caller's maxRounds
   *   2. the last round was productive
   *   3. remaining budget can afford at least one more round of the recent avg cost
   *   4. we haven't blown past the hard ceiling
   *
   * The extension is +1 at a time (the caller re-asks each round). This keeps a
   * runaway impossible — every extra round has to earn the next extra round.
   */
  export function shouldExtend(args: {
    currentRound: number
    callerMaxRounds: number
    records: RoundRecord[]
    remainingBudgetUsd: number
    cfg?: Config
  }): { extend: boolean; newMax: number; reason: string } {
    const cfg = args.cfg ?? config()
    if (args.currentRound < args.callerMaxRounds) {
      return { extend: false, newMax: args.callerMaxRounds, reason: "within callerMaxRounds" }
    }
    if (args.currentRound >= cfg.hardCeiling) {
      return { extend: false, newMax: args.callerMaxRounds, reason: `hard ceiling ${cfg.hardCeiling}` }
    }
    if (args.records.length === 0) {
      return { extend: false, newMax: args.callerMaxRounds, reason: "no records yet" }
    }
    const v = verdict(args.records, cfg)
    if (!v.productive) {
      return { extend: false, newMax: args.callerMaxRounds, reason: `last round unproductive (dry=${v.dryStreak})` }
    }
    // Recent avg round cost, capped at 3 last rounds so a single spike doesn't dominate.
    const tail = args.records.slice(-3)
    const avgCost = tail.reduce((s, r) => s + (r.roundCostUsd ?? 0), 0) / tail.length
    const headroom = args.remainingBudgetUsd * cfg.budgetHeadroomFrac
    if (avgCost > 0 && avgCost > headroom) {
      return { extend: false, newMax: args.callerMaxRounds, reason: `avg $${avgCost.toFixed(2)}/round > ${(cfg.budgetHeadroomFrac * 100)|0}% headroom of $${args.remainingBudgetUsd.toFixed(2)}` }
    }
    return { extend: true, newMax: args.callerMaxRounds + 1, reason: `productive (+${v.combosClosed} combos, avg $${avgCost.toFixed(2)}, headroom $${headroom.toFixed(2)})` }
  }

  /**
   * Aggregate metrics for a target — useful for `openhack status` and the TUI.
   * Cheap: reads the JSONL once, computes per-round convergence rate, returns
   * a small object.
   */
  export function metrics(target: string, dir?: string): {
    rounds: number
    totalCostUsd: number
    findingsAdded: number
    combosClosed: number
    avgFindingsPerRound: number
    avgCombosClosedPerRound: number
    lastDryStreak: number
  } {
    const recs = readRoundLog(target, dir)
    if (recs.length === 0) return { rounds: 0, totalCostUsd: 0, findingsAdded: 0, combosClosed: 0, avgFindingsPerRound: 0, avgCombosClosedPerRound: 0, lastDryStreak: 0 }
    const totalCostUsd = recs.reduce((s, r) => s + (r.roundCostUsd ?? 0), 0)
    const findingsAdded = recs.reduce((s, r) => s + (r.newFindings ?? 0), 0)
    let combosClosed = 0
    for (let i = 1; i < recs.length; i++) {
      const a = recs[i - 1]!.combos?.open
      const b = recs[i]!.combos?.open
      if (typeof a === "number" && typeof b === "number") combosClosed += Math.max(0, a - b)
    }
    const v = verdict(recs)
    return {
      rounds: recs.length,
      totalCostUsd: Math.round(totalCostUsd * 1000) / 1000,
      findingsAdded,
      combosClosed,
      avgFindingsPerRound: Math.round((findingsAdded / recs.length) * 100) / 100,
      avgCombosClosedPerRound: Math.round((combosClosed / recs.length) * 100) / 100,
      lastDryStreak: v.dryStreak,
    }
  }
}
