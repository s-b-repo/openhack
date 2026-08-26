/**
 * Loop physics — the quantitative model behind OpenHack's loop-vs-graph stance.
 *
 * Three empirical results drive the design, and each is operationalized here as
 * pure math the loop driver, controllers, and bench harness consult:
 *
 *  1. COMPOUNDING STEP RELIABILITY. A plan whose steps succeed with per-step
 *     probability p has total success probability p^n — it decays
 *     exponentially in chain length. At p=0.95 a 100-step rigid pipeline
 *     succeeds ~0.6% of the time. This is why OpenHack prefers flat,
 *     self-orchestrated rounds with verification checkpoints over deep,
 *     rigid graphs (the GPT-Researcher lesson: they deleted their LangGraph
 *     subgraphs and scores went UP). See `Reliability`.
 *
 *  2. CONTEXT DEGRADATION. Multi-needle retrieval fidelity holds near ~97% on
 *     short contexts and falls to ~37% by 500K tokens — long-context recall
 *     does NOT degrade gracefully; it falls off a cliff. Agents working past
 *     the cliff confidently act on information they can no longer actually
 *     retrieve. See `ContextHealth`. The loop uses this to advise compaction /
 *     fresh-instance dispatch BEFORE the cliff, not after.
 *
 *  3. HARNESS > MODEL. Measured harness-design deltas reach ~48 points while
 *     model choice moves ~5 points on the same tasks. So the harness is worth
 *     auto-tuning: `script/bench-harness-tuner.ts` sweeps frontier width /
 *     instance fan-out against the deterministic bench and persists winners to
 *     `.openhack/harness-tuning.json`, which automode picks up as defaults.
 *
 * Everything here is deterministic and side-effect free so tests can pin exact
 * numbers.
 */
export namespace LoopPhysics {
  // ---------- Defaults -------------------------------------------------------

  /** Default assumed per-step success probability for one subagent objective. */
  export const DEFAULT_STEP_P = 0.85
  /** Compounded-reliability floor below which a chain must be staged/verified. */
  export const DEFAULT_FLOOR = 0.5
  /** Published retrieval anchors: ~97% short-context → ~37% at 500K tokens. */
  export const SHORT_CONTEXT_RETRIEVAL = 0.97
  export const CLIFF_TOKENS = 500_000

  // ---------- 1) Reliability (compounding decay) -----------------------------

  export namespace Reliability {
    /** p^n — probability an n-step chain completes with every step succeeding. */
    export function compound(p: number, n: number): number {
      if (!(p > 0)) return 0
      if (n <= 0) return 1
      return Math.pow(clamp01(p), n)
    }

    /** Πp_i — compounded reliability of a heterogeneous step list. */
    export function plan(ps: number[]): number {
      let r = 1
      for (const p of ps) r *= clamp01(p)
      return r
    }

    /**
     * Longest UNVERIFIED chain that still clears `floor`: max n with p^n ≥ floor.
     * Beyond this many steps without a verification checkpoint, expected success
     * drops below the floor and the work must be split into verified stages
     * (verify → then continue), because undetected failure compounds into rework.
     * Returns ≥1 always: a single step is allowed even at terrible p (floor < p).
     */
    export function maxUnverifiedSteps(p: number, floor = DEFAULT_FLOOR): number {
      if (!(p > 0)) return 1
      if (clamp01(p) >= 1) return Number.POSITIVE_INFINITY
      const n = Math.floor(Math.log(Math.min(1, Math.max(floor, Number.EPSILON))) / Math.log(clamp01(p)))
      return Math.max(1, n)
    }

    /**
     * Verification checkpoint interval for a long run at per-step p: verify at
     * least this often so any single unverified segment stays above `floor`.
     * Same math as maxUnverifiedSteps — named for intent at call sites.
     */
    export function checkpointInterval(p: number, floor = DEFAULT_FLOOR): number {
      return maxUnverifiedSteps(p, floor)
    }

    /**
     * Expected wasted-work when something fails mid-chain. Detection lag is the
     * operative variable: an UNVERIFIED chain only reveals a failed step at the
     * end (lag = n — you re-run everything); a chain verified every k steps
     * catches any failure within k steps (lag = k). Rework ≈ P(any failure) × lag,
     * which is why short verified loops beat long rigid pipelines even when the
     * per-step success rate is identical.
     */
    export function expectedRework(p: number, n: number, checkpointEvery?: number): number {
      if (n <= 0 || !(p > 0)) return 0
      const lag = checkpointEvery && checkpointEvery > 0 ? Math.min(checkpointEvery, n) : n
      return (1 - compound(clamp01(p), n)) * lag
    }

    export type Band = "green" | "yellow" | "red"

    export interface RiskVerdict {
      /** Compounded success probability of the whole step list. */
      reliability: number
      band: Band
      /** Max steps at DEFAULT_STEP_P-equivalent quality before verification is due. */
      maxUnverified: number
      recommendation: string
    }

    /**
     * Classify a plan/chain. Bands (relative to `floor`):
     *   green  — reliability ≥ 2×floor … just run it flat.
     *   yellow — floor ≤ reliability < 2×floor … run, but verify before building on it.
     *   red    — reliability < floor … split into verified stages or re-plan shorter.
     */
    export function risk(ps: number[], floor = DEFAULT_FLOOR): RiskVerdict {
      const rel = plan(ps)
      const effP = ps.length ? Math.pow(Math.max(rel, Number.EPSILON), 1 / ps.length) : 1
      const maxUnverified = maxUnverifiedSteps(effP, floor)
      if (rel >= 2 * floor) {
        return { reliability: rel, band: "green", maxUnverified, recommendation: "run flat" }
      }
      if (rel >= floor) {
        return { reliability: rel, band: "yellow", maxUnverified, recommendation: "verify output before chaining further" }
      }
      return {
        reliability: rel,
        band: "red",
        maxUnverified,
        recommendation: `split into ≤${maxUnverified}-step verified stages (compounded ${rel.toFixed(3)} < floor ${floor})`,
      }
    }

    /**
     * Score multiplier for scheduling an action whose dependency chain has `depth`
     * nodes (+ itself). Discounts the nominal score by the compounded probability
     * the whole dependency chain is actually done-and-correct when the action runs,
     * so deep speculative chains lose top-k slots to shallow high-certainty work.
     * Bounded to [minMult, 1] so priors stay sane; depth ≤1 returns 1.
     */
    export function scheduleDiscount(depth: number, p = DEFAULT_STEP_P, minMult = 0.4): number {
      if (depth <= 1) return 1
      return Math.max(minMult, compound(p, depth))
    }
  }

  // ---------- 2) ContextHealth (degradation cliff) ----------------------------

  export namespace ContextHealth {
    /**
     * Calibration curve for multi-needle retrieval fidelity vs context size.
     * Anchored at published measurements (~97% at working lengths, ~37% at
     * 500K); intermediate points are piecewise-linear interpolation — a model
     * of the shape, not a claim about any specific provider. Monotone
     * decreasing; clamped outside the last anchor.
     */
    export const CALIBRATION: ReadonlyArray<{ tokens: number; retrieval: number }> = Object.freeze([
      { tokens: 0, retrieval: 1.0 },
      { tokens: 32_000, retrieval: SHORT_CONTEXT_RETRIEVAL },
      { tokens: 128_000, retrieval: 0.85 },
      { tokens: 256_000, retrieval: 0.62 },
      { tokens: 384_000, retrieval: 0.48 },
      { tokens: CLIFF_TOKENS, retrieval: 0.37 },
    ])

    /** Piecewise-linear interpolated retrieval fidelity at `tokens`. */
    export function fidelityAt(tokens: number): number {
      const t = Math.max(0, tokens)
      const c = CALIBRATION
      if (t <= c[0].tokens) return c[0].retrieval
      for (let i = 1; i < c.length; i++) {
        const hi = c[i]
        if (t <= hi.tokens) {
          const lo = c[i - 1]
          const span = hi.tokens - lo.tokens || 1
          const w = (t - lo.tokens) / span
          return lo.retrieval + w * (hi.retrieval - lo.retrieval)
        }
      }
      // Past the last anchor: keep decaying along the final slope but never
      // below zero — past-cliff contexts are effectively unusable for recall.
      const last = c[c.length - 1]
      const prev = c[c.length - 2]
      const slope = (last.retrieval - prev.retrieval) / ((last.tokens - prev.tokens) || 1)
      return Math.max(0, last.retrieval + slope * (t - last.tokens))
    }

    /**
     * Per-step reliability discounted by how much of the needed context the
     * agent can still actually retrieve: p × fidelity(tokens). This is the
     * combined physics view — a long-context step is a less reliable step.
     */
    export function effectiveStep(p: number, tokens: number): number {
      return clamp01(p) * fidelityAt(tokens)
    }

    export type Band = "healthy" | "degrading" | "cliff"
    export type Action = "continue" | "compact" | "fresh-instance"

    export interface Verdict {
      tokens: number
      /** Estimated multi-needle retrieval fidelity at this context length. */
      fidelity: number
      band: Band
      action: Action
      reason: string
    }

    /** Thresholds: degradation starts being material under ~85% fidelity;
     *  under ~60% the agent is past the useful-recall region. */
    export const DEGRADING_AT = 0.85
    export const CLIFF_AT = 0.6

    export function verdict(tokens: number): Verdict {
      const f = fidelityAt(tokens)
      if (f >= DEGRADING_AT) {
        return { tokens, fidelity: round(f), band: "healthy", action: "continue", reason: `retrieval ≈${pct(f)} at ${fmt(tokens)} tokens` }
      }
      if (f >= CLIFF_AT) {
        return { tokens, fidelity: round(f), band: "degrading", action: "compact", reason: `retrieval ≈${pct(f)} at ${fmt(tokens)} tokens — compact transcripts / split objectives` }
      }
      return { tokens, fidelity: round(f), band: "cliff", action: "fresh-instance", reason: `retrieval ≈${pct(f)} at ${fmt(tokens)} tokens — past the usable-recall cliff, dispatch fresh instances instead of extending` }
    }

    /**
     * Combined verdict for scheduling: given a candidate action's dependency
     * depth AND the context length it would run at, is it worth dispatching?
     * Returns the effective compounded reliability using context-discounted
     * per-step probability.
     */
    export function effectiveReliability(ps: Array<{ p: number; tokens: number }>): number {
      return Reliability.plan(ps.map((s) => effectiveStep(s.p, s.tokens)))
    }
  }

  // ---------- 3) Harness tuner scoring ---------------------------------------
  //
  // Harness design moves outcomes far more than model choice (≈48 vs ≈5 points
  // in published ablations), so the bench harness can safely pick its own knobs.
  // `scoreRun` is the pure selection kernel used by bench-harness-tuner.ts.

  /** Normalized composite score for one bench run — higher is better. */
  export interface TunerWeights {
    highValue: number
    coverage: number
    totalFindings: number
    cost: number
    wall: number
  }
  export const TUNER_WEIGHTS: TunerWeights = {
    highValue: 2.0, coverage: 1.0, totalFindings: 0.5, cost: 1.0, wall: 0.25,
  }

  /**
   * Score one run's metrics against the best/worst observed across the grid
   * (min-max normalization; metrics missing → neutral). Deterministic.
   */
  export function scoreRun(
    m: Record<string, number>,
    bestWorst: { highs: [number, number]; covs: [number, number]; totals: [number, number]; costs: [number, number]; walls: [number, number] },
    w: TunerWeights = TUNER_WEIGHTS,
  ): number {
    const norm = (v: number, [lo, hi]: [number, number]): number => (hi - lo > 0 ? (v - lo) / (hi - lo) : 0.5)
    return (
      w.highValue * norm(m.high ?? 0, bestWorst.highs) +
      w.coverage * norm(m.cov ?? 0, bestWorst.covs) +
      w.totalFindings * norm(m.total ?? 0, bestWorst.totals) +
      w.cost * (1 - norm(m.cost ?? 0, bestWorst.costs)) +
      w.wall * (1 - norm(m.wall ?? 0, bestWorst.walls))
    )
  }

  /** Pick the winning config from scored runs; ties break toward cheaper/simpler harnesses. */
  export function pickWinner<T extends { score: number; frontierK: number; instances: number; cost?: number; wall?: number }>(runs: T[]): T | null {
    if (!runs.length) return null
    return [...runs].sort((a, b) =>
      b.score - a.score ||
      (a.cost ?? 0) - (b.cost ?? 0) ||
      a.frontierK - b.frontierK ||
      a.instances - b.instances ||
      (a.wall ?? 0) - (b.wall ?? 0),
    )[0]
  }
}

// ---------- internal helpers (namespace-private) ------------------------------

function clamp01(x: number): number {
  return Math.min(1, Math.max(0, x))
}
function round(x: number): number {
  return Math.round(x * 1000) / 1000
}
function pct(x: number): string {
  return `${Math.round(x * 100)}%`
}
function fmt(n: number): string {
  return n.toLocaleString("en-US")
}
