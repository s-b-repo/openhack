import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"
import { ModelCosts } from "./model-costs"
import { GlobalConfig } from "./global-config"
import { Variants } from "./variants"
import { ConfigStore } from "./config-store"

/**
 * Overwatch — the "o5" benchmark council.
 *
 * Continuously benchmarks `(role × model × prompt-variant)` from the live loop's own
 * telemetry (findings delta, council-confirmed rate, real cost, latency) and, every
 * `review_every` rounds, forces every role onto its best-measured model+variant. It is
 * DISTINCT from the findings-review `Council` (that adjudicates vulnerabilities); this
 * ranks agents. Enforcement rides the single `GlobalConfig.resolveForAgent` choke point
 * (via `agent_models`) plus `Variants` — so a promoted winner takes effect next round
 * with zero subprocess changes.
 *
 * Store: `.openhack/overwatch.json` (global / cross-run so learning survives sessions),
 * HMAC-signed `{body,sig}` like `Scores`, guarded by an atomic-mkdir `withLock`.
 */
export namespace Overwatch {
  export interface CandidateKey {
    role: string
    modelId: string
    variantId: string
  }

  export interface CandidateStats {
    dispatches: number
    productiveRounds: number
    highValueRounds: number
    confirmedRounds: number
    meanNewFindings: number
    meanCostUsd: number
    meanLatencyMs: number
    lastRound: number
    lastAt: number
  }

  export interface Store {
    candidates: Record<string, CandidateStats>
    /** role → currently-enforced winner. */
    chosen: Record<string, { modelId: string; variantId: string }>
    lastReviewRound: number
    /** Round of the most-recent record() — dedup guard against double-record. */
    lastAppliedRound: number
  }

  export interface RoundRoleOutcome {
    role: string
    modelId: string
    variantId: string
    newFindings: number
    newHigh: number
    /** Council-confirmed findings attributed to this role this round. */
    confirmed: number
    costUsd: number
    latencyMs: number
  }

  export interface Grid {
    models: string[]
    variants: string[]
  }

  export interface Config {
    enabled: boolean
    reviewEvery: number
    epsilon: number
    minSamples: number
    seedFromModelsDev: boolean
    candidates: Record<string, Grid>
  }

  const DIR = ".openhack"
  const FILE = path.join(DIR, "overwatch.json")
  const KEY_FILE = path.join(DIR, ".overwatch_signing_key")
  const LOCK = path.join(DIR, ".overwatch.lock")

  /**
   * Optional cold-start seed per model (0..1), consulted only when
   * `seed_from_models_dev` is on and a candidate has < minSamples dispatches. Left
   * empty by default; a build that wants models.dev priors populates this from
   * `packages/stats/app/src/routes/model-catalog.ts`'s `ModelCatalogEntry.benchmarks`
   * (normalized). Kept as a plain table so Overwatch has no cross-package/network dep.
   */
  export const SEED: Record<string, number> = {}

  export function keyOf(k: CandidateKey): string {
    return `${k.role}::${k.modelId}::${k.variantId}`
  }

  function ensureDir(): void {
    if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true })
  }

  let signingKey: string | null = null
  function getSigningKey(): string {
    if (signingKey) return signingKey
    try {
      signingKey = fs.readFileSync(KEY_FILE, "utf-8").trim()
    } catch {
      signingKey = crypto.randomBytes(32).toString("hex")
      ensureDir()
      fs.writeFileSync(KEY_FILE, signingKey, { encoding: "utf-8", mode: 0o600 })
    }
    return signingKey
  }

  function signBody(body: string): string {
    return crypto.createHmac("sha256", getSigningKey()).update(body).digest("hex")
  }

  export function empty(): Store {
    return { candidates: {}, chosen: {}, lastReviewRound: 0, lastAppliedRound: 0 }
  }

  export function load(): Store {
    if (!fs.existsSync(FILE)) return empty()
    try {
      const parsed = JSON.parse(fs.readFileSync(FILE, "utf-8")) as { body: string; sig: string }
      const expected = signBody(parsed.body)
      if (
        parsed.sig.length !== expected.length ||
        !crypto.timingSafeEqual(Buffer.from(parsed.sig), Buffer.from(expected))
      ) {
        process.stderr.write("[overwatch] HMAC verification failed — starting fresh.\n")
        return empty()
      }
      return JSON.parse(parsed.body) as Store
    } catch {
      return empty()
    }
  }

  export function save(store: Store): void {
    ensureDir()
    const body = JSON.stringify(store)
    const doc = { body, sig: signBody(body) }
    const tmp = `${FILE}.tmp`
    fs.writeFileSync(tmp, JSON.stringify(doc, null, 2))
    fs.renameSync(tmp, FILE)
  }

  /** Atomic-mkdir advisory lock (copy of the Findings/Scores pattern). */
  export function withLock<T>(fn: () => T): T {
    ensureDir()
    const start = Date.now()
    for (;;) {
      try {
        fs.mkdirSync(LOCK)
        break
      } catch {
        try {
          if (Date.now() - fs.statSync(LOCK).mtimeMs > 10_000) fs.rmSync(LOCK, { recursive: true, force: true })
        } catch {}
        if (Date.now() - start > 15_000) {
          try { fs.rmSync(LOCK, { recursive: true, force: true }) } catch {}
          continue
        }
        try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25) } catch {}
      }
    }
    try {
      return fn()
    } finally {
      try { fs.rmSync(LOCK, { recursive: true, force: true }) } catch {}
    }
  }

  function emptyStats(): CandidateStats {
    return {
      dispatches: 0, productiveRounds: 0, highValueRounds: 0, confirmedRounds: 0,
      meanNewFindings: 0, meanCostUsd: 0, meanLatencyMs: 0, lastRound: 0, lastAt: 0,
    }
  }

  /**
   * Record one round's per-role outcomes. Welford rolling means keep the store flat.
   * `roundNumber` dedups a double-record (mirrors `Scores.record`).
   */
  export function record(store: Store, roundNumber: number, outcomes: RoundRoleOutcome[]): Store {
    if (roundNumber <= store.lastAppliedRound) return store
    const now = Date.now()
    for (const o of outcomes) {
      const key = keyOf(o)
      const cur = store.candidates[key] ?? emptyStats()
      const n = cur.dispatches + 1
      store.candidates[key] = {
        dispatches: n,
        productiveRounds: cur.productiveRounds + (o.newFindings > 0 ? 1 : 0),
        highValueRounds: cur.highValueRounds + (o.newHigh > 0 ? 1 : 0),
        confirmedRounds: cur.confirmedRounds + (o.confirmed > 0 ? 1 : 0),
        meanNewFindings: round3(cur.meanNewFindings + (o.newFindings - cur.meanNewFindings) / n),
        meanCostUsd: round4(cur.meanCostUsd + (o.costUsd - cur.meanCostUsd) / n),
        meanLatencyMs: Math.round(cur.meanLatencyMs + (o.latencyMs - cur.meanLatencyMs) / n),
        lastRound: roundNumber,
        lastAt: now,
      }
    }
    store.lastAppliedRound = roundNumber
    return store
  }

  function round3(n: number): number { return Math.round(n * 1000) / 1000 }
  function round4(n: number): number { return Math.round(n * 10000) / 10000 }

  /**
   * Quality score for a candidate — higher is better. Reuses the `Scores.priorFor`
   * shape (successRate + a bounded efficiency term) and adds a confirmed-rate reward
   * and a latency penalty. Cost enters via `efficiency` (findings per USD), floored by
   * the model's list rate so a never-charged mock still ranks by findings.
   *
   * Cold start: a candidate with < `minSamples` dispatches blends toward its seed
   * (models.dev prior when enabled, else a neutral 1.0) so unproven candidates aren't
   * prematurely dismissed.
   */
  export function scoreCandidate(
    store: Store,
    key: CandidateKey,
    opts: { minSamples?: number; seedFromModelsDev?: boolean } = {},
  ): number {
    const s = store.candidates[keyOf(key)]
    const minSamples = Math.max(1, opts.minSamples ?? 3)
    const seed = opts.seedFromModelsDev ? seedScore(key.modelId) : 1.0
    if (!s || s.dispatches === 0) return seed
    const successRate = s.productiveRounds / s.dispatches
    const confirmRate = s.confirmedRounds / s.dispatches
    const costFloor = Math.max(s.meanCostUsd, ModelCosts.ratePer1KUsd(key.modelId), 0.001)
    const efficiency = s.meanNewFindings / costFloor
    const measured =
      0.5 +
      1.4 * successRate +
      0.6 * confirmRate +
      Math.tanh(efficiency / 5) * 0.5 -
      0.3 * Math.tanh(s.meanLatencyMs / 60_000)
    // Blend measured with the seed until we have minSamples observations.
    if (s.dispatches < minSamples) {
      const w = s.dispatches / minSamples
      return round3(measured * w + seed * (1 - w))
    }
    return round3(measured)
  }

  /** Seed prior for a model (0..1 mapped to a neutral-ish score band). Neutral 1.0 when unseeded. */
  function seedScore(modelId: string): number {
    const s = SEED[modelId]
    if (s == null) return 1.0
    // Map a 0..1 external benchmark to a 0.5..2.5 score band.
    return 0.5 + Math.max(0, Math.min(1, s)) * 2.0
  }

  /**
   * Choose the `(model, variant)` to run for a role THIS round — epsilon-greedy but
   * deterministic (no RNG, so runs are reproducible/testable):
   *   • any candidate under `minSamples` → round-robin among the under-sampled set
   *     (guarantees the grid actually gets measured);
   *   • else on an "explore" round (every ~1/epsilon rounds) → the least-sampled candidate;
   *   • else → the incumbent (`store.chosen[role]`) if it's still in the grid, else argmax.
   */
  export function pick(
    store: Store,
    role: string,
    grid: Grid,
    round: number,
    epsilon: number,
    opts: { minSamples?: number; seedFromModelsDev?: boolean } = {},
  ): { modelId: string; variantId: string } {
    const minSamples = Math.max(1, opts.minSamples ?? 3)
    const cells = gridCells(role, grid)
    if (cells.length === 0) return fallbackCell(role, grid)

    const dispatchesOf = (c: CandidateKey) => store.candidates[keyOf(c)]?.dispatches ?? 0
    const under = cells.filter((c) => dispatchesOf(c) < minSamples)
    if (under.length > 0) {
      const chosen = under[round % under.length]!
      return { modelId: chosen.modelId, variantId: chosen.variantId }
    }

    const explorePeriod = Math.max(2, Math.round(1 / Math.max(0.01, Math.min(1, epsilon))))
    if (round % explorePeriod === 0) {
      const leastSampled = [...cells].sort((a, b) => dispatchesOf(a) - dispatchesOf(b))[0]!
      return { modelId: leastSampled.modelId, variantId: leastSampled.variantId }
    }

    const incumbent = store.chosen[role]
    if (incumbent && cells.some((c) => c.modelId === incumbent.modelId && c.variantId === incumbent.variantId)) {
      return { modelId: incumbent.modelId, variantId: incumbent.variantId }
    }
    return bestCell(store, cells, opts).cell
  }

  /**
   * Re-rank every role's grid and update `store.chosen` to the best-measured candidate.
   * An incumbent is only unseated by a challenger that (a) has ≥ `minSamples` dispatches
   * and (b) strictly out-scores it — the anti-thrash / measurement-stability guard.
   * Returns the winners it settled on (per role).
   */
  export function review(
    store: Store,
    roles: Record<string, Grid>,
    minSamples: number,
    round?: number,
  ): Record<string, { modelId: string; variantId: string; score: number }> {
    const winners: Record<string, { modelId: string; variantId: string; score: number }> = {}
    const opts = { minSamples, seedFromModelsDev: false }
    for (const [role, grid] of Object.entries(roles)) {
      const cells = gridCells(role, grid)
      if (cells.length === 0) continue
      const incumbent = store.chosen[role]
      const incumbentCell =
        incumbent && cells.find((c) => c.modelId === incumbent.modelId && c.variantId === incumbent.variantId)
      const incumbentScore = incumbentCell ? scoreCandidate(store, incumbentCell, opts) : -Infinity

      // Eligible challengers: enough samples to trust.
      const eligible = cells.filter((c) => (store.candidates[keyOf(c)]?.dispatches ?? 0) >= minSamples)
      const pool = eligible.length ? eligible : cells
      const best = bestCell(store, pool, opts)

      let winner: CandidateKey
      let winnerScore: number
      if (incumbentCell && best.score <= incumbentScore) {
        winner = incumbentCell
        winnerScore = incumbentScore
      } else if (eligible.some((c) => keyOf(c) === keyOf(best.cell)) || !incumbentCell) {
        // Switch only to an eligible challenger, or seed the very first incumbent.
        winner = best.cell
        winnerScore = best.score
      } else {
        winner = incumbentCell
        winnerScore = incumbentScore
      }
      store.chosen[role] = { modelId: winner.modelId, variantId: winner.variantId }
      winners[role] = { modelId: winner.modelId, variantId: winner.variantId, score: round3(winnerScore) }
    }
    if (round != null) store.lastReviewRound = round
    return winners
  }

  /**
   * Apply the review winners to the live routing levers so the NEXT round picks them up:
   *   • model → `GlobalConfig.agent_models[role]` (read by `resolveForAgent`)
   *   • variant → `.openhack/agent-variants.json` (read by `Variants.fragmentFor`)
   */
  export function enforce(winners: Record<string, { modelId: string; variantId: string }>): void {
    const models: Record<string, string> = {}
    for (const [role, w] of Object.entries(winners)) {
      models[role] = w.modelId
      Variants.setChosen(role, w.variantId)
    }
    if (Object.keys(models).length) {
      const cur = GlobalConfig.get().agent_models ?? {}
      GlobalConfig.set({ agent_models: { ...cur, ...models } })
    }
  }

  function gridCells(role: string, grid: Grid): CandidateKey[] {
    const models = grid.models ?? []
    const variants = grid.variants?.length ? grid.variants : ["default"]
    const cells: CandidateKey[] = []
    for (const modelId of models) for (const variantId of variants) cells.push({ role, modelId, variantId })
    return cells
  }

  function fallbackCell(role: string, grid: Grid): { modelId: string; variantId: string } {
    return { modelId: grid.models?.[0] ?? GlobalConfig.resolveForAgent(role), variantId: grid.variants?.[0] ?? "default" }
  }

  function bestCell(
    store: Store,
    cells: CandidateKey[],
    opts: { minSamples?: number; seedFromModelsDev?: boolean },
  ): { cell: CandidateKey; score: number } {
    let best = cells[0]!
    let bestScore = scoreCandidate(store, best, opts)
    for (const c of cells.slice(1)) {
      const s = scoreCandidate(store, c, opts)
      if (s > bestScore) { best = c; bestScore = s }
    }
    return { cell: best, score: bestScore }
  }

  /** Read the o5.* config section from `.openhack/openhack.jsonc`. */
  export function config(): Config {
    const enabled = Boolean(ConfigStore.get("o5.enabled") ?? false)
    const reviewEvery = Math.max(1, Number(ConfigStore.get("o5.review_every") ?? 3))
    const epsilon = clamp01(Number(ConfigStore.get("o5.explore_epsilon") ?? 0.2))
    const minSamples = Math.max(1, Number(ConfigStore.get("o5.min_samples") ?? 3))
    const seedFromModelsDev = Boolean(ConfigStore.get("o5.seed_from_models_dev") ?? false)
    const raw = (ConfigStore.get("o5.candidates") as Record<string, Grid> | undefined) ?? {}
    const candidates: Record<string, Grid> = {}
    for (const [role, g] of Object.entries(raw)) {
      if (!g || !Array.isArray(g.models) || g.models.length === 0) continue
      candidates[role] = { models: g.models, variants: Array.isArray(g.variants) && g.variants.length ? g.variants : ["default"] }
    }
    return { enabled, reviewEvery, epsilon, minSamples, seedFromModelsDev, candidates }
  }

  function clamp01(n: number): number {
    if (!Number.isFinite(n)) return 0.2
    return Math.max(0.01, Math.min(1, n))
  }
}
