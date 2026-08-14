// Graph controller score persistence.
//
// After every round, the loop records what actions were dispatched last round
// and what the delta was (new findings, cost, high-value). Over time this
// yields a per-action-kind history the heuristic + LLM controllers consult
// when emitting new frontier ActionNodes — actions that historically produced
// findings get their score bumped, ones that consistently returned nothing
// get dampened. Cross-run learning without any ML: just a rolling mean.
//
// File: `.openhack/graph-scores.<target>.json`. HMAC-signed via GraphStore so
// the file is tamper-evident just like the graph and coverage stores. (Earlier
// builds wrote `.openhack/graph-scores.json.<target>`, which read as a stray
// file in the repo root; those are migrated on first read — see load().)
//
// Action kind = the ActionNode.agent field. That's the coarsest useful bucket
// — "recon" wins its own reweight independently of "exploit-sqli" — while
// staying stable across runs (kind name doesn't change when the prompt does).
// A future refinement could hash the prompt-template family, but agent-name
// buckets are enough to move the needle for now.

import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"
import { GraphStore } from "./store"

export namespace Scores {
  export interface KindStats {
    /** How many times this action kind has been dispatched, across all rounds. */
    dispatches: number
    /** Rounds where the dispatch was followed by ≥1 new finding. */
    productiveRounds: number
    /** Rounds where the dispatch was followed by ≥1 high-value finding. */
    highValueRounds: number
    /** Rolling mean of new findings per round when dispatched. */
    meanNewFindings: number
    /** Rolling mean of cost paid per round when dispatched. */
    meanCostUsd: number
    /** Last round this kind was dispatched (across runs, may be from an earlier session). */
    lastRound: number
    /** Last epoch-ms timestamp of a dispatch. */
    lastAt: number
  }

  export interface Store {
    target: string
    kinds: Record<string, KindStats>
    /** Round of the most-recent record() call — dedup guard against double-record. */
    lastAppliedRound: number
  }

  const DIR = ".openhack"
  const BASE = "graph-scores"

  function safeTarget(target: string): string {
    return target.replace(/[^a-zA-Z0-9.-]/g, "_")
  }
  function fileFor(target: string): string {
    return path.join(DIR, `${BASE}.${safeTarget(target)}.json`)
  }
  // Legacy shape (`graph-scores.json.<target>`) — migrated on first read.
  function legacyFileFor(target: string): string {
    return path.join(DIR, `${BASE}.json.${safeTarget(target)}`)
  }

  function empty(target: string): Store {
    return { target, kinds: {}, lastAppliedRound: 0 }
  }

  function signBody(body: string): string {
    const key = GraphStore.getSigningKey()
    return crypto.createHmac("sha256", key).update(body).digest("hex")
  }

  export function load(target: string): Store {
    const f = fileFor(target)
    if (!fs.existsSync(f)) {
      // One-time migration from the old `graph-scores.json.<target>` name.
      const legacy = legacyFileFor(target)
      if (fs.existsSync(legacy)) {
        try {
          fs.mkdirSync(DIR, { recursive: true })
          fs.renameSync(legacy, f)
        } catch {}
      }
    }
    if (!fs.existsSync(f)) return empty(target)
    try {
      const raw = fs.readFileSync(f, "utf-8")
      const parsed = JSON.parse(raw) as { body: string; sig: string }
      const expected = signBody(parsed.body)
      // Constant-time equality check — HMAC tamper resistance.
      if (parsed.sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(parsed.sig), Buffer.from(expected))) {
        process.stderr.write(`[scores] HMAC verification failed for ${target} — dropping cache and starting fresh.\n`)
        return empty(target)
      }
      return JSON.parse(parsed.body) as Store
    } catch {
      return empty(target)
    }
  }

  export function save(store: Store): void {
    fs.mkdirSync(DIR, { recursive: true })
    const body = JSON.stringify(store)
    const doc = { body, sig: signBody(body) }
    const f = fileFor(store.target)
    const tmp = `${f}.tmp`
    fs.writeFileSync(tmp, JSON.stringify(doc, null, 2))
    fs.renameSync(tmp, f)
  }

  /**
   * Record one round's outcome for a set of dispatched action kinds.
   * `roundNumber` is used to detect + skip a double-record. Rolling means
   * are updated with (n → n+1) Welford-style so the store size stays flat.
   */
  export function record(store: Store, args: {
    roundNumber: number
    dispatchedKinds: string[]
    newFindings: number
    newHigh: number
    roundCostUsd: number
  }): Store {
    if (args.roundNumber <= store.lastAppliedRound) return store
    const now = Date.now()
    const perKindShare = args.dispatchedKinds.length > 0 ? args.newFindings / args.dispatchedKinds.length : 0
    const perKindHigh = args.dispatchedKinds.length > 0 ? args.newHigh / args.dispatchedKinds.length : 0
    const perKindCost = args.dispatchedKinds.length > 0 ? args.roundCostUsd / args.dispatchedKinds.length : 0
    for (const kind of args.dispatchedKinds) {
      const cur = store.kinds[kind] ?? {
        dispatches: 0, productiveRounds: 0, highValueRounds: 0,
        meanNewFindings: 0, meanCostUsd: 0, lastRound: 0, lastAt: 0,
      }
      const n = cur.dispatches + 1
      const meanF = cur.meanNewFindings + (perKindShare - cur.meanNewFindings) / n
      const meanC = cur.meanCostUsd + (perKindCost - cur.meanCostUsd) / n
      store.kinds[kind] = {
        dispatches: n,
        productiveRounds: cur.productiveRounds + (perKindShare > 0 ? 1 : 0),
        highValueRounds: cur.highValueRounds + (perKindHigh > 0 ? 1 : 0),
        meanNewFindings: Math.round(meanF * 1000) / 1000,
        meanCostUsd: Math.round(meanC * 10000) / 10000,
        lastRound: args.roundNumber,
        lastAt: now,
      }
    }
    store.lastAppliedRound = args.roundNumber
    return store
  }

  /**
   * Prior multiplier for a given action kind — bounded to [0.25, 3.0].
   *
   * Formula:
   *   - Unknown kind (0 dispatches): return 1.0 (neutral — try it).
   *   - success_rate = productiveRounds / dispatches ∈ [0, 1]
   *   - efficiency = meanNewFindings / max(meanCostUsd, 0.001)
   *   - prior = 0.5 + success_rate * 2.0 + tanh(efficiency / 5) * 0.5
   *   - clamp to [0.25, 3.0]
   *
   * A kind that always produces findings (success_rate=1) with reasonable cost
   * lands near ~2.5–3.0, one that never has → ~0.5, an unknown one stays at 1.0.
   * The heuristic multiplies the base ActionNode score by this prior before
   * emitting to the frontier.
   */
  export function priorFor(store: Store, kind: string): number {
    const s = store.kinds[kind]
    if (!s || s.dispatches === 0) return 1.0
    const successRate = s.productiveRounds / s.dispatches
    const efficiency = s.meanNewFindings / Math.max(s.meanCostUsd, 0.001)
    const raw = 0.5 + successRate * 2.0 + Math.tanh(efficiency / 5) * 0.5
    return Math.min(3.0, Math.max(0.25, Math.round(raw * 100) / 100))
  }

  /** Bulk prior — small convenience for a heuristic that wants a whole map. */
  export function priorMap(store: Store, kinds: string[]): Record<string, number> {
    const out: Record<string, number> = {}
    for (const k of kinds) out[k] = priorFor(store, k)
    return out
  }

  /**
   * Compact summary for `openhack status` — the top-5 highest-prior kinds and
   * the bottom-5 (so an operator can eyeball what's producing vs. what's dead
   * weight).
   */
  export function summary(store: Store, limit = 5): { top: Array<{ kind: string; prior: number; dispatches: number; productive: number }>; bottom: Array<{ kind: string; prior: number; dispatches: number; productive: number }> } {
    const rows = Object.entries(store.kinds).map(([kind, s]) => ({
      kind, prior: priorFor(store, kind), dispatches: s.dispatches, productive: s.productiveRounds,
    }))
    rows.sort((a, b) => b.prior - a.prior)
    return {
      top: rows.slice(0, limit),
      bottom: rows.filter((r) => r.dispatches >= 2).slice(-limit).reverse(),
    }
  }
}
