// Overwatch (o5) benchmark-council tests.
//
//   • record → Welford rolling means + round dedup
//   • scoreCandidate → productive candidate ranks far above a dead one; cold-start seed
//   • pick → deterministic exploration (round-robin under minSamples; incumbent stability)
//   • review → argmax with minSamples anti-thrash stability
//   • enforce → writes agent_models + agent-variants.json; resolveForAgent honors it
//   • save/load roundtrip + HMAC tamper → fresh store

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Overwatch } from "../src/overwatch"
import { GlobalConfig } from "../src/global-config"
import { Variants } from "../src/variants"

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "overwatch-test-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
  GlobalConfig.reset()
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
  GlobalConfig.reset()
})

const MA = "anthropic/claude-sonnet-4"
const MB = "openai/o3"

function outcome(role: string, modelId: string, variantId: string, nf: number, nh = 0, conf = 0, cost = 0.1, lat = 1000): Overwatch.RoundRoleOutcome {
  return { role, modelId, variantId, newFindings: nf, newHigh: nh, confirmed: conf, costUsd: cost, latencyMs: lat }
}

describe("Overwatch.record", () => {
  test("Welford rolling means across rounds", () => {
    const s = Overwatch.empty()
    Overwatch.record(s, 1, [outcome("exploit", MA, "default", 2, 1, 1, 0.1)])
    Overwatch.record(s, 2, [outcome("exploit", MA, "default", 4, 1, 1, 0.3)])
    const c = s.candidates[Overwatch.keyOf({ role: "exploit", modelId: MA, variantId: "default" })]!
    expect(c.dispatches).toBe(2)
    expect(c.meanNewFindings).toBe(3) // (2+4)/2
    expect(c.meanCostUsd).toBe(0.2) // (0.1+0.3)/2
    expect(c.productiveRounds).toBe(2)
    expect(c.confirmedRounds).toBe(2)
  })

  test("record dedups on the same round", () => {
    const s = Overwatch.empty()
    Overwatch.record(s, 1, [outcome("exploit", MA, "default", 2)])
    Overwatch.record(s, 1, [outcome("exploit", MA, "default", 100)])
    const c = s.candidates[Overwatch.keyOf({ role: "exploit", modelId: MA, variantId: "default" })]!
    expect(c.dispatches).toBe(1)
  })
})

describe("Overwatch.scoreCandidate", () => {
  test("productive candidate scores far above a dead one", () => {
    const s = Overwatch.empty()
    for (let r = 1; r <= 5; r++) Overwatch.record(s, r, [outcome("exploit", MA, "default", 3, 1, 1, 0.1)])
    for (let r = 6; r <= 10; r++) Overwatch.record(s, r, [outcome("exploit", MB, "default", 0, 0, 0, 0.1)])
    const good = Overwatch.scoreCandidate(s, { role: "exploit", modelId: MA, variantId: "default" }, { minSamples: 3 })
    const dead = Overwatch.scoreCandidate(s, { role: "exploit", modelId: MB, variantId: "default" }, { minSamples: 3 })
    expect(good).toBeGreaterThan(2.0)
    expect(dead).toBeLessThan(1.0)
    expect(good).toBeGreaterThan(dead)
  })

  test("unsampled candidate returns the neutral seed (1.0)", () => {
    const s = Overwatch.empty()
    expect(Overwatch.scoreCandidate(s, { role: "exploit", modelId: MA, variantId: "default" })).toBe(1.0)
  })
})

describe("Overwatch.pick", () => {
  const grid: Overwatch.Grid = { models: [MA, MB], variants: ["default", "chain-forward"] }

  test("round-robins under-sampled cells so the whole grid gets measured", () => {
    const s = Overwatch.empty()
    const seen = new Set<string>()
    for (let r = 0; r < 4; r++) {
      const p = Overwatch.pick(s, "exploit", grid, r, 0.2, { minSamples: 3 })
      seen.add(`${p.modelId}::${p.variantId}`)
    }
    expect(seen.size).toBe(4) // all four cells visited
  })

  test("once sampled, a set incumbent is returned on non-explore rounds", () => {
    const s = Overwatch.empty()
    // Give every cell >= minSamples so nothing is under-sampled.
    for (let r = 1; r <= 3; r++) {
      Overwatch.record(s, r * 10 + 1, [outcome("exploit", MA, "default", 1)])
      Overwatch.record(s, r * 10 + 2, [outcome("exploit", MA, "chain-forward", 1)])
      Overwatch.record(s, r * 10 + 3, [outcome("exploit", MB, "default", 1)])
      Overwatch.record(s, r * 10 + 4, [outcome("exploit", MB, "chain-forward", 1)])
    }
    s.chosen["exploit"] = { modelId: MB, variantId: "chain-forward" }
    // round 1 is not an explore round for epsilon 0.2 (period 5) → incumbent.
    const p = Overwatch.pick(s, "exploit", grid, 1, 0.2, { minSamples: 3 })
    expect(p).toEqual({ modelId: MB, variantId: "chain-forward" })
  })
})

describe("Overwatch.review", () => {
  const grid: Overwatch.Grid = { models: [MA, MB], variants: ["default"] }
  const roles = { exploit: grid }

  test("picks the argmax candidate that has enough samples", () => {
    const s = Overwatch.empty()
    for (let r = 1; r <= 5; r++) Overwatch.record(s, r, [outcome("exploit", MA, "default", 3, 1, 1, 0.1)])
    for (let r = 6; r <= 10; r++) Overwatch.record(s, r, [outcome("exploit", MB, "default", 0, 0, 0, 0.1)])
    const winners = Overwatch.review(s, roles, 3, 10)
    expect(winners.exploit!.modelId).toBe(MA)
    expect(s.chosen["exploit"]).toEqual({ modelId: MA, variantId: "default" })
    expect(s.lastReviewRound).toBe(10)
  })

  test("an under-sampled challenger cannot unseat a solid incumbent", () => {
    const s = Overwatch.empty()
    // MA is the incumbent, well-sampled and productive.
    for (let r = 1; r <= 5; r++) Overwatch.record(s, r, [outcome("exploit", MA, "default", 3, 1, 1, 0.1)])
    s.chosen["exploit"] = { modelId: MA, variantId: "default" }
    // MB has just ONE great-looking round (below minSamples=3) — must not win.
    Overwatch.record(s, 6, [outcome("exploit", MB, "default", 100, 100, 100, 0.001)])
    const winners = Overwatch.review(s, roles, 3, 6)
    expect(winners.exploit!.modelId).toBe(MA)
  })
})

describe("Overwatch.enforce", () => {
  test("writes agent_models + variant; resolveForAgent + fragmentFor reflect it", () => {
    Overwatch.enforce({ exploit: { modelId: MB, variantId: "chain-forward" } })
    expect(GlobalConfig.resolveForAgent("exploit")).toBe(MB)
    expect(Variants.chosenFor("exploit")).toBe("chain-forward")
    expect(fs.existsSync(".openhack/agent-variants.json")).toBe(true)
  })
})

describe("Overwatch save/load", () => {
  test("roundtrip preserves stats", () => {
    const s = Overwatch.empty()
    Overwatch.record(s, 1, [outcome("recon", MA, "default", 2, 0, 0, 0.05)])
    Overwatch.save(s)
    const loaded = Overwatch.load()
    expect(loaded.candidates[Overwatch.keyOf({ role: "recon", modelId: MA, variantId: "default" })]!.dispatches).toBe(1)
    expect(loaded.lastAppliedRound).toBe(1)
  })

  test("HMAC tamper → fresh store", () => {
    const s = Overwatch.empty()
    Overwatch.record(s, 1, [outcome("recon", MA, "default", 2)])
    Overwatch.save(s)
    const raw = JSON.parse(fs.readFileSync(".openhack/overwatch.json", "utf-8"))
    raw.body = raw.body.replace("recon", "attacker")
    fs.writeFileSync(".openhack/overwatch.json", JSON.stringify(raw))
    expect(Object.keys(Overwatch.load().candidates).length).toBe(0)
  })
})
