// Loop-physics tests — the quantitative model behind the loop-vs-graph stance.
//
//   • Reliability: compounding step decay (p^n), max unverified chain length,
//     checkpoint intervals, rework math, schedule discounts.
//   • ContextHealth: retrieval-fidelity curve anchored at the published
//     ~97% → ~37% @500K measurements, verdict bands, effective reliability.
//   • Tuner kernel: min-max normalized scoring + deterministic winner picking.
//   • Heuristic integration: chain actions carry the physics annotation and
//     discounted scores; ordering doctrine (verify > chain > gap) still holds.

import { describe, expect, test } from "bun:test"
import { LoopPhysics, HeuristicController, GraphStore } from "../../openhack-orchestration/src"
import type { ControllerInput, FindingLike } from "../../openhack-orchestration/src/types"

const { Reliability, ContextHealth } = LoopPhysics

describe("Reliability.compound", () => {
  test("p^n decays exponentially — 95% per step over 100 steps ≈ 0.6%", () => {
    const r = Reliability.compound(0.95, 100)
    expect(r).toBeGreaterThan(0.005)
    expect(r).toBeLessThan(0.007)
  })

  test("edge cases: n=0 → 1, p=1 → 1, p≤0 → 0", () => {
    expect(Reliability.compound(0.9, 0)).toBe(1)
    expect(Reliability.compound(1, 500)).toBe(1)
    expect(Reliability.compound(0, 3)).toBe(0)
    expect(Reliability.compound(-1, 3)).toBe(0)
  })

  test("monotone decreasing in chain length", () => {
    let prev = 1
    for (let n = 1; n <= 20; n++) {
      const r = Reliability.compound(0.9, n)
      expect(r).toBeLessThanOrEqual(prev)
      prev = r
    }
  })
})

describe("Reliability.plan / risk", () => {
  test("plan multiplies heterogeneous steps", () => {
    expect(Reliability.plan([0.9, 0.9, 0.9])).toBeCloseTo(0.729, 10)
  })

  test("risk bands: green ≥ 2×floor, yellow ≥ floor, red < floor", () => {
    // Two 95% steps → 0.9025 ≥ 2×0.5? No — 2×floor = 1.0, so 0.9025 is yellow.
    // Use a small floor to exercise green.
    expect(Reliability.risk([0.95, 0.95], 0.4).band).toBe("green")
    expect(Reliability.risk([0.85, 0.85], 0.5).band).toBe("yellow") // 0.7225 ∈ [0.5, 1)
    expect(Reliability.risk(Array.from({ length: 6 }, () => 0.85), 0.5).band).toBe("red")
  })

  test("red-band recommendation names a verified-stage split", () => {
    const v = Reliability.risk(Array.from({ length: 8 }, () => 0.85), 0.5)
    expect(v.band).toBe("red")
    expect(v.recommendation).toMatch(/split into ≤\d+-step verified stages/)
  })

  test("empty plan is trivially green", () => {
    const v = Reliability.risk([], 0.5)
    expect(v.reliability).toBe(1)
    expect(v.band).toBe("green")
  })
})

describe("Reliability.maxUnverifiedSteps / checkpointInterval", () => {
  test("at p=0.95, an unverified chain clears the 0.5 floor for exactly 13 steps", () => {
    expect(Reliability.maxUnverifiedSteps(0.95, 0.5)).toBe(13)
    expect(Reliability.compound(0.95, 13)).toBeGreaterThanOrEqual(0.5)
    expect(Reliability.compound(0.95, 14)).toBeLessThan(0.5)
  })

  test("never below 1 even at terrible odds", () => {
    expect(Reliability.maxUnverifiedSteps(0.05, 0.9)).toBe(1)
  })

  test("perfect steps → unbounded chains", () => {
    expect(Reliability.maxUnverifiedSteps(1, 0.999)).toBe(Number.POSITIVE_INFINITY)
  })

  test("checkpointInterval is the same bound by intent", () => {
    expect(Reliability.checkpointInterval(0.95, 0.5)).toBe(Reliability.maxUnverifiedSteps(0.95, 0.5))
  })
})

describe("Reliability.expectedRework", () => {
  test("unverified long chains pay near-full-chain rework; checkpoints cap it", () => {
    const unverified = Reliability.expectedRework(0.95, 100)
    const checked = Reliability.expectedRework(0.95, 100, 10)
    expect(unverified).toBeGreaterThan(90)   // (1 − 0.95¹⁰⁰) × 100 ≈ 99.4
    expect(checked).toBeLessThan(10)         // same failure prob, lag capped at 10
    expect(checked).toBeLessThan(unverified / 9)
  })

  test("zero-length plans waste nothing", () => {
    expect(Reliability.expectedRework(0.9, 0)).toBe(0)
  })
})

describe("Reliability.scheduleDiscount", () => {
  test("shallow chains are undiscounted; deep chains bounded in [minMult, 1)", () => {
    expect(Reliability.scheduleDiscount(1)).toBe(1)
    expect(Reliability.scheduleDiscount(0)).toBe(1)
    const d3 = Reliability.scheduleDiscount(3, 0.85, 0.4)
    expect(d3).toBeCloseTo(Math.pow(0.85, 3), 10)
    expect(Reliability.scheduleDiscount(50, 0.85, 0.4)).toBe(0.4)
    for (let d = 1; d <= 30; d++) {
      const v = Reliability.scheduleDiscount(d)
      expect(v).toBeGreaterThan(0)
      expect(v).toBeLessThanOrEqual(1)
    }
  })
})

describe("ContextHealth.fidelityAt", () => {
  test("anchors: ~97% at short contexts, exactly 37% at the 500K cliff", () => {
    expect(ContextHealth.fidelityAt(32_000)).toBeCloseTo(0.97, 10)
    expect(ContextHealth.fidelityAt(500_000)).toBeCloseTo(0.37, 10)
  })

  test("monotone non-increasing across the whole range, clamped ≥ 0 past the curve", () => {
    let prev = 1.01
    for (let t = 0; t <= 800_000; t += 25_000) {
      const f = ContextHealth.fidelityAt(t)
      expect(f).toBeLessThanOrEqual(prev)
      expect(f).toBeGreaterThanOrEqual(0)
      prev = f
    }
    expect(ContextHealth.fidelityAt(600_000)).toBeLessThan(0.37)
  })

  test("short contexts are effectively perfect recall", () => {
    expect(ContextHealth.fidelityAt(0)).toBe(1)
  })
})

describe("ContextHealth.verdict", () => {
  test("healthy → continue at short contexts", () => {
    const v = ContextHealth.verdict(16_000)
    expect(v.band).toBe("healthy")
    expect(v.action).toBe("continue")
  })

  test("degrading mid-range → compact", () => {
    const v = ContextHealth.verdict(150_000)
    expect(v.band).toBe("degrading")
    expect(v.action).toBe("compact")
  })

  test("past ~60% fidelity → cliff → fresh-instance", () => {
    const v = ContextHealth.verdict(400_000)
    expect(v.band).toBe("cliff")
    expect(v.action).toBe("fresh-instance")
  })

  test("verdict carries its own fidelity number", () => {
    const v = ContextHealth.verdict(250_000)
    expect(v.fidelity).toBeCloseTo(ContextHealth.fidelityAt(250_000), 3)
  })
})

describe("ContextHealth.effectiveStep / effectiveReliability", () => {
  test("a 500K-token step is only ~37% as reliable as the same step fresh", () => {
    const eff = ContextHealth.effectiveStep(0.9, 500_000)
    expect(eff).toBeCloseTo(0.333, 10)
  })

  test("effectiveReliability compounds context-discounted steps", () => {
    const r = ContextHealth.effectiveReliability([
      { p: 0.9, tokens: 0 },
      { p: 0.9, tokens: 0 },
    ])
    expect(r).toBeCloseTo(0.81, 10)
    // Same two steps run deep into degradation compound much lower.
    const degraded = ContextHealth.effectiveReliability([
      { p: 0.9, tokens: 400_000 },
      { p: 0.9, tokens: 400_000 },
    ])
    expect(degraded).toBeLessThan(0.81 * 0.5)
  })
})

describe("Tuner kernel (scoreRun / pickWinner)", () => {
  const bw = {
    highs: [0, 10] as [number, number],
    covs: [0, 100] as [number, number],
    totals: [0, 20] as [number, number],
    costs: [0, 1] as [number, number],
    walls: [0, 60] as [number, number],
  }

  test("higher findings/coverage and lower cost/wall score better", () => {
    const good = LoopPhysics.scoreRun({ high: 10, cov: 100, total: 20, cost: 0, wall: 0 }, bw)
    const bad = LoopPhysics.scoreRun({ high: 0, cov: 0, total: 0, cost: 1, wall: 60 }, bw)
    expect(good).toBeGreaterThan(bad)
    expect(good).toBeCloseTo(LoopPhysics.TUNER_WEIGHTS.highValue + LoopPhysics.TUNER_WEIGHTS.coverage + LoopPhysics.TUNER_WEIGHTS.totalFindings + LoopPhysics.TUNER_WEIGHTS.cost + LoopPhysics.TUNER_WEIGHTS.wall, 6)
  })

  test("missing metrics are neutral (mid-normalized), not best or worst", () => {
    const neutralOnly = LoopPhysics.scoreRun({}, bw)
    const allBest = LoopPhysics.scoreRun({ high: 10, cov: 100, total: 20, cost: 0, wall: 0 }, bw)
    expect(neutralOnly).toBeGreaterThan(badScore(bw))
    expect(neutralOnly).toBeLessThan(allBest)
  })

  function badScore(bw: unknown): number {
    return LoopPhysics.scoreRun({ high: 0, cov: 0, total: 0, cost: 1, wall: 60 }, bw as never)
  }

  test("pickWinner: highest score wins; ties break cheaper → simpler harness", () => {
    const w = LoopPhysics.pickWinner([
      { score: 1, frontierK: 6, instances: 2, wall: 5, cost: 0.5 },
      { score: 3, frontierK: 10, instances: 2, wall: 5, cost: 0.5 },
      { score: 2, frontierK: 4, instances: 1, wall: 5, cost: 0.1 },
    ])
    expect(w!.frontierK).toBe(10)

    const tie = LoopPhysics.pickWinner([
      { score: 3, frontierK: 6, instances: 2, wall: 9, cost: 0.5 },
      { score: 3, frontierK: 6, instances: 2, wall: 9, cost: 0.5 },
      { score: 3, frontierK: 6, instances: 1, wall: 9, cost: 0.2 },
      { score: 3, frontierK: 4, instances: 1, wall: 9, cost: 0.2 },
    ])
    // Cost dominates first: cheapest pair survives, then the narrower harness.
    expect(tie!.cost).toBe(0.2)
    expect(tie!.frontierK).toBe(4)
    expect(tie!.instances).toBe(1)
  })

  test("pickWinner on empty grid → null", () => {
    expect(LoopPhysics.pickWinner([])).toBeNull()
  })
})

// ---------- heuristic integration ---------------------------------------------

function inputWith(overrides: Partial<ControllerInput> = {}): ControllerInput {
  return {
    target: "example.com",
    round: 2,
    snapshot: GraphStore.empty("example.com"),
    findings: [],
    coverageSummary: null,
    coverageGaps: [],
    lastRoundDelta: { newFindings: 0, newHigh: 0, costUsd: 0 },
    budgetRemainingUsd: 10,
    currentFrontierIds: [],
    combinationGaps: null,
    ...overrides,
  }
}

function finding(hash: string, severity: FindingLike["severity"], status: FindingLike["status"], title = "t"): FindingLike {
  return { hash, severity, status, title }
}

describe("HeuristicController physics staging", () => {
  test("chain actions carry a physics annotation with a discounted score", () => {
    const findings = [finding("h1", "critical", "verified", "auth-bypass")]
    const update = HeuristicController.run(inputWith({ findings }))
    const chain = update.addNodes.find((n: any) => n.objective?.startsWith("chain-finding-")) as any
    expect(chain).toBeDefined()
    expect(chain.physics).toBeDefined()
    expect(chain.physics.band).toBe("yellow") // depth 2 @0.85 → 0.7225 ∈ [0.5, 1)
    expect(chain.physics.reliability).toBeCloseTo(0.7225, 2)
    expect(chain.score).toBeCloseTo(5 * Math.pow(0.85, 2), 2) // nominal 5, depth-2 discount
    expect(update.rationale).toMatch(/physics=\d+/)
  })

  test("doctrine ordering survives the discount: verify > chain > gap", () => {
    const findings = [
      finding("h1", "critical", "uncertain"), // → verify (score 6)
      finding("h2", "critical", "verified"),  // → chain (score 5×0.7225≈3.61)
    ]
    const update = HeuristicController.run(inputWith({
      findings,
      coverageGaps: [{ endpoint: "/x", method: "GET", className: "SQL Injection", classId: "sqli" }],
    }))
    const verify = update.addNodes.find((n: any) => n.objective?.startsWith("verify-finding-")) as any
    const chain = update.addNodes.find((n: any) => n.objective?.startsWith("chain-finding-")) as any
    const gapAction = update.addNodes.find((n: any) => n.objective?.startsWith("test-gap-")) as any
    expect(verify.score).toBeGreaterThan(chain.score)
    // sqli gap: priority 2 → base score 3, no physics discount (not a chain-*).
    expect(gapAction.score).toBeLessThan(chain.score)
  })

  test("non-chain actions are untouched by the physics pass", () => {
    const update = HeuristicController.run(inputWith({
      coverageGaps: [{ endpoint: "/x", method: "GET", className: "SQL Injection", classId: "sqli" }],
    }))
    const gapAction = update.addNodes.find((n: any) => n.objective?.startsWith("test-gap-")) as any
    expect(gapAction.physics).toBeUndefined()
    expect(gapAction.score).toBe(3)
  })
})
