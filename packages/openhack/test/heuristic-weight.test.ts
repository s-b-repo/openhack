import { describe, expect, test } from "bun:test"
import { HeuristicController, GraphStore, AttackGraph } from "../../openhack-orchestration/src"
import type { ControllerInput, CombinationGapsLike } from "../../openhack-orchestration/src/types"

/**
 * Severity-weighted frontier scoring — with weights populated on
 * CombinationGapsLike.payloads/chains, the heuristic must emit ActionNodes
 * whose priority/score reflect the weight.
 */

function inputWith(combinationGaps: CombinationGapsLike | null): ControllerInput {
  return {
    target: "example.com",
    round: 2,
    snapshot: GraphStore.empty("example.com"),
    findings: [],
    coverageSummary: null,
    coverageGaps: [],
    combinationGaps,
    lastRoundDelta: { newFindings: 0, newHigh: 0, costUsd: 0 },
    budgetRemainingUsd: 10,
    currentFrontierIds: [],
  }
}

function emptyGaps(): CombinationGapsLike {
  return { methods: [], payloads: [], chains: [], perFinding: [], universeSize: 0, satisfiedSize: 0 }
}

describe("HeuristicController — severity-weighted scoring", () => {
  test("high-weight payload gap outscores low-weight payload gap", () => {
    const gaps = emptyGaps()
    gaps.payloads = [
      { endpoint: "/a", method: "POST", classId: "sqli", className: "SQL injection", missingFamilies: ["time-blind"], weight: "high" },
      { endpoint: "/b", method: "GET", classId: "sec-headers", className: "Security headers & TLS", missingFamilies: [], weight: "low" },
    ]
    const update = HeuristicController.run(inputWith(gaps))
    const hi = update.addNodes.find((n: any) => n.objective?.includes("sqli"))!
    const lo = update.addNodes.find((n: any) => n.objective?.includes("sec-headers"))!
    expect(hi).toBeDefined()
    expect(lo).toBeDefined()
    expect((hi as any).score).toBeGreaterThan((lo as any).score)
    expect((hi as any).priority).toBeLessThan((lo as any).priority)
  })

  test("high-weight chain gap outscores medium-weight chain gap", () => {
    const gaps = emptyGaps()
    gaps.chains = [
      { endpointA: "/a", methodA: "POST", classA: "sqli", endpointB: "/b", methodB: "GET", classB: "auth", weight: "high" },
      { endpointA: "/c", methodA: "GET", classA: "clickjacking", endpointB: "/d", methodB: "GET", classB: "cache", weight: "medium" },
    ]
    const update = HeuristicController.run(inputWith(gaps))
    const hi = update.addNodes.find((n: any) => n.objective?.includes("chain-sqli"))!
    const md = update.addNodes.find((n: any) => n.objective?.includes("chain-clickjacking"))!
    expect(hi).toBeDefined()
    expect(md).toBeDefined()
    expect((hi as any).score).toBeGreaterThan((md as any).score)
  })

  test("high-weight actions land at the top of frontier(k)", () => {
    const gaps = emptyGaps()
    gaps.payloads = [
      { endpoint: "/lo", method: "GET", classId: "sec-headers", className: "Security headers & TLS", missingFamilies: [], weight: "low" },
      { endpoint: "/hi", method: "POST", classId: "sqli", className: "SQL injection", missingFamilies: ["time-blind"], weight: "high" },
    ]
    const update = HeuristicController.run(inputWith(gaps))
    // Apply to a graph and see the top of frontier(2).
    const snap = GraphStore.empty("example.com")
    AttackGraph.apply(snap, update, 2)
    const top = AttackGraph.frontier(snap, 1)[0]!
    expect(top.objective).toMatch(/sqli/)
  })

  test("default weight ('medium' when unset) still gives a workable score", () => {
    const gaps = emptyGaps()
    gaps.payloads = [
      { endpoint: "/x", method: "POST", classId: "sqli", className: "SQL injection", missingFamilies: ["time-blind"] },
    ]
    const update = HeuristicController.run(inputWith(gaps))
    const n = update.addNodes[0] as any
    expect(n.score).toBe(4) // medium default → 4
    expect(n.priority).toBe(3)
  })
})
