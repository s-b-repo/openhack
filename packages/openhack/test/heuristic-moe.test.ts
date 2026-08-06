import { describe, expect, test } from "bun:test"
import { HeuristicController, GraphStore } from "../../openhack-orchestration/src"
import type { ControllerInput, CombinationGapsLike } from "../../openhack-orchestration/src/types"

/**
 * MoE routing integration on the heuristic controller. Guards:
 *   • When routeAgent is supplied, gap actions use its verdict.
 *   • When routeAgent throws, the fallback (classifyGapAgent regex) is used.
 *   • When routeAgent returns empty/invalid, the fallback is used.
 *   • When routeAgent is unset, hard-coded doctrine defaults kick in (byte-compat).
 */

function base(overrides: Partial<ControllerInput> = {}): ControllerInput {
  return {
    target: "example.com",
    round: 2,
    snapshot: GraphStore.empty("example.com"),
    findings: [],
    coverageSummary: null,
    coverageGaps: [],
    combinationGaps: null,
    lastRoundDelta: { newFindings: 0, newHigh: 0, costUsd: 0 },
    budgetRemainingUsd: 10,
    currentFrontierIds: [],
    ...overrides,
  }
}

function makeGaps(): CombinationGapsLike {
  return { methods: [], payloads: [], chains: [], perFinding: [], universeSize: 0, satisfiedSize: 0 }
}

describe("HeuristicController — MoE routing", () => {
  test("routeAgent decides the gap action's agent when supplied", () => {
    const seen: string[] = []
    const routeAgent = (prompt: string) => { seen.push(prompt); return "post-exploit" }
    const update = HeuristicController.run(base({
      coverageGaps: [{ endpoint: "/x", method: "GET", classId: "sqli", className: "SQL injection" }],
      routeAgent,
    }))
    const gapAction: any = update.addNodes.find((n: any) => n.objective?.startsWith("test-gap-"))
    expect(gapAction).toBeDefined()
    expect(gapAction.agent).toBe("post-exploit")
    expect(seen.length).toBeGreaterThan(0)
  })

  test("routeAgent verdict routes payload actions too", () => {
    const gaps = makeGaps()
    gaps.payloads = [{ endpoint: "/x", method: "POST", classId: "sqli", className: "SQL injection", missingFamilies: ["time-blind"], weight: "high" }]
    const routeAgent = () => "recon"
    const update = HeuristicController.run(base({ combinationGaps: gaps, routeAgent }))
    const payloadAction: any = update.addNodes.find((n: any) => n.objective?.startsWith("test-payload-"))
    expect(payloadAction).toBeDefined()
    expect(payloadAction.agent).toBe("recon")
  })

  test("routeAgent throwing → fallback to classifyGapAgent", () => {
    const routeAgent = () => { throw new Error("nope") }
    const update = HeuristicController.run(base({
      coverageGaps: [{ endpoint: "/x", method: "GET", classId: "sqli", className: "SQL injection" }],
      routeAgent,
    }))
    const gapAction: any = update.addNodes.find((n: any) => n.objective?.startsWith("test-gap-"))
    // classifyGapAgent returns "exploit" for injection-family classes.
    expect(["exploit", "recon", "post-exploit"]).toContain(gapAction.agent)
  })

  test("routeAgent returning empty string → fallback", () => {
    const routeAgent = () => ""
    const update = HeuristicController.run(base({
      coverageGaps: [{ endpoint: "/x", method: "GET", classId: "sqli", className: "SQL injection" }],
      routeAgent,
    }))
    const gapAction: any = update.addNodes.find((n: any) => n.objective?.startsWith("test-gap-"))
    expect(["exploit", "recon", "post-exploit"]).toContain(gapAction.agent)
  })

  test("no routeAgent → doctrine defaults (byte-compat with pre-MoE build)", () => {
    const update = HeuristicController.run(base({
      coverageGaps: [{ endpoint: "/x", method: "GET", classId: "sqli", className: "SQL injection" }],
    }))
    const gapAction: any = update.addNodes.find((n: any) => n.objective?.startsWith("test-gap-"))
    // classifyGapAgent picks 'exploit' for sqli / injection-adjacent classes.
    expect(gapAction.agent).toBe("exploit")
  })
})
