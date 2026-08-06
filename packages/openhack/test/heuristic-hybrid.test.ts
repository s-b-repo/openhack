import { describe, expect, test } from "bun:test"
import { HeuristicController, GraphStore } from "../../openhack-orchestration/src"
import type { ControllerInput, CombinationGapsLike, FindingLike } from "../../openhack-orchestration/src/types"

/**
 * Loop-graph hybrid heuristic branches. Guards:
 *   • Council ActionNode fires when lastRoundDelta.newFindings >= 2 (score 8, command="council").
 *   • Triage ActionNode fires when coverage AND method-combo thresholds trip (score 6, command="triage").
 *   • OSINT ActionNode fires on round 1 (agent=osint, no command).
 *   • Cleanup ActionNode fires when the entire checklist is closed (command="cleanup", priority 99).
 *   • Every hybrid emission carries `command` field where declared.
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

function emptyGaps(): CombinationGapsLike {
  return { methods: [], payloads: [], chains: [], perFinding: [], universeSize: 0, satisfiedSize: 0 }
}

describe("HeuristicController — council trigger", () => {
  test("emits council ActionNode when lastRoundDelta.newFindings >= 2", () => {
    const findings: FindingLike[] = [
      { hash: "aaa", severity: "critical", status: "verified", title: "F1" },
      { hash: "bbb", severity: "high", status: "verified", title: "F2" },
    ]
    const update = HeuristicController.run(base({
      lastRoundDelta: { newFindings: 3, newHigh: 2, costUsd: 0.5 },
      findings,
    }))
    const council = update.addNodes.find((n: any) => n.objective?.startsWith("council-review-"))
    expect(council).toBeDefined()
    expect((council as any).command).toBe("council")
    expect((council as any).score).toBe(8)
    expect((council as any).priority).toBe(1)
    // Requires: every new finding node id.
    expect((council as any).requires.length).toBe(findings.length)
  })

  test("does NOT emit council when newFindings < 2", () => {
    const update = HeuristicController.run(base({
      lastRoundDelta: { newFindings: 1, newHigh: 0, costUsd: 0.5 },
    }))
    const council = update.addNodes.find((n: any) => n.objective?.startsWith("council-review-"))
    expect(council).toBeUndefined()
  })
})

describe("HeuristicController — triage trigger", () => {
  test("emits triage ActionNode when coverage>20 AND method combos>5", () => {
    const gaps = emptyGaps()
    gaps.methods = Array.from({ length: 6 }, (_, i) => ({ endpoint: `/e${i}`, testedMethods: [], missingMethods: ["POST"] }))
    const coverageGaps = Array.from({ length: 25 }, (_, i) => ({ endpoint: `/e${i}`, method: "GET", classId: "sqli", className: "SQL injection" }))
    const update = HeuristicController.run(base({
      combinationGaps: gaps,
      coverageGaps,
    }))
    const triage = update.addNodes.find((n: any) => n.objective?.startsWith("triage-"))
    expect(triage).toBeDefined()
    expect((triage as any).command).toBe("triage")
    expect((triage as any).score).toBe(6)
  })

  test("does NOT emit triage when only method threshold trips (coverage below 20)", () => {
    const gaps = emptyGaps()
    gaps.methods = Array.from({ length: 10 }, (_, i) => ({ endpoint: `/e${i}`, testedMethods: [], missingMethods: ["POST"] }))
    const update = HeuristicController.run(base({ combinationGaps: gaps, coverageGaps: [] }))
    const triage = update.addNodes.find((n: any) => n.objective?.startsWith("triage-"))
    expect(triage).toBeUndefined()
  })
})

describe("HeuristicController — OSINT trigger", () => {
  test("emits OSINT ActionNode on round 1", () => {
    const update = HeuristicController.run(base({ round: 1 }))
    const osint = update.addNodes.find((n: any) => n.objective === "osint-r1")
    expect(osint).toBeDefined()
    expect((osint as any).agent).toBe("osint")
    // No command — OSINT dispatches as a normal agent.
    expect((osint as any).command).toBeUndefined()
  })

  test("does NOT emit OSINT on round 2+", () => {
    const update = HeuristicController.run(base({ round: 2 }))
    const osint = update.addNodes.find((n: any) => n.objective === "osint-r1")
    expect(osint).toBeUndefined()
  })
})

describe("HeuristicController — cleanup trigger", () => {
  test("emits cleanup ActionNode when frontier + combos + coverage all empty", () => {
    const gaps = emptyGaps() // methods/payloads/chains all []
    const update = HeuristicController.run(base({
      combinationGaps: gaps,
      coverageGaps: [],
    }))
    const cleanup = update.addNodes.find((n: any) => n.objective === "cleanup-final")
    expect(cleanup).toBeDefined()
    expect((cleanup as any).command).toBe("cleanup")
    expect((cleanup as any).priority).toBe(99)
  })

  test("does NOT emit cleanup when any axis still has gaps", () => {
    const gaps = emptyGaps()
    gaps.methods = [{ endpoint: "/x", testedMethods: [], missingMethods: ["POST"] }]
    const update = HeuristicController.run(base({ combinationGaps: gaps }))
    const cleanup = update.addNodes.find((n: any) => n.objective === "cleanup-final")
    expect(cleanup).toBeUndefined()
  })
})

describe("HeuristicController — rationale reflects hybrid count", () => {
  test("rationale carries hybrid=<N> tag", () => {
    const update = HeuristicController.run(base({
      round: 1,
      lastRoundDelta: { newFindings: 3, newHigh: 1, costUsd: 0 },
      findings: [
        { hash: "a", severity: "high", status: "verified", title: "F" },
        { hash: "b", severity: "high", status: "verified", title: "G" },
      ],
    }))
    expect(update.rationale).toMatch(/hybrid=\d+/)
  })
})
