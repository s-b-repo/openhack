import { describe, expect, test } from "bun:test"
import { HeuristicController, AttackGraph, GraphStore } from "../../openhack-orchestration/src"
import type { ControllerInput, FindingLike, CoverageGap } from "../../openhack-orchestration/src/types"

/**
 * The heuristic controller must be:
 *   - deterministic  (same input → same output, modulo the random ActionNode ids)
 *   - crash-safe on empty state
 *   - respectful of its own action budget (≤ 12 addActions)
 *   - ordering-stable: verify > chain > gap, per the doctrine.
 */

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

function gap(endpoint: string, method: string, className: string, classId?: string): CoverageGap {
  return { endpoint, method, className, classId: classId ?? className.toLowerCase().replace(/\s+/g, "-") }
}

describe("HeuristicController.run — empty state", () => {
  test("empty findings + empty gaps yields empty addNodes and never throws", () => {
    const update = HeuristicController.run(inputWith())
    expect(update.addNodes.length).toBe(0)
    expect(update.dispatch.length).toBe(0)
    expect(update.rationale).toMatch(/heuristic/)
  })
})

describe("HeuristicController.run — verify path", () => {
  test("emits a verify-finding action per unverified high/critical finding, capped at 6", () => {
    const findings = Array.from({ length: 10 }, (_, i) => finding(`hash${i}`, "critical", "uncertain", `f${i}`))
    const update = HeuristicController.run(inputWith({ findings }))
    // Every emitted action targets a finding.
    const verifyActions = update.addNodes.filter((n: any) => n.objective?.startsWith("verify-finding-"))
    expect(verifyActions.length).toBe(6) // capped
    for (const a of verifyActions as any[]) {
      expect(a.agent).toBe("general")
      expect(a.priority).toBe(2)
      expect(a.status).toBe("queued")
      // 'requires' points back at the corresponding finding node.
      expect(a.requires[0]).toMatch(/^finding:/)
    }
  })

  test("verified & false-positive findings are NOT scheduled for verify", () => {
    const findings: FindingLike[] = [
      finding("h1", "critical", "verified"),
      finding("h2", "high", "false_positive"),
      finding("h3", "high", "uncertain"),
    ]
    const update = HeuristicController.run(inputWith({ findings }))
    const verifies = update.addNodes.filter((n: any) => n.objective?.startsWith("verify-finding-"))
    expect(verifies.length).toBe(1)
    expect((verifies[0] as any).requires[0]).toBe("finding:h3")
  })
})

describe("HeuristicController.run — chain path", () => {
  test("verified critical findings get chain actions (post-exploit, priority 3)", () => {
    const findings = [finding("h1", "critical", "verified", "auth-bypass"), finding("h2", "critical", "verified", "rce")]
    const update = HeuristicController.run(inputWith({ findings }))
    const chains = update.addNodes.filter((n: any) => n.objective?.startsWith("chain-finding-"))
    expect(chains.length).toBe(2)
    for (const c of chains as any[]) {
      expect(c.agent).toBe("post-exploit")
      expect(c.priority).toBe(3)
    }
  })

  test("verified high (not critical) findings do NOT get chain actions", () => {
    const update = HeuristicController.run(inputWith({ findings: [finding("h1", "high", "verified")] }))
    const chains = update.addNodes.filter((n: any) => n.objective?.startsWith("chain-finding-"))
    expect(chains.length).toBe(0)
  })
})

describe("HeuristicController.run — gap path", () => {
  test("gap actions routed by class: recon vs exploit vs post-exploit", () => {
    const gaps: CoverageGap[] = [
      gap("/", "GET", "Port Enumeration", "port-enum"),          // recon
      gap("/login", "POST", "Auth Bypass", "auth-bypass"),        // exploit
      gap("/api", "GET", "Info Leak", "info-leak"),               // post-exploit
      gap("/upload", "POST", "SSRF", "ssrf"),                     // exploit
    ]
    const update = HeuristicController.run(inputWith({ coverageGaps: gaps }))
    const agents = update.addNodes.map((n: any) => n.agent)
    expect(agents).toContain("recon")
    expect(agents).toContain("exploit")
    expect(agents).toContain("post-exploit")
  })

  test("gap actions carry classId + endpointKey + a requires: edge into the endpoint asset", () => {
    const gaps = [gap("/x", "POST", "SQL Injection", "sqli")]
    const update = HeuristicController.run(inputWith({ coverageGaps: gaps }))
    const gapAction: any = update.addNodes.find((n: any) => n.objective?.startsWith("test-gap-"))
    expect(gapAction).toBeDefined()
    expect(gapAction.classId).toBe("sqli")
    expect(gapAction.endpointKey).toBe("POST /x")
    const req = update.addEdges.find((e) => e.kind === "requires" && e.from === gapAction.id)
    expect(req).toBeDefined()
    expect(req!.to).toBe(AttackGraph.endpointId("/x", "POST"))
  })
})

describe("HeuristicController.run — budget cap", () => {
  test("total addActions never exceed MAX_ACTIONS_PER_ROUND (12)", () => {
    const findings: FindingLike[] = Array.from({ length: 20 }, (_, i) => finding(`h${i}`, "critical", "uncertain"))
    const gaps: CoverageGap[] = Array.from({ length: 40 }, (_, i) => gap(`/e${i}`, "GET", "SQL Injection", "sqli"))
    const update = HeuristicController.run(inputWith({ findings, coverageGaps: gaps }))
    expect(update.addNodes.length).toBeLessThanOrEqual(12)
  })
})
