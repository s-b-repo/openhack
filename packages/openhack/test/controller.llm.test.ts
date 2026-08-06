import { describe, expect, test } from "bun:test"
import { LlmController, GraphStore, HeuristicController } from "../../openhack-orchestration/src"
import type { ControllerInput } from "../../openhack-orchestration/src/types"

/**
 * LLM controller with a stubbed `generate`. Exercises:
 *  - happy path with a well-formed model response
 *  - timeout → falls back to HeuristicController
 *  - throw → falls back to HeuristicController
 *  - invalid / partial shape → filtered but never crashes
 *  - `generate` omitted → falls back to HeuristicController transparently
 *  - convert() sanitizes numbers and truncates the rationale
 *  - buildUser() includes the current frontier ids so the model won't re-emit
 */

function inputWith(overrides: Partial<ControllerInput> = {}): ControllerInput {
  return {
    target: "example.com",
    round: 3,
    snapshot: GraphStore.empty("example.com"),
    findings: [],
    coverageSummary: null,
    coverageGaps: [],
    lastRoundDelta: { newFindings: 0, newHigh: 0, costUsd: 0 },
    budgetRemainingUsd: 5,
    currentFrontierIds: [],
    combinationGaps: null,
    ...overrides,
  }
}

describe("LlmController.make", () => {
  test("happy path — validated addActions become queued ActionNodes with requires edges", async () => {
    const ctrl = LlmController.make({
      generate: async () => ({
        addActions: [
          {
            objective: "verify-x",
            agent: "general",
            prompt: "Verify finding X on example.com — reproduce PoC only.",
            priority: 2,
            score: 7,
            requires: ["finding:aaa"],
          },
        ],
        rationale: "verify newly-emitted x",
      }),
    })
    const update = await ctrl(inputWith())
    expect(update.addNodes.length).toBe(1)
    const a: any = update.addNodes[0]
    expect(a.status).toBe("queued")
    expect(a.spawnedRound).toBe(3)
    expect(a.priority).toBe(2)
    expect(a.score).toBe(7)
    // Auto-materializes the requires: edge.
    const req = update.addEdges.find((e) => e.kind === "requires")
    expect(req).toBeDefined()
    expect(req!.to).toBe("finding:aaa")
  })

  test("timeout → HeuristicController fallback (no crash, sensible rationale)", async () => {
    let called = 0
    const ctrl = LlmController.make({
      generate: () => {
        called++
        return new Promise((resolve) => setTimeout(() => resolve(null), 200))
      },
      timeoutMs: 1, // race resolves with null almost immediately
    })
    const update = await ctrl(inputWith())
    expect(called).toBe(1)
    expect(update.rationale).toMatch(/heuristic/)
  })

  test("throw in generate → HeuristicController fallback", async () => {
    const ctrl = LlmController.make({
      generate: async () => {
        throw new Error("boom")
      },
    })
    const update = await ctrl(inputWith())
    expect(update.rationale).toMatch(/heuristic/)
  })

  test("no generator wired up → HeuristicController result directly", async () => {
    const ctrl = LlmController.make({})
    const update = await ctrl(inputWith())
    expect(update.rationale).toMatch(/heuristic/)
  })

  test("invalid partial addActions are dropped, not thrown", async () => {
    const ctrl = LlmController.make({
      generate: async () => ({
        addActions: [
          { objective: "no-prompt", agent: "exploit", prompt: "" }, // empty prompt → dropped
          null as any,                                                 // null → dropped
          { objective: "ok", agent: "exploit", prompt: "Do a thing" }, // kept
        ],
        rationale: "mixed shape",
      }),
    })
    const update = await ctrl(inputWith())
    expect(update.addNodes.length).toBe(1)
    expect((update.addNodes[0] as any).objective).toBe("ok")
  })
})

describe("LlmController.convert", () => {
  test("clamps out-of-range numbers", () => {
    const update = LlmController.convert(
      {
        addActions: [
          { objective: "x", agent: "recon", prompt: "p", priority: 99, score: -100, expectedGain: 9999 },
        ],
        rationale: "clamp me",
      },
      inputWith(),
    )
    const a: any = update.addNodes[0]
    expect(a.priority).toBeLessThanOrEqual(5)
    expect(a.priority).toBeGreaterThanOrEqual(1)
    expect(a.score).toBeGreaterThanOrEqual(0)
    expect(a.expectedGain).toBeLessThanOrEqual(10)
  })

  test("truncates rationale at 240 chars", () => {
    const long = "x".repeat(500)
    const update = LlmController.convert({ addActions: [], rationale: long }, inputWith())
    expect(update.rationale.length).toBeLessThanOrEqual(240)
  })

  test("dedupes actions with identical caller-supplied ids", () => {
    const update = LlmController.convert(
      {
        addActions: [
          { id: "action:same", objective: "a", agent: "recon", prompt: "p1" },
          { id: "action:same", objective: "b", agent: "recon", prompt: "p2" },
        ],
      },
      inputWith(),
    )
    expect(update.addNodes.length).toBe(1)
  })
})

describe("LlmController.buildUser", () => {
  test("mentions current frontier ids so the model doesn't re-emit them", () => {
    const user = LlmController.buildUser(inputWith({ currentFrontierIds: ["action:aa", "action:bb"] }))
    expect(user).toContain("action:aa")
    expect(user).toContain("action:bb")
    expect(user).toContain("do NOT re-emit")
  })

  test("labels rounds and target unambiguously", () => {
    const user = LlmController.buildUser(inputWith({ round: 7 }))
    expect(user).toMatch(/Round 7/)
    expect(user).toContain("example.com")
  })
})

describe("HeuristicController exposed as fallback identity", () => {
  test("HeuristicController.run(input) is what the LLM controller falls back to", async () => {
    const findings = [
      { hash: "abc123def", severity: "critical" as const, status: "uncertain" as const, title: "verify me" },
    ]
    const via = HeuristicController.run(inputWith({ findings }))
    const ctrl = LlmController.make({})
    const update = await ctrl(inputWith({ findings }))
    // Same shape of actions (ids differ — they're random).
    expect(update.addNodes.length).toBe(via.addNodes.length)
    expect((update.addNodes[0] as any).objective).toBe((via.addNodes[0] as any).objective)
  })
})
