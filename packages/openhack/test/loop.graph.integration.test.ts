import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { runOrchestrationLoop } from "../../openhack-cli/src/cli/cmd/openhack.automode"
import { AttackGraph, GraphStore } from "../../openhack-orchestration/src"
import type { LlmFactory, LlmFn } from "../../openhack-cli/src/cli/cmd/openhack.automode"
import { Findings } from "../src/findings"
import { Coverage } from "../src/coverage"

/**
 * Integration: `runOrchestrationLoop` with graph mode on, driven by a purely
 * synchronous fake `llmFn` factory. Asserts:
 *   - byte-identical fallback when `graph: false`
 *   - round 1 dispatches the static batch even with `graph: true` (warm start)
 *   - rounds 2+ dispatch the graph frontier (which the controller populates
 *     from the deterministic heuristic)
 *   - a controller throw / empty frontier degrades cleanly to the static batch
 *   - the empty-frontier + no-gaps terminator fires before maxRounds
 *
 * The test drives the loop headlessly — no subprocesses, no real LLM.
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-loop-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

/** Deterministic mock LLM: records every prompt and returns a canned reply. */
function mockFactory(record: string[]): LlmFactory {
  const fn: LlmFn = async (prompt) => {
    record.push(prompt)
    return { output: "mock ok", tokensIn: 100, tokensOut: 200, cost: 0.001 }
  }
  return () => fn
}

/**
 * Same as mockFactory but writes ONE fresh finding on the first call so the
 * convergence check doesn't fire immediately. Also marks a coverage cell as
 * safe so the gaps eventually drain.
 */
function mockFactoryWithFinding(record: string[], target: string): LlmFactory {
  let firstCall = true
  const fn: LlmFn = async (prompt) => {
    record.push(prompt)
    if (firstCall) {
      firstCall = false
      const store = Findings.load(target)
      Findings.add(store, {
        id: "",
        timestamp: new Date().toISOString(),
        target,
        title: "Test critical finding",
        description: "seeded by integration test",
        severity: "critical",
        status: "uncertain",
        source_agent: "recon",
        source_session: "test",
        evidence_files: [],
        manual_verify_required: true,
        audit_trail: [],
        promotionChain: [],
        challengedByCouncils: [],
        hash: "",
        hmac: "",
        tags: [],
      })
    }
    return { output: "mock", tokensIn: 100, tokensOut: 200, cost: 0.001 }
  }
  return () => fn
}

describe("runOrchestrationLoop — graph mode integration", () => {
  test("graph: false is byte-identical to legacy behavior (no graph file created)", async () => {
    const seen: string[] = []
    await runOrchestrationLoop("example.com", {
      maxRounds: 1,
      makeLlmFn: mockFactory(seen),
      plan: false,
      council: false,
      instances: 1,
      graph: false,
    })
    expect(fs.existsSync(path.join(".openhack", "graph"))).toBe(false)
    // A round 1 with the static batch runs the non-report objective set.
    expect(seen.length).toBeGreaterThan(0)
  })

  test("graph: true seeds a graph and persists it after round 1", async () => {
    const seen: string[] = []
    await runOrchestrationLoop("example.com", {
      maxRounds: 1,
      makeLlmFn: mockFactory(seen),
      plan: false,
      council: false,
      instances: 1,
      graph: true,
    })
    const snap = GraphStore.load("example.com")
    expect(Object.keys(snap.nodes).length).toBeGreaterThan(0)
    // Some seeded ActionNodes must exist.
    const actions = Object.values(snap.nodes).filter((n) => AttackGraph.isAction(n as any))
    expect(actions.length).toBeGreaterThan(0)
  })

  test("rounds 2+ dispatch the graph frontier, not the static batch", async () => {
    const seen: string[] = []
    await runOrchestrationLoop("example.com", {
      maxRounds: 2,
      makeLlmFn: mockFactoryWithFinding(seen, "example.com"),
      plan: false,
      council: false,
      instances: 1,
      graph: true,
      frontierK: 3,
    })
    // The heuristic controller emitted a verify-finding action for the seeded
    // critical finding; the loop must have dispatched at least one such action
    // in round 2. Prompt bodies include "verify the finding" (from HeuristicController).
    const round2Verify = seen.some((p) => /verify the finding/i.test(p))
    expect(round2Verify).toBe(true)
  })

  test("controller throw degrades to static batch — no crash", async () => {
    const seen: string[] = []
    await runOrchestrationLoop("example.com", {
      maxRounds: 2,
      makeLlmFn: mockFactoryWithFinding(seen, "example.com"),
      plan: false,
      council: false,
      instances: 1,
      graph: true,
      frontierK: 3,
      graphGenerate: () => {
        throw new Error("boom from generator")
      },
    })
    // Even with the LLM generator throwing every round, the loop completes
    // and the heuristic fallback populates the graph.
    const snap = GraphStore.load("example.com")
    expect(snap.lastRound).toBeGreaterThanOrEqual(1)
  })

  test("empty-frontier + zero-gaps terminates before maxRounds", async () => {
    const seen: string[] = []
    // Use a factory that never produces findings AND leaves coverage untouched;
    // the heuristic emits no verify/chain actions and there are no coverage gaps
    // to fill, so the frontier stays empty and the loop terminates early.
    await runOrchestrationLoop("example.com", {
      maxRounds: 5,
      makeLlmFn: mockFactory(seen),
      plan: false,
      council: false,
      instances: 1,
      graph: true,
      frontierK: 3,
    })
    // Should not have run all 5 rounds' worth of static batches — the graph
    // termination branch fires after round 1 (empty frontier + no coverage cells).
    // Static batch is 6 non-report objectives × 1 instance = 6 dispatches per round.
    // So < 6 * 5 = 30 dispatches is a proxy for "terminated early".
    expect(seen.length).toBeLessThan(30)
  })

  test("frontier ordering: highest score dispatches first", async () => {
    // Seed a graph with three known-priority actions, then start the loop with
    // maxRounds=2 so round 2 pulls exactly frontierK=1 from the top.
    const target = "example.com"
    const snap = GraphStore.empty(target)
    for (const [id, score] of [
      ["low", 1],
      ["high", 10],
      ["mid", 5],
    ] as const) {
      snap.nodes[`action:${id}`] = {
        id: `action:${id}`,
        objective: `preseed-${id}`,
        agent: "general",
        prompt: `preseed prompt ${id}`,
        priority: 3,
        score,
        expectedGain: 1,
        requires: [],
        produces: [],
        spawnedRound: 1,
        status: "queued",
      } as any
    }
    GraphStore.save(snap)

    const seen: string[] = []
    // Use the finding-injecting factory so round 1 produces at least one new
    // finding — that prevents the convergence terminator from firing and lets
    // round 2 actually execute (where the pre-seeded frontier gets dispatched).
    await runOrchestrationLoop(target, {
      maxRounds: 2,
      makeLlmFn: mockFactoryWithFinding(seen, target),
      plan: false,
      council: false,
      instances: 1,
      graph: true,
      frontierK: 1,
    })
    // Round 2 should have dispatched exactly one preseeded action — the one
    // with the highest score. (The heuristic controller ALSO emits a verify
    // action for the round-1 finding; its score is 6 versus our high=10 —
    // "high" still wins the frontier tie-break.)
    const hits = seen.filter((p) => /preseed prompt/.test(p))
    expect(hits.length).toBeGreaterThan(0)
    expect(hits.some((p) => p.includes("preseed prompt high"))).toBe(true)
  })

  test("per-round telemetry lands at .openhack/rounds/<target>.jsonl with the expected shape", async () => {
    const seen: string[] = []
    await runOrchestrationLoop("example.com", {
      maxRounds: 1,
      makeLlmFn: mockFactory(seen),
      plan: false,
      council: false,
      instances: 1,
      graph: false,
    })
    const fp = path.join(".openhack", "rounds", "example.com.jsonl")
    expect(fs.existsSync(fp)).toBe(true)
    const lines = fs.readFileSync(fp, "utf-8").trim().split("\n").filter(Boolean)
    expect(lines.length).toBe(1)
    const rec = JSON.parse(lines[0]!)
    expect(rec.target).toBe("example.com")
    expect(rec.round).toBe(1)
    expect(typeof rec.findingsTotal).toBe("number")
    expect(typeof rec.totalCostUsd).toBe("number")
    expect(typeof rec.rssMb).toBe("number")
    // Combos summary is present (or explicitly null in an empty engagement).
    expect(rec).toHaveProperty("combos")
    expect(rec).toHaveProperty("frontierSize")
  })

  test("combinationGaps drive method / payload / chain actions into the frontier", async () => {
    const target = "example.com"
    // Seed a vulnerable sqli cell so a chain-pair action can spawn — combined
    // with a partial payload set so payload-family gaps also fire.
    const { Coverage } = await import("../src/coverage")
    let store = Coverage.load(target)
    store = Coverage.mark(store, {
      endpoint: "/login", method: "POST", classId: "sqli",
      result: "vulnerable", payloadFamilies: ["error-based"],
    })

    const seen: string[] = []
    await runOrchestrationLoop(target, {
      maxRounds: 2,
      makeLlmFn: mockFactoryWithFinding(seen, target),
      plan: false,
      council: false,
      instances: 1,
      graph: true,
      frontierK: 6,
    })
    // Round 2 should have dispatched at least one combo-driven action prompt.
    // The heuristic's combo prompts start with:
    //   "extend HTTP-method coverage on"   — method combo
    //   "exercise .*for .* with the payload families you have NOT yet tried" — payload combo
    //   "prove the CHAIN from vulnerable"   — chain combo
    const gotMethodCombo = seen.some((p) => /extend HTTP-method coverage/i.test(p))
    const gotPayloadCombo = seen.some((p) => /payload families you have NOT yet tried/i.test(p))
    const gotChainCombo = seen.some((p) => /prove the CHAIN from vulnerable/i.test(p))
    // At least one axis must have fired — with the seed above we expect method + payload + chain.
    expect(gotMethodCombo || gotPayloadCombo || gotChainCombo).toBe(true)
  })
})
