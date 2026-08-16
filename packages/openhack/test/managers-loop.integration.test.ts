// Integration: the hierarchical manager tier + blackboard + o5 driven through
// `runOrchestrationLoop` with a deterministic fake LLM (no subprocess, no real cost).
//
// Asserts:
//   • managers select the objectives their plan dispatches, and honor `skip`
//     (recon skips osint-passive → the osint agent never runs)
//   • a directive posted by one manager reaches a peer manager on the NEXT round
//     (exploitation → recon; recon reads it round 2)
//   • o5 records (role×model×variant) outcomes and enforces a choice (overwatch.json
//     accumulates candidates; agent-variants.json is written)

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { runOrchestrationLoop } from "../../openhack-cli/src/cli/cmd/openhack.automode"
import type { LlmFactory, LlmFn, LlmResult } from "../../openhack-cli/src/cli/cmd/openhack.automode"
import { Findings } from "../src/findings"
import { Overwatch } from "../src/overwatch"
import { GlobalConfig } from "../src/global-config"
import { ConfigStore } from "../src/config-store"

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "managers-loop-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
  GlobalConfig.reset()
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
  GlobalConfig.reset()
})

const TARGET = "example.com"

function writeConfig(overrides: Record<string, unknown> = {}) {
  const cfg = {
    managers: {
      enabled: true,
      tier: "cheap",
      phases: {
        recon: { objectives: ["osint-passive", "recon-depth"] },
        enumeration: { objectives: ["combination-gaps"] },
        exploitation: { objectives: ["internal-access", "chaining-planning", "defense-review"] },
        "post-exploitation": { objectives: ["pii-exposure", "pivoting", "privesc"] },
        c2: { objectives: ["c2-handoff", "cleanup-artifacts"] },
      },
    },
    blackboard: { enabled: true, retain_rounds: 4, mcp: false },
    o5: {
      enabled: true,
      review_every: 1,
      explore_epsilon: 0.5,
      min_samples: 1,
      seed_from_models_dev: false,
      candidates: {
        recon: { models: ["deepseek/deepseek-v4", "anthropic/claude-haiku-4-5"], variants: ["default", "exhaustive"] },
        exploit: { models: ["anthropic/claude-sonnet-4", "anthropic/claude-haiku-4-5"], variants: ["default", "chain-forward"] },
      },
    },
    // Keep the loop from converging early so several rounds run.
    round_budget: { adaptive: false },
    ...overrides,
  }
  fs.writeFileSync(path.join(".openhack", "openhack.jsonc"), JSON.stringify(cfg, null, 2))
  ConfigStore.invalidateCache()
}

interface Rec { agent?: string; prompt: string }

/** Fake factory: canned manager plans keyed by phase; workers seed a unique finding/round. */
function factory(record: Rec[]): LlmFactory {
  let findingSeq = 0
  return (agentOrOpts) => {
    const agent = typeof agentOrOpts === "string" ? agentOrOpts : agentOrOpts?.agent
    const fn: LlmFn = async (prompt): Promise<LlmResult> => {
      record.push({ agent, prompt })
      if (agent === "phase-manager") {
        const phase = prompt.match(/You are the (\S+) phase-manager/)?.[1]
        let plan: any = {}
        if (phase === "recon") {
          plan = { phase, dispatch: [{ objective: "recon-depth", note: "vhosts" }], skip: ["osint-passive"] }
        } else if (phase === "exploitation") {
          plan = {
            phase,
            dispatch: [{ objective: "internal-access" }],
            messages: [{ to: "recon", kind: "request", text: "need deeper vhost enum around /admin", refs: [] }],
          }
        } // other phases: {} → empty → static fallback
        return { output: JSON.stringify(plan), tokensIn: 10, tokensOut: 10, cost: 0, latencyMs: 5 }
      }
      // Worker: seed a fresh finding each call so rounds keep producing deltas.
      findingSeq++
      const store = Findings.load(TARGET)
      Findings.add(store, {
        id: "", timestamp: new Date().toISOString(), target: TARGET,
        title: `finding ${findingSeq} from ${agent}`, description: "seeded",
        severity: "high", status: "uncertain", source_agent: String(agent ?? "general"),
        source_session: "test", evidence_files: [], manual_verify_required: true,
        audit_trail: [], promotionChain: [], challengedByCouncils: [], hash: "", hmac: "", tags: [],
      })
      return { output: "mock work", tokensIn: 100, tokensOut: 200, cost: 0.001, latencyMs: 1000 }
    }
    return fn
  }
}

describe("runOrchestrationLoop — manager hierarchy + blackboard + o5", () => {
  test("managers select their dispatched objectives and honor skip", async () => {
    writeConfig()
    const rec: Rec[] = []
    await runOrchestrationLoop(TARGET, {
      maxRounds: 1, makeLlmFn: factory(rec), plan: false, council: false, instances: 1, graph: false,
    })
    const workerAgents = rec.filter((r) => r.agent !== "phase-manager").map((r) => r.agent)
    // recon manager dispatched recon-depth (→recon) and skipped osint-passive (→osint).
    expect(workerAgents).toContain("recon")
    expect(workerAgents).not.toContain("osint")
    // exploitation manager dispatched internal-access (→exploit).
    expect(workerAgents).toContain("exploit")
  })

  test("a manager directive reaches a peer manager on the next round", async () => {
    writeConfig()
    const rec: Rec[] = []
    await runOrchestrationLoop(TARGET, {
      maxRounds: 2, makeLlmFn: factory(rec), plan: false, council: false, instances: 1, graph: false,
    })
    // The recon phase-manager is prompted once per round; the 2nd one is round 2 and
    // must carry the request exploitation posted to recon in round 1.
    const reconPrompts = rec.filter((r) => r.agent === "phase-manager" && /the recon phase-manager/.test(r.prompt))
    expect(reconPrompts.length).toBeGreaterThanOrEqual(2)
    expect(reconPrompts[1]!.prompt).toContain("need deeper vhost enum around /admin")
  })

  test("o5 records candidate stats and enforces a choice", async () => {
    writeConfig()
    const rec: Rec[] = []
    await runOrchestrationLoop(TARGET, {
      maxRounds: 3, makeLlmFn: factory(rec), plan: false, council: false, instances: 1, graph: false,
    })
    expect(fs.existsSync(path.join(".openhack", "overwatch.json"))).toBe(true)
    const store = Overwatch.load()
    // recon + exploit both have candidate grids and both ran, so both accrue stats.
    const reconKeys = Object.keys(store.candidates).filter((k) => k.startsWith("recon::"))
    const exploitKeys = Object.keys(store.candidates).filter((k) => k.startsWith("exploit::"))
    expect(reconKeys.length).toBeGreaterThan(0)
    expect(exploitKeys.length).toBeGreaterThan(0)
    // review_every=1 → o5 enforced winners, writing chosen + the variant store.
    expect(Object.keys(store.chosen).length).toBeGreaterThan(0)
    expect(fs.existsSync(path.join(".openhack", "agent-variants.json"))).toBe(true)
  })
})
