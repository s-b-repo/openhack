import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Automode } from "../src/automode"
import { runOrchestrationLoop } from "../../opencode/src/cli/cmd/openhack.automode"
import type { LlmFactory, LlmFn } from "../../opencode/src/cli/cmd/openhack.automode"
import { Findings } from "../src/findings"

// Regression coverage for the two correctness fixes:
//   B1 — a resolved-but-failed subprocess run must be recorded as FAILURE, not
//        success (the golecloud.co.za "52/52 successful, 0 findings" bug).
//   B2 — a loop that discovered nothing terminates as `no_discovery`, never as
//        a clean `completed`.

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-automode-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

function session() {
  return Automode.createSession(
    [{ id: "t1", prompt: "probe the target", agent: "recon" }],
    "example.com",
    ".openhack/automode-results/example.com",
  )
}
const task = { id: "t1", prompt: "probe the target", agent: "recon" }

describe("Automode.executeTask — failure is not success (B1)", () => {
  test("ok:false is recorded as a failed task", async () => {
    const fn = async () => ({ output: "[run exited null] boom", tokensIn: 0, tokensOut: 0, cost: 0, ok: false, error: "run exited null" })
    const r = await Automode.executeTask(task, session(), fn)
    expect(r.success).toBe(false)
    expect(r.error).toBe("run exited null")
  })

  test("error-shaped output with no ok flag still fails (fallback sniff)", async () => {
    const fn = async () => ({ output: "[run exited null] stderr…", tokensIn: 0, tokensOut: 0, cost: 0 })
    const r = await Automode.executeTask(task, session(), fn)
    expect(r.success).toBe(false)
  })

  test("a clean run with output is a success", async () => {
    const fn = async () => ({ output: "found an exposed admin panel", tokensIn: 10, tokensOut: 20, cost: 0.01, ok: true })
    const r = await Automode.executeTask(task, session(), fn)
    expect(r.success).toBe(true)
    expect(r.error).toBeUndefined()
  })

  test("summary counts a failed run as a failure, not 1/1 success", async () => {
    const s = session()
    const fn = async () => ({ output: "[run exited null]", tokensIn: 0, tokensOut: 0, cost: 0, ok: false, error: "run exited null" })
    await Automode.executeTask(task, s, fn)
    expect(s.results.filter((r) => r.success).length).toBe(0)
    expect(s.results.filter((r) => !r.success).length).toBe(1)
  })
})

function factory(record: string[]): LlmFactory {
  const fn: LlmFn = async (prompt) => {
    record.push(prompt)
    return { output: "mock ok", tokensIn: 100, tokensOut: 200, cost: 0.001, ok: true }
  }
  return () => fn
}

function factoryWithFinding(record: string[], target: string): LlmFactory {
  let first = true
  const fn: LlmFn = async (prompt) => {
    record.push(prompt)
    if (first) {
      first = false
      const store = Findings.load(target)
      Findings.add(store, {
        id: "", timestamp: new Date().toISOString(), target,
        title: "Exposed admin panel", description: "seeded by test", severity: "high", status: "uncertain",
        source_agent: "recon", source_session: "test", evidence_files: [], manual_verify_required: true,
        audit_trail: [], promotionChain: [], challengedByCouncils: [], hash: "", hmac: "", tags: [],
      })
    }
    return { output: "mock", tokensIn: 100, tokensOut: 200, cost: 0.001, ok: true }
  }
  return () => fn
}

describe("runOrchestrationLoop — discovery-aware status (B2)", () => {
  test("a run that discovered nothing is no_discovery, not completed", async () => {
    const seen: string[] = []
    const s = await runOrchestrationLoop("nodisc.example", {
      maxRounds: 1, makeLlmFn: factory(seen), plan: false, council: false, instances: 1, graph: false,
    })
    expect(s.status).toBe("no_discovery")
  })

  test("a run that found something completes cleanly", async () => {
    const seen: string[] = []
    const s = await runOrchestrationLoop("disc.example", {
      maxRounds: 1, makeLlmFn: factoryWithFinding(seen, "disc.example"), plan: false, council: false, instances: 1, graph: false,
    })
    expect(s.status).toBe("completed")
  })
})
