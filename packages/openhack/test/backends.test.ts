// Unit tests for the vendored execution/planning/mirror backends:
//   • MiniSwe.parseTrajectory (mini-swe-agent-1.1 shape + tolerant fallbacks)
//   • MiniSwe.run failing with the exact bootstrap fix when not built
//   • DeepPlan.status + complete() failing with the bootstrap fix when not built
//   • Temporal.config defaults + mirrorRound disabled / not-bootstrapped paths
//
// No venv or network needed — the "missing artifact" paths are the contract.

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { MiniSwe } from "../src/miniswe"
import { DeepPlan } from "../src/deepplan"
import { Temporal } from "../src/temporal"

let tmp: string
let origCwd: string
const savedEnv: Record<string, string | undefined> = {}

function setEnv(key: string, value: string | undefined) {
  if (!(key in savedEnv)) savedEnv[key] = process.env[key]
  if (value === undefined) delete process.env[key]
  else process.env[key] = value
}

beforeEach(() => {
  origCwd = process.cwd()
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "backends-"))
  process.chdir(tmp) // no vendor/ above tmp → backends resolve to missing
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(tmp, { recursive: true, force: true })
  for (const [key, value] of Object.entries(savedEnv)) setEnv(key, value)
})

describe("MiniSwe.parseTrajectory", () => {
  test("parses the mini-swe-agent-1.1 trajectory shape", () => {
    const trajectory = {
      trajectory_format: "mini-swe-agent-1.1",
      info: {
        exit_status: "Submitted",
        submission: "the final patch answer",
        model_stats: { instance_cost: 0.42, api_calls: 7 },
      },
      messages: [
        { role: "user", content: "do the thing" },
        { role: "assistant", content: "intermediate" },
      ],
    }
    const parsed = MiniSwe.parseTrajectory(JSON.stringify(trajectory))
    expect(parsed).not.toBeNull()
    expect(parsed!.output).toBe("the final patch answer")
    expect(parsed!.exitStatus).toBe("Submitted")
    expect(parsed!.cost).toBeCloseTo(0.42)
    expect(parsed!.apiCalls).toBe(7)
  })

  test("falls back to the last assistant message when no submission", () => {
    const trajectory = {
      info: {},
      messages: [{ role: "assistant", content: "partial answer text" }],
    }
    const parsed = MiniSwe.parseTrajectory(JSON.stringify(trajectory))
    expect(parsed!.output).toBe("partial answer text")
  })

  test("non-trajectory input → null", () => {
    expect(MiniSwe.parseTrajectory("not json")).toBeNull()
    expect(MiniSwe.parseTrajectory(JSON.stringify({ messages: "nope" }))).toBeNull()
  })
})

describe("MiniSwe.run", () => {
  test("missing backend fails with the exact bootstrap fix", async () => {
    setEnv("OPENHACK_MINI_BIN", undefined)
    setEnv("PATH", tmp)
    const result = await MiniSwe.run({ prompt: "task" })
    expect(result.ok).toBe(false)
    expect(result.error).toContain("not bootstrapped")
    expect(result.error).toContain("vendor/mini-swe-agent/bootstrap.sh")
  })
})

describe("DeepPlan", () => {
  test("status reports the harness and python resolution", () => {
    const st = DeepPlan.status()
    expect(st.harness).toContain("deepplan.py")
    expect(fs.existsSync(st.harness!)).toBe(true)
  })

  test("missing backend fails with the exact bootstrap fix", async () => {
    setEnv("OPENHACK_DEEPAGENTS_BIN", undefined)
    setEnv("PATH", tmp)
    const result = await DeepPlan.complete({ prompt: "plan this" })
    expect(result.ok).toBe(false)
    expect(result.error).toContain("not bootstrapped")
    expect(result.error).toContain("vendor/deepagents/bootstrap.sh")
  })
})

describe("Temporal", () => {
  test("config defaults", () => {
    const cfg = Temporal.config()
    expect(cfg.enabled).toBe(false)
    expect(cfg.address).toBe("localhost:7233")
    expect(cfg.namespace).toBe("default")
    expect(cfg.taskQueue).toBe("openhack")
  })

  test("mirrorRound with a missing CLI reports the fix (never throws)", async () => {
    setEnv("OPENHACK_TEMPORAL_BIN", undefined)
    setEnv("PATH", tmp)
    const result = await Temporal.mirrorRound({ target: "site1", round: 1 }, { ...Temporal.config(), enabled: true })
    expect(result.ok).toBe(false)
    expect(result.error).toContain("not bootstrapped")
    expect(result.error).toContain("vendor/temporal/bootstrap.sh")
  })

  test("disabled mirror short-circuits with the reason", async () => {
    const result = await Temporal.mirrorRound({ target: "site1", round: 1 }, { ...Temporal.config(), enabled: false })
    expect(result.ok).toBe(false)
    expect(result.error).toContain("disabled")
  })
})
