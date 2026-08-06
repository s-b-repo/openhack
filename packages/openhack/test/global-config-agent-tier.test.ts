import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { GlobalConfig } from "../src/global-config"

/**
 * Per-agent tier resolution. Guards:
 *   • the doctrine defaults (recon/osint → cheap, exploit → main, defense/council/triage → fast, cleanup → draft)
 *   • .openhack/models.json override under `agent_tiers`
 *   • `openhack model --set X` (custom) takes precedence over both
 *   • unknown agent → main
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-agent-tier-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
  GlobalConfig.reset() // module-level cache -> defaults
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
  GlobalConfig.reset()
})

describe("GlobalConfig.resolveForAgent — doctrine defaults", () => {
  test("recon and osint map to cheap tier", () => {
    expect(GlobalConfig.resolveForAgent("recon")).toBe(GlobalConfig.cheap())
    expect(GlobalConfig.resolveForAgent("osint")).toBe(GlobalConfig.cheap())
  })

  test("exploit / post-exploit / c2 / report / plan / planner map to main tier", () => {
    for (const a of ["exploit", "post-exploit", "c2", "report", "plan", "planner"]) {
      expect(GlobalConfig.resolveForAgent(a)).toBe(GlobalConfig.main())
    }
  })

  test("defense / defense-review / council / triage / general map to fast tier", () => {
    for (const a of ["defense", "defense-review", "council", "triage", "general"]) {
      expect(GlobalConfig.resolveForAgent(a)).toBe(GlobalConfig.fast())
    }
  })

  test("cleanup maps to draft tier", () => {
    expect(GlobalConfig.resolveForAgent("cleanup")).toBe(GlobalConfig.draft())
  })

  test("unknown agent falls back to main", () => {
    expect(GlobalConfig.resolveForAgent("some-new-agent")).toBe(GlobalConfig.main())
    expect(GlobalConfig.resolveForAgent(null)).toBe(GlobalConfig.main())
    expect(GlobalConfig.resolveForAgent(undefined)).toBe(GlobalConfig.main())
  })
})

describe("GlobalConfig.resolveForAgent — overrides", () => {
  test(".openhack/models.json agent_tiers override wins over the doctrine default", () => {
    GlobalConfig.set({ agent_tiers: { recon: "main" } })
    // recon default is 'cheap'; override says 'main'.
    expect(GlobalConfig.resolveForAgent("recon")).toBe(GlobalConfig.main())
  })

  test("`openhack model --set X` (custom) overrides both agent_tiers and defaults", () => {
    GlobalConfig.set({ agent_tiers: { recon: "cheap" } })
    GlobalConfig.useCustomModel("openai/gpt-4o")
    expect(GlobalConfig.resolveForAgent("recon")).toBe("openai/gpt-4o")
    expect(GlobalConfig.resolveForAgent("exploit")).toBe("openai/gpt-4o")
    expect(GlobalConfig.resolveForAgent("no-such-agent")).toBe("openai/gpt-4o")
  })

  test("clearing custom re-enables tier resolution", () => {
    GlobalConfig.useCustomModel("openai/gpt-4o")
    expect(GlobalConfig.resolveForAgent("recon")).toBe("openai/gpt-4o")
    GlobalConfig.clearCustom()
    expect(GlobalConfig.resolveForAgent("recon")).toBe(GlobalConfig.cheap())
  })
})

describe("GlobalConfig.tierModel", () => {
  test("returns the model id for each tier", () => {
    expect(GlobalConfig.tierModel("main")).toBe(GlobalConfig.main())
    expect(GlobalConfig.tierModel("fast")).toBe(GlobalConfig.fast())
    expect(GlobalConfig.tierModel("cheap")).toBe(GlobalConfig.cheap())
    expect(GlobalConfig.tierModel("draft")).toBe(GlobalConfig.draft())
  })
})
