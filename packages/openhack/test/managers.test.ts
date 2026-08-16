// Phase-manager tier tests (pure logic).
//
//   • parsePlan drops hallucinated / out-of-whitelist objectives + messages
//   • parsePlan tolerates raw string (fenced JSON) and malformed input → empty plan
//   • toTasks maps to the correct Orchestrators + honors note/skip/instances
//   • config falls back to DEFAULT_PHASES; overrides via managers.phases.*

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Managers } from "../src/managers"
import { ConfigStore } from "../src/config-store"

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "managers-test-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
  ConfigStore.invalidateCache()
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

const RECON_ALLOWED = Managers.DEFAULT_PHASES.recon // ["osint-passive","recon-depth"]

describe("Managers.parsePlan", () => {
  test("drops objectives not in the phase whitelist", () => {
    const raw = {
      phase: "recon",
      dispatch: [
        { objective: "recon-depth", priority: 1 },
        { objective: "internal-access" }, // exploitation's objective — must be dropped
        { objective: "rm-rf-everything" }, // hallucinated — must be dropped
      ],
    }
    const plan = Managers.parsePlan("recon", raw, RECON_ALLOWED)
    expect(plan.dispatch.map((d) => d.objective)).toEqual(["recon-depth"])
  })

  test("keeps only valid messages (known phase/kind + non-empty text)", () => {
    const raw = {
      dispatch: [],
      messages: [
        { to: "exploitation", kind: "directive", text: "found /admin", refs: ["FIND-1"] },
        { to: "nowhere", kind: "directive", text: "bad target" },
        { to: "all", kind: "banana", text: "bad kind" },
        { to: "c2", kind: "hint", text: "" },
      ],
    }
    const plan = Managers.parsePlan("recon", raw, RECON_ALLOWED)
    expect(plan.messages.length).toBe(1)
    expect(plan.messages[0]!.to).toBe("exploitation")
    expect(plan.messages[0]!.refs).toEqual(["FIND-1"])
  })

  test("parses a raw fenced-JSON string", () => {
    const raw = '```json\n{"phase":"recon","dispatch":[{"objective":"osint-passive","note":"crt.sh first"}]}\n```'
    const plan = Managers.parsePlan("recon", raw, RECON_ALLOWED)
    expect(plan.dispatch[0]!.objective).toBe("osint-passive")
    expect(plan.dispatch[0]!.note).toBe("crt.sh first")
  })

  test("malformed input → empty plan", () => {
    expect(Managers.parsePlan("recon", "not json at all", RECON_ALLOWED).dispatch).toEqual([])
    expect(Managers.parsePlan("recon", null, RECON_ALLOWED).dispatch).toEqual([])
    expect(Managers.parsePlan("recon", 42, RECON_ALLOWED).messages).toEqual([])
  })

  test("clamps instances to [1,6]", () => {
    const raw = { dispatch: [{ objective: "recon-depth", instances: 99 }] }
    expect(Managers.parsePlan("recon", raw, RECON_ALLOWED).dispatch[0]!.instances).toBe(6)
  })
})

describe("Managers.toTasks", () => {
  test("maps dispatch ids to Orchestrator TaskSpecs with note + priority override", () => {
    const plan = Managers.parsePlan(
      "recon",
      { dispatch: [{ objective: "recon-depth", priority: 2, note: "focus vhosts", instances: 2 }] },
      RECON_ALLOWED,
    )
    const tasks = Managers.toTasks(plan, "example.com")
    expect(tasks.length).toBe(1)
    expect(tasks[0]!.id).toBe("recon-depth")
    expect(tasks[0]!.agent).toBe("recon")
    expect(tasks[0]!.priority).toBe(2)
    expect(tasks[0]!.instances).toBe(2)
    expect(tasks[0]!.prompt).toContain("[Manager directive: focus vhosts]")
    expect(tasks[0]!.prompt).toContain("example.com")
  })

  test("skip excludes an objective even if also dispatched", () => {
    const plan: Managers.Plan = {
      phase: "recon",
      dispatch: [{ objective: "recon-depth" }, { objective: "osint-passive" }],
      skip: ["osint-passive"],
      messages: [],
    }
    const tasks = Managers.toTasks(plan, "example.com")
    expect(tasks.map((t) => t.id)).toEqual(["recon-depth"])
  })
})

describe("Managers.config", () => {
  test("falls back to DEFAULT_PHASES when unset", () => {
    const cfg = Managers.config()
    expect(cfg.phases.exploitation.objectives).toEqual(Managers.DEFAULT_PHASES.exploitation)
  })

  test("honors a managers.phases override", () => {
    ConfigStore.set("managers.phases.recon.objectives", ["recon-depth"])
    const cfg = Managers.config()
    expect(cfg.phases.recon.objectives).toEqual(["recon-depth"])
    expect(Managers.allowedObjectives("recon", cfg)).toEqual(["recon-depth"])
  })
})
