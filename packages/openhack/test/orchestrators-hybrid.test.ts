import { describe, expect, test } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import { Orchestrators } from "../src/orchestrators"

/**
 * Orchestrator widening + new hybrid roles. Guards:
 *   • Widened `subagentType` accepts strings outside the old 5-value union.
 *   • The four new roles (osint-passive, defense-review, c2-handoff, cleanup-artifacts) are declared.
 *   • Every orchestrator's `subagentType` is either a framework default (general/plan) or matches an agent file in .openhack/agents/.
 *   • Priority ordering is stable across widening.
 *   • `cleanup-artifacts` is command-dispatched via `/cleanup`.
 *   • `buildBatch` propagates the `command` field into the TaskSpec.
 */

const REPO_ROOT = path.resolve(__dirname, "../../..")
const AGENT_DIR = path.join(REPO_ROOT, ".openhack", "agents")

// Framework-default agents that don't need a .md file.
const FRAMEWORK_AGENTS = new Set(["general", "plan"])

describe("Orchestrators — widened subagentType", () => {
  test("new roles are present in ORCHESTRATORS", () => {
    const ids = new Set(Orchestrators.ORCHESTRATORS.map((o) => o.id))
    for (const id of ["osint-passive", "defense-review", "c2-handoff", "cleanup-artifacts"]) {
      expect(ids.has(id)).toBe(true)
    }
  })

  test("each new orchestrator's subagentType matches an agent file on disk (or a framework default)", () => {
    const onDisk = new Set(
      fs.readdirSync(AGENT_DIR).filter((f) => f.endsWith(".md")).map((f) => f.slice(0, -3)),
    )
    for (const o of Orchestrators.ORCHESTRATORS) {
      const ok = FRAMEWORK_AGENTS.has(o.subagentType) || onDisk.has(o.subagentType)
      if (!ok) throw new Error(`${o.id} → subagentType=${o.subagentType} has no .openhack/agents/${o.subagentType}.md file`)
      expect(ok).toBe(true)
    }
  })

  test("cleanup-artifacts is command-dispatched via /cleanup", () => {
    const cleanup = Orchestrators.get("cleanup-artifacts")
    expect(cleanup).toBeDefined()
    expect(cleanup!.command).toBe("cleanup")
  })

  test("osint-passive is priority 0 (runs before recon)", () => {
    const osint = Orchestrators.get("osint-passive")
    expect(osint).toBeDefined()
    expect(osint!.priority).toBe(0)
    const recon = Orchestrators.get("recon-depth")
    expect(recon).toBeDefined()
    expect(osint!.priority).toBeLessThan(recon!.priority)
  })

  test("cleanup-artifacts is priority 99 (runs last)", () => {
    const cleanup = Orchestrators.get("cleanup-artifacts")
    const report = Orchestrators.get("report")
    expect(cleanup!.priority).toBeGreaterThan(report!.priority)
  })
})

describe("Orchestrators.buildBatch — hybrid dispatch", () => {
  test("propagates `command` field on cleanup TaskSpec", () => {
    const batch = Orchestrators.buildBatch("t")
    const cleanup = batch.find((t) => t.id === "cleanup-artifacts")
    expect(cleanup).toBeDefined()
    expect(cleanup!.command).toBe("cleanup")
    // Every other task has no command.
    const others = batch.filter((t) => t.id !== "cleanup-artifacts")
    for (const o of others) expect(o.command).toBeUndefined()
  })

  test("id-filtering respects the new orchestrators", () => {
    const b = Orchestrators.buildBatch("t", ["osint-passive", "defense-review"])
    expect(b.length).toBe(2)
    expect(b[0]!.priority).toBeLessThanOrEqual(b[1]!.priority)
  })

  test("all orchestrators have non-empty instructions and doctrine embedded", () => {
    for (const t of Orchestrators.buildBatch("example.com")) {
      expect(t.prompt.length).toBeGreaterThan(0)
      expect(t.prompt).toContain("example.com")
      // Doctrine (from `withDoctrine`) is embedded in every orchestrator.
      expect(t.prompt).toContain("Authorized, in-scope work only")
    }
  })
})
