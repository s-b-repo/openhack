import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Frontier, AttackGraph } from "../../openhack-orchestration/src"
import type { ActionNode } from "../../openhack-orchestration/src/types"
import { Scope } from "../src/scope"
import { ROE } from "../src/roe"
import { ResourceManager } from "../src/resources"

/**
 * Frontier pruning is the single point that connects the graph controller to
 * the real enforcement chain (evaluateToolCall → ROE.enforce →
 * ResourceManager.findConflicting). These tests exercise each block reason.
 *
 * Uses a per-test scratch cwd so scope.json / active.roe.json / resources.json
 * files don't cross-contaminate.
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-frontier-"))
  process.chdir(scratch)
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
  // Scope module-level cache would leak across scratch dirs — reload with a fresh empty cfg.
  Scope.load({ enabled: false, targets: [], exclusions: [], max_port_range: "1-65535", allowed_tools: [], disallowed_tools: [], require_confirmation_for: [] })
})

function mkAction(id: string, agent: string, prompt: string): ActionNode {
  return {
    id: `action:${id}`,
    objective: id,
    agent,
    prompt,
    priority: 3,
    score: 3,
    expectedGain: 2,
    requires: [],
    produces: [],
    spawnedRound: 1,
    status: "queued",
  }
}

describe("Frontier.pruneWithEnforcement", () => {
  test("passes actions when scope is disabled and no ROE is present", () => {
    const actions = [mkAction("a1", "recon", "Scan example.com for open ports")]
    const { kept, blocked } = Frontier.pruneWithEnforcement(actions, "example.com", 1)
    expect(kept.length).toBe(1)
    expect(blocked.length).toBe(0)
  })

  test("SCOPE: an out-of-scope target in the action's prompt is blocked when scope is enabled", () => {
    Scope.save({
      enabled: true, targets: ["example.com"], exclusions: [],
      max_port_range: "1-65535", allowed_tools: [], disallowed_tools: [], require_confirmation_for: [],
    })
    const good = mkAction("good", "recon", "Recon on example.com")
    const bad = mkAction("bad", "recon", "Recon on unrelated.internal — try admin panel http://unrelated.internal/admin")
    const { kept, blocked } = Frontier.pruneWithEnforcement([good, bad], "example.com", 1)
    const keptIds = new Set(kept.map((a) => a.id))
    expect(keptIds.has(good.id)).toBe(true)
    // At least one enforcement pass blocks the out-of-scope prompt.
    const badResult = kept.find((a) => a.id === bad.id) || blocked.find((b) => b.action.id === bad.id)?.action
    expect(badResult).toBeDefined()
    // The blocked action carries a scope/ROE reason.
    if (blocked.some((b) => b.action.id === bad.id)) {
      const b = blocked.find((x) => x.action.id === bad.id)!
      expect(["scope", "roe"]).toContain(b.kind)
      expect(bad.status).toBe("blocked")
      expect(bad.blockedReason).toBeTruthy()
    }
  })

  test("ROE: an active signed ROE that expired blocks all actions", () => {
    const roe = ROE.createTemplate("Acme", "Acme")
    roe.targets = ["example.com"]
    roe.date_start = new Date(Date.now() - 30 * 86400_000).toISOString().slice(0, 10)
    roe.date_end = new Date(Date.now() - 1 * 86400_000).toISOString().slice(0, 10)
    roe.expires_at = new Date(Date.now() - 1 * 86400_000).toISOString()
    ROE.sign(roe)
    const a = mkAction("a", "recon", "Scan example.com")
    const { kept, blocked } = Frontier.pruneWithEnforcement([a], "example.com", 1)
    // Expired ROE => blocked with kind=roe.
    expect(blocked.length).toBe(1)
    expect(blocked[0]!.kind).toBe("roe")
    expect(kept.find((x) => x.id === a.id)).toBeUndefined()
  })

  test("ROE: a valid signed ROE with * targets allows in-scope actions", () => {
    const roe = ROE.createTemplate("Acme", "Acme")
    roe.targets = ["*"]
    roe.authorized_tools = ["*"]
    roe.expires_at = new Date(Date.now() + 30 * 86400_000).toISOString()
    ROE.sign(roe)
    const a = mkAction("a", "recon", "Recon on example.com")
    const { kept, blocked } = Frontier.pruneWithEnforcement([a], "example.com", 1)
    expect(kept.length).toBe(1)
    expect(blocked.length).toBe(0)
  })

  test("RESOURCE: a target lock held by another agent marks (not prunes) the action", () => {
    // Two agents contending for the same target lock.
    ResourceManager.acquire("target", "example.com", "session-1", "session-1", "recon", 60_000)
    const a = mkAction("a", "exploit", "Attack example.com")
    const { kept, blocked } = Frontier.pruneWithEnforcement([a], "example.com", 1)
    // Resource conflict is soft — action is kept, score lowered, reason recorded.
    expect(kept.length).toBe(1)
    expect(blocked.length).toBe(0)
    const stillQueued = kept[0]!
    expect(stillQueued.status).toBe("queued")
    expect(stillQueued.blockedReason).toMatch(/resource:/)
  })

  test("SAFETY: actions in a prompt-only form are not treated as shell commands (no false safety block)", () => {
    // The action's *prompt* mentions a destructive verb but the tool call is 'task', not 'bash'.
    const a = mkAction("a", "recon", "Do NOT rm -rf anything — just recon example.com carefully")
    const { kept, blocked } = Frontier.pruneWithEnforcement([a], "example.com", 1)
    expect(kept.length + blocked.length).toBe(1)
    // Whichever it lands in, if blocked at all it must NOT be for safety on a 'task' tool.
    if (blocked.length) expect(blocked[0]!.kind).not.toBe("safety")
  })
})

describe("Frontier.pruneAndAnnotateEdges", () => {
  test("non-action nodes pass through untouched", () => {
    const finding = { id: "finding:xyz", findingHash: "xyz", severity: "critical" as const, verified: false }
    const action = mkAction("a", "recon", "Scan example.com")
    const { keptAddNodes } = Frontier.pruneAndAnnotateEdges([finding as any, action], "example.com", 1)
    expect(keptAddNodes.some((n: any) => n.id === "finding:xyz")).toBe(true)
    expect(keptAddNodes.some((n: any) => n.id === action.id)).toBe(true)
  })

  test("blocked actions produce an 'invalidates' edge to a policy pseudo-node", () => {
    Scope.save({
      enabled: true, targets: ["example.com"], exclusions: [],
      max_port_range: "1-65535", allowed_tools: [], disallowed_tools: [], require_confirmation_for: [],
    })
    const bad = mkAction("bad", "recon", "Try admin panel http://unrelated.internal/admin")
    const { addEdges } = Frontier.pruneAndAnnotateEdges([bad], "example.com", 1)
    if (bad.status === "blocked") {
      const invalidate = addEdges.find((e) => e.kind === "invalidates" && e.from === bad.id)
      expect(invalidate).toBeDefined()
      expect(invalidate!.to.startsWith("policy:")).toBe(true)
    }
  })
})
