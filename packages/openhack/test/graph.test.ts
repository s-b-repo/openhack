import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { AttackGraph, GraphStore, HeuristicController } from "../../openhack-orchestration/src"
import type { ActionNode, AttackGraphSnapshot } from "../../openhack-orchestration/src/types"

/**
 * Graph store + AttackGraph API tests.
 * Isolated per-test via a scratch cwd so the on-disk .openhack/graph/ store
 * doesn't collide with a real engagement or another test file.
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-graph-"))
  process.chdir(scratch)
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

function seedAction(round = 1, i = 0): ActionNode {
  return {
    id: `action:seed-${i}`,
    objective: `seed-${i}`,
    agent: "recon",
    prompt: `Scan example.com step ${i}`,
    priority: 3,
    score: i, // ascending
    expectedGain: 1,
    requires: [],
    produces: [],
    spawnedRound: round,
    status: "queued",
  }
}

describe("GraphStore", () => {
  test("round-trip preserves nodes and edges and re-verifies", () => {
    const snap = GraphStore.empty("example.com")
    snap.nodes["asset:host/example.com"] = {
      id: "asset:host/example.com",
      kind: "host",
      value: "example.com",
      parents: [],
      discoveredInRound: 1,
      lastSeenRound: 1,
      attrs: {},
    }
    snap.edges.push({ from: "asset:host/example.com", to: "asset:host/example.com", kind: "parent-of", addedInRound: 1, source: "seed" })
    GraphStore.save(snap)

    const reloaded = GraphStore.load("example.com")
    expect(Object.keys(reloaded.nodes).length).toBe(1)
    expect(reloaded.edges.length).toBe(1)
    expect(GraphStore.verifyHmac(reloaded)).toBe(true)
  })

  test("HMAC tamper is detected and snapshot is dropped", () => {
    const snap = GraphStore.empty("example.com")
    snap.nodes["asset:host/example.com"] = {
      id: "asset:host/example.com",
      kind: "host",
      value: "example.com",
      parents: [],
      discoveredInRound: 1,
      lastSeenRound: 1,
      attrs: {},
    }
    GraphStore.save(snap)

    // Tamper on disk — add a rogue node without recomputing the HMAC.
    const fp = GraphStore.filePath("example.com")
    const raw: AttackGraphSnapshot = JSON.parse(fs.readFileSync(fp, "utf-8"))
    raw.nodes["asset:host/rogue.example.com"] = {
      id: "asset:host/rogue.example.com",
      kind: "host",
      value: "rogue.example.com",
      parents: [],
      discoveredInRound: 1,
      lastSeenRound: 1,
      attrs: {},
    }
    fs.writeFileSync(fp, JSON.stringify(raw))

    const reloaded = GraphStore.load("example.com")
    // Fresh empty snapshot after HMAC mismatch — the rogue node is dropped.
    expect(Object.keys(reloaded.nodes).length).toBe(0)
  })

  test("safe-target names stay inside .openhack/graph even for traversal input", () => {
    const fp = GraphStore.filePath("../../../etc/passwd")
    // Resolve away any residual "..": the sanitized filename lives inside .openhack/graph.
    const resolved = path.resolve(fp)
    const dir = path.resolve(".openhack", "graph")
    expect(resolved.startsWith(dir + path.sep)).toBe(true)
    expect(fp.endsWith(".json")).toBe(true)
    // And path traversal characters are stripped from the filename itself.
    const name = path.basename(fp)
    expect(name.split(path.sep).length).toBe(1)
    expect(name.split("/").length).toBe(1)
  })
})

describe("AttackGraph.apply", () => {
  test("apply is idempotent — same update twice = same graph", () => {
    const snap = GraphStore.empty("t")
    const a1 = seedAction(1, 0)
    const a2 = seedAction(1, 1)
    const update = {
      addNodes: [a1, a2],
      addEdges: [AttackGraph.edge(a1.id, a2.id, "requires", 1)],
      reprioritize: [],
      prune: [],
      dispatch: [],
      rationale: "test",
    }
    AttackGraph.apply(snap, update, 1)
    const beforeNodes = Object.keys(snap.nodes).length
    const beforeEdges = snap.edges.length
    AttackGraph.apply(snap, update, 1)
    expect(Object.keys(snap.nodes).length).toBe(beforeNodes)
    expect(snap.edges.length).toBe(beforeEdges)
  })

  test("reprioritize only affects queued actions; dispatched are frozen", () => {
    const snap = GraphStore.empty("t")
    const a = seedAction(1, 0)
    AttackGraph.apply(snap, { addNodes: [a], addEdges: [], reprioritize: [], prune: [], dispatch: [a.id], rationale: "d" }, 1)
    expect((snap.nodes[a.id] as ActionNode).status).toBe("dispatched")
    AttackGraph.apply(snap, { addNodes: [], addEdges: [], reprioritize: [{ id: a.id, score: 99 }], prune: [], dispatch: [], rationale: "" }, 2)
    // Dispatched node's score should NOT be silently rewritten.
    expect((snap.nodes[a.id] as ActionNode).score).not.toBe(99)
  })

  test("prune moves queued/blocked actions to pruned, but not done/dispatched", () => {
    const snap = GraphStore.empty("t")
    const q = seedAction(1, 0)
    const d = { ...seedAction(1, 1), id: "action:d", status: "dispatched" as const }
    AttackGraph.apply(snap, { addNodes: [q, d], addEdges: [], reprioritize: [], prune: [q.id, d.id], dispatch: [], rationale: "p" }, 1)
    expect((snap.nodes[q.id] as ActionNode).status).toBe("pruned")
    // Dispatched must not be pruned by the controller.
    expect((snap.nodes[d.id] as ActionNode).status).toBe("dispatched")
  })
})

describe("AttackGraph.frontier", () => {
  test("orders by score desc, then priority asc, then spawnedRound asc", () => {
    const snap = GraphStore.empty("t")
    const high = { ...seedAction(1, 0), id: "action:high", score: 10, priority: 3 }
    const mid = { ...seedAction(1, 1), id: "action:mid", score: 5, priority: 2 }
    const low = { ...seedAction(2, 2), id: "action:low", score: 5, priority: 3 }
    AttackGraph.apply(snap, { addNodes: [low, high, mid], addEdges: [], reprioritize: [], prune: [], dispatch: [], rationale: "" }, 2)
    const f = AttackGraph.frontier(snap, 3)
    expect(f.map((a) => a.id)).toEqual(["action:high", "action:mid", "action:low"])
  })

  test("respects k cap", () => {
    const snap = GraphStore.empty("t")
    for (let i = 0; i < 20; i++)
      AttackGraph.apply(snap, { addNodes: [seedAction(1, i)], addEdges: [], reprioritize: [], prune: [], dispatch: [], rationale: "" }, 1)
    expect(AttackGraph.frontier(snap, 5).length).toBe(5)
  })

  test("skips non-queued actions", () => {
    const snap = GraphStore.empty("t")
    const q = seedAction(1, 0)
    const done = { ...seedAction(1, 1), id: "action:done", status: "done" as const }
    AttackGraph.apply(snap, { addNodes: [q, done], addEdges: [], reprioritize: [], prune: [], dispatch: [], rationale: "" }, 1)
    const f = AttackGraph.frontier(snap)
    expect(f.length).toBe(1)
    expect(f[0]!.id).toBe(q.id)
  })
})

describe("AttackGraph.gc", () => {
  test("drops pruned/done actions older than keepRounds and cleans dangling edges", () => {
    const snap = GraphStore.empty("t")
    const old = { ...seedAction(1, 0), id: "action:old", status: "pruned" as const }
    const young = { ...seedAction(1, 1), id: "action:young" }
    const done = { ...seedAction(5, 2), id: "action:done", status: "done" as const }
    AttackGraph.apply(snap, {
      addNodes: [old, young, done],
      addEdges: [AttackGraph.edge(old.id, young.id, "requires", 1)],
      reprioritize: [], prune: [], dispatch: [], rationale: "",
    }, 5)
    const dropped = AttackGraph.gc(snap, 10, 3) // older than round 10-3=7 spawned
    expect(dropped).toBe(2) // old (round 1) and done (round 5) both age out
    expect(snap.nodes["action:old"]).toBeUndefined()
    expect(snap.nodes["action:done"]).toBeUndefined()
    expect(snap.nodes["action:young"]).toBeDefined()
    // Dangling edge should have been swept.
    expect(snap.edges.length).toBe(0)
  })

  test("never drops assets or findings", () => {
    const snap = GraphStore.empty("t")
    HeuristicController.run
    AttackGraph.apply(snap, {
      addNodes: [
        { id: "asset:host/example.com", kind: "host", value: "example.com", parents: [], discoveredInRound: 1, lastSeenRound: 1, attrs: {} },
        { id: "finding:abc123", findingHash: "abc123", severity: "critical", verified: false },
      ],
      addEdges: [], reprioritize: [], prune: [], dispatch: [], rationale: "",
    }, 1)
    AttackGraph.gc(snap, 100, 3)
    expect(snap.nodes["asset:host/example.com"]).toBeDefined()
    expect(snap.nodes["finding:abc123"]).toBeDefined()
  })
})
