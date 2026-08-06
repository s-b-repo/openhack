import * as crypto from "node:crypto"
import type {
  ActionNode,
  AssetNode,
  AttackGraphSnapshot,
  CoverageGap,
  Edge,
  FindingLike,
  FindingNode,
  GraphUpdate,
  NodeId,
  NodeUnion,
} from "./types"
import { GraphStore } from "./store"

/**
 * AttackGraph — the mutable state a pentest engagement's loop iterates over.
 *
 * The graph is a *view* over the two HMAC-signed sources of truth already in
 * `.openhack/` (Findings + Coverage) plus one novel node type — ActionNode,
 * the queue of candidate dispatches the controller proposes each round. All
 * mutations are idempotent by node id / edge triple so the same GraphUpdate
 * applied twice is a no-op (needed for controller retries + resume/replay).
 */
export namespace AttackGraph {
  // ---------------- IO shims -------------------------------------------------

  export function load(target: string): AttackGraphSnapshot {
    return GraphStore.load(target)
  }
  export function save(snap: AttackGraphSnapshot): void {
    GraphStore.save(snap)
  }
  export function withLock<T>(target: string, fn: () => T): T {
    return GraphStore.withLock(target, fn)
  }

  // ---------------- Type-safe node accessors ---------------------------------

  export function isAsset(n: NodeUnion): n is AssetNode {
    return typeof (n as any).kind === "string" && !("findingHash" in n) && !("objective" in n)
  }
  export function isFinding(n: NodeUnion): n is FindingNode {
    return typeof (n as any).findingHash === "string"
  }
  export function isAction(n: NodeUnion): n is ActionNode {
    return typeof (n as any).objective === "string" && typeof (n as any).agent === "string"
  }

  // ---------------- Id helpers -----------------------------------------------

  function actionId(): NodeId {
    return `action:${crypto.randomBytes(8).toString("hex")}`
  }
  function findingId(hash: string): NodeId {
    return `finding:${hash}`
  }
  function endpointAssetId(endpoint: string, method: string): NodeId {
    return `asset:endpoint/${method.toUpperCase()} ${endpoint}`
  }

  // ---------------- Seed / warm start ----------------------------------------

  /**
   * Populate a fresh (or existing) snapshot with the initial static batch's
   * action nodes AND with `finding:` nodes for anything already recorded, so
   * the controller has a base graph on its very first invocation. Idempotent.
   */
  export function seed(
    snap: AttackGraphSnapshot,
    round: number,
    initialActions: ActionNode[],
    findings: FindingLike[],
    gaps: CoverageGap[],
  ): void {
    // Findings → FindingNode
    for (const f of findings) {
      const id = findingId(f.hash)
      if (snap.nodes[id]) continue
      const node: FindingNode = {
        id,
        findingHash: f.hash,
        severity: f.severity,
        cwe: f.cwe,
        affectedComponent: f.affected_component,
        verified: f.status === "verified",
      }
      snap.nodes[id] = node
    }
    // Coverage gaps → endpoint AssetNodes (cheap and lets ActionNodes hang requires: on them)
    for (const g of gaps) {
      const id = endpointAssetId(g.endpoint, g.method)
      if (snap.nodes[id]) {
        ;(snap.nodes[id] as AssetNode).lastSeenRound = round
        continue
      }
      const node: AssetNode = {
        id,
        kind: "endpoint",
        value: `${g.method.toUpperCase()} ${g.endpoint}`,
        parents: [],
        discoveredInRound: round,
        lastSeenRound: round,
        attrs: {},
      }
      snap.nodes[id] = node
    }
    // Initial actions (round-1 static batch) as queued ActionNodes
    for (const a of initialActions) {
      if (snap.nodes[a.id]) continue
      snap.nodes[a.id] = a
    }
    snap.lastRound = Math.max(snap.lastRound, round)
  }

  // ---------------- Apply an update (idempotent) ----------------------------

  /**
   * Merge a GraphUpdate into the snapshot. Idempotent: repeat application of
   * the same update leaves the snapshot structurally identical (same nodes,
   * same edges — edges deduped by (from,kind,to)). Nodes existing under the
   * same id are updated in place (severity/verified/status), not replaced.
   */
  export function apply(snap: AttackGraphSnapshot, update: GraphUpdate, round: number): void {
    // Add / merge nodes
    for (const node of update.addNodes) {
      const existing = snap.nodes[node.id]
      if (!existing) {
        snap.nodes[node.id] = node
        continue
      }
      // In-place merge — preserve id but update mutable fields for the same kind.
      if (isFinding(existing) && isFinding(node)) {
        existing.severity = node.severity
        existing.verified = node.verified
        existing.cwe = node.cwe ?? existing.cwe
        existing.affectedComponent = node.affectedComponent ?? existing.affectedComponent
      } else if (isAsset(existing) && isAsset(node)) {
        existing.lastSeenRound = round
        existing.attrs = { ...existing.attrs, ...node.attrs }
      } else if (isAction(existing) && isAction(node)) {
        // Preserve status if it has progressed past `queued`; controller may
        // reprioritize but must not un-dispatch a live action.
        if (existing.status === "queued") {
          existing.priority = node.priority
          existing.score = node.score
          existing.expectedGain = node.expectedGain
          existing.prompt = node.prompt
          existing.agent = node.agent
          existing.requires = node.requires
        }
      }
    }
    // Add / dedup edges
    const seen = new Set(snap.edges.map((e) => `${e.from}|${e.kind}|${e.to}`))
    for (const e of update.addEdges) {
      const key = `${e.from}|${e.kind}|${e.to}`
      if (seen.has(key)) continue
      seen.add(key)
      snap.edges.push({ ...e, addedInRound: e.addedInRound || round })
    }
    // Reprioritize
    for (const r of update.reprioritize) {
      const n = snap.nodes[r.id]
      if (n && isAction(n) && n.status === "queued") n.score = r.score
    }
    // Prune
    for (const id of update.prune) {
      const n = snap.nodes[id]
      if (n && isAction(n) && (n.status === "queued" || n.status === "blocked")) n.status = "pruned"
    }
    // Mark dispatched
    for (const id of update.dispatch) {
      const n = snap.nodes[id]
      if (n && isAction(n) && n.status === "queued") n.status = "dispatched"
    }
    snap.lastRound = Math.max(snap.lastRound, round)
  }

  // ---------------- Frontier -------------------------------------------------

  /**
   * Return up to `k` queued action nodes, ordered by score desc → priority asc
   * → spawnedRound asc (older first as tie-break). This is what the loop
   * driver dispatches for the next round when the graph is active.
   */
  export function frontier(snap: AttackGraphSnapshot, k = 6): ActionNode[] {
    const queued: ActionNode[] = []
    for (const id of Object.keys(snap.nodes)) {
      const n = snap.nodes[id]
      if (n && isAction(n) && n.status === "queued") queued.push(n)
    }
    queued.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score
      if (a.priority !== b.priority) return a.priority - b.priority
      return a.spawnedRound - b.spawnedRound
    })
    return queued.slice(0, Math.max(0, k))
  }

  // ---------------- Housekeeping --------------------------------------------

  /**
   * Drop pruned/done ActionNodes older than `keepRounds`. Never touches
   * assets or findings — those are cheap and downstream tools query them.
   */
  export function gc(snap: AttackGraphSnapshot, round: number, keepRounds = 5): number {
    let dropped = 0
    for (const id of Object.keys(snap.nodes)) {
      const n = snap.nodes[id]
      if (!n || !isAction(n)) continue
      if ((n.status === "pruned" || n.status === "done") && round - n.spawnedRound > keepRounds) {
        delete snap.nodes[id]
        dropped++
      }
    }
    if (dropped) {
      snap.edges = snap.edges.filter((e) => snap.nodes[e.from] && snap.nodes[e.to])
    }
    return dropped
  }

  // ---------------- Adapters -------------------------------------------------

  /**
   * Build an ActionNode from a static Automode.TaskSpec-shaped record — used
   * to seed the graph with round 1's static batch. Score defaults to inverted
   * priority (5 - priority) so priority-1 tasks lead in frontier sort.
   */
  export function toActionNode(
    spec: { id: string; prompt: string; agent?: string; priority?: number; command?: string },
    round: number,
  ): ActionNode {
    const priority = spec.priority ?? 3
    return {
      id: `action:${spec.id}`,
      objective: spec.id,
      agent: spec.agent ?? "general",
      command: spec.command,
      prompt: spec.prompt,
      priority,
      score: 5 - priority,
      expectedGain: 1,
      requires: [],
      produces: [],
      spawnedRound: round,
      status: "queued",
    }
  }

  /** Convert an ActionNode back to Automode.TaskSpec shape for dispatch. */
  export function toTaskSpec(a: ActionNode): { id: string; prompt: string; agent?: string; priority?: number; command?: string } {
    return { id: a.objective, prompt: a.prompt, agent: a.agent, priority: a.priority, command: a.command }
  }

  /** Convenience id-generators used by the controllers. */
  export function newActionId(): NodeId {
    return actionId()
  }
  export function endpointId(endpoint: string, method: string): NodeId {
    return endpointAssetId(endpoint, method)
  }
  export function edge(from: NodeId, to: NodeId, kind: Edge["kind"], round: number, source: Edge["source"] = "controller"): Edge {
    return { from, to, kind, addedInRound: round, source }
  }
}
