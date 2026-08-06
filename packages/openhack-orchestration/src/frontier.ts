import { evaluateToolCall } from "../../openhack/src/plugin/enforcement"
import { ROE } from "../../openhack/src/roe"
import { ResourceManager } from "../../openhack/src/resources"
import { Net } from "../../openhack/src/net"
import type { ActionNode, Edge } from "./types"
import { AttackGraph } from "./graph"

/**
 * Frontier pruning through the OpenHack pure-enforcement decisions.
 *
 * Every candidate ActionNode is dry-run through the exact chain a real tool
 * call would face (`evaluateToolCall("task", …)` composes safety + scope +
 * ROE) plus a target-level `ROE.enforce(…)` pass and a `ResourceManager`
 * conflict check. Blocked actions carry their `blockedReason` and become
 * "blocked" nodes with an "invalidates" edge to the enforcement kind — so
 * the controller sees why on the next round and stops re-emitting the same
 * doomed action. Resource conflicts do NOT prune (the lock may drop next
 * round); they lower the score and record the reason.
 *
 * The whole pass is synchronous and cheap (no tool call ever runs).
 */
export namespace Frontier {
  export interface PruneResult {
    kept: ActionNode[]
    blocked: Array<{ action: ActionNode; kind: "safety" | "scope" | "roe" | "resource"; reason: string }>
  }

  const TARGET_PATTERN =
    /\b(?:(?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))/i

  /**
   * Best-effort target extraction from the action's prompt, then falls back
   * to the outer engagement target. Used only for the ROE dry-run; the
   * per-tool-call scope check inside `evaluateToolCall` sees the real args.
   */
  function extractTarget(prompt: string, fallback: string): string {
    try {
      const first = Net.firstTarget(prompt)
      if (first) return first
    } catch {}
    const m = TARGET_PATTERN.exec(prompt)
    return m ? m[0] : fallback
  }

  export function pruneWithEnforcement(
    actions: ActionNode[],
    outerTarget: string,
    round: number,
  ): PruneResult {
    const kept: ActionNode[] = []
    const blocked: PruneResult["blocked"] = []
    const roe = safeLoadRoe()

    for (const a of actions) {
      // Skip already-terminal nodes (idempotent — a re-enqueue of a blocked
      // action from the controller shouldn't flip it back to queued).
      if (a.status !== "queued") {
        kept.push(a)
        continue
      }

      // (1) Safety + scope via the same decision the real tool call would face.
      let decision: { blocked: boolean; reason?: string; kind?: "safety" | "scope" | "roe" }
      try {
        decision = evaluateToolCall("task", {
          subagent_type: a.agent,
          prompt: a.prompt,
          description: a.objective,
        })
      } catch {
        decision = { blocked: false }
      }
      if (decision.blocked) {
        a.status = "blocked"
        a.blockedReason = `${decision.kind ?? "policy"}: ${decision.reason ?? "blocked"}`
        blocked.push({ action: a, kind: (decision.kind ?? "scope") as any, reason: a.blockedReason })
        continue
      }

      // (2) Target-scoped ROE enforcement — the plugin does this per-shell-command,
      // but we can prune upfront on a per-action basis.
      const target = extractTarget(a.prompt, outerTarget)
      try {
        const roeDecision = ROE.enforce(roe, target, "task")
        if (roeDecision.blocked) {
          a.status = "blocked"
          a.blockedReason = `roe: ${roeDecision.reason ?? "blocked"}`
          blocked.push({ action: a, kind: "roe", reason: a.blockedReason })
          continue
        }
      } catch {}

      // (3) Resource conflict — soft: lower score, add reason, still keep.
      try {
        const conflicts = ResourceManager.findConflicting(a.agent).filter(
          (r) => (r.type === "target" || r.type === "host") && r.value === target,
        )
        if (conflicts.length) {
          a.score = Math.max(0, a.score - 5)
          a.blockedReason = `resource: target ${target} held by ${conflicts[0].agent}`
        }
      } catch {}

      kept.push(a)
    }

    return { kept, blocked }
  }

  function safeLoadRoe(): ROE.ROEDocument | null {
    try {
      return ROE.load()
    } catch {
      return null
    }
  }

  /**
   * Convenience helper the loop driver calls: prune `update.addNodes`'s
   * ActionNodes, replace them with the surviving/blocked set in-place, and
   * append `invalidates` edges from the containing action to a synthetic
   * "policy" pseudo-node for each block reason (so the graph carries the
   * *why* forward without a dedicated node type). Non-Action nodes pass
   * through untouched.
   */
  export function pruneAndAnnotateEdges(
    addNodes: Array<ActionNode | any>,
    outerTarget: string,
    round: number,
  ): { keptAddNodes: Array<ActionNode | any>; addEdges: Edge[] } {
    const actions: ActionNode[] = []
    const others: any[] = []
    for (const n of addNodes) {
      if (AttackGraph.isAction(n)) actions.push(n)
      else others.push(n)
    }
    const { kept, blocked } = pruneWithEnforcement(actions, outerTarget, round)
    const addEdges: Edge[] = blocked.map((b) => ({
      from: b.action.id,
      to: `policy:${b.kind}`,
      kind: "invalidates",
      addedInRound: round,
      source: "observation",
    }))
    return { keptAddNodes: [...others, ...kept, ...blocked.map((b) => b.action)], addEdges }
  }
}
