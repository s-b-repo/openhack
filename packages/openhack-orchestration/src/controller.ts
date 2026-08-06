import type {
  ActionNode,
  Controller,
  ControllerInput,
  Edge,
  GraphUpdate,
  NodeId,
  NodeUnion,
} from "./types"
import { emptyUpdate } from "./types"
import { AttackGraph } from "./graph"
import { HeuristicController } from "./heuristic"

/**
 * AI-driven graph controller.
 *
 * Wraps a small model (resolved by the loop driver via
 * `Provider.getSmallModel(defaultProvider)` — no OpenHack-only knob) and asks
 * it, once per round, to turn the round's observations into a `GraphUpdate`:
 *
 *   • what new ActionNodes to enqueue (grounded in the round's findings +
 *     coverage gaps + the surviving frontier),
 *   • which existing queued actions to re-prioritize or prune,
 *   • a one-line rationale that lands in the graph's audit trail.
 *
 * Every failure mode — timeout, throw, schema mismatch, empty response —
 * degrades to the deterministic HeuristicController result so the loop
 * always makes forward progress. The controller never dispatches or blocks
 * on its own; those are the loop driver's + enforcement's responsibilities.
 *
 * Model integration note: to keep this package framework-free (and to keep
 * tests fast), we accept a `generate` callable in the options rather than
 * baking in an AI-SDK dependency. The loop driver constructs it from
 * `ai`'s `generateObject` using the resolved small model.
 */
export namespace LlmController {
  export interface GeneratedUpdate {
    /**
     * Model-emitted actions to enqueue. Ids are optional — the controller
     * mints a stable id if missing. `requires` may reference existing nodes;
     * unknown references are logged but not fatal.
     */
    addActions: Array<{
      id?: string
      objective: string
      agent: string
      prompt: string
      priority?: number
      score?: number
      expectedGain?: number
      classId?: string
      endpointKey?: string
      requires?: string[]
    }>
    reprioritize?: Array<{ id: string; score: number }>
    prune?: string[]
    rationale?: string
  }

  export type Generate = (args: {
    system: string
    user: string
    timeoutMs: number
  }) => Promise<GeneratedUpdate | null>

  export interface Options {
    /**
     * Callable that wraps whatever LLM/schema-validation stack the driver has
     * (typically `generateObject` from "ai"). Return `null` on error/timeout
     * so the controller can degrade cleanly.
     */
    generate?: Generate
    /** Per-call soft timeout. Defaults to 15 s. */
    timeoutMs?: number
    /** Optional logger. */
    logger?: (msg: string) => void
  }

  export function make(opts: Options = {}): Controller {
    const timeoutMs = opts.timeoutMs ?? 15_000
    const log = opts.logger ?? (() => {})
    const generate = opts.generate

    return async (input: ControllerInput): Promise<GraphUpdate> => {
      // No generator wired up → degrade to heuristic. This is the same code
      // path the loop uses when `Provider.getSmallModel` returns undefined.
      if (!generate) return HeuristicController.run(input)

      try {
        const raced = await Promise.race<GeneratedUpdate | null>([
          generate({ system: SYSTEM, user: buildUser(input), timeoutMs }),
          new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs + 1_000)),
        ])
        if (!raced) {
          log("llm-controller: timeout / null → heuristic fallback")
          return HeuristicController.run(input)
        }
        return convert(raced, input)
      } catch (e: any) {
        log(`llm-controller: error (${e?.message ?? e}) → heuristic fallback`)
        return HeuristicController.run(input)
      }
    }
  }

  /** Exposed for tests: convert the model's raw shape into a validated GraphUpdate. */
  export function convert(raw: GeneratedUpdate, input: ControllerInput): GraphUpdate {
    const round = input.round
    const addNodes: NodeUnion[] = []
    const addEdges: Edge[] = []
    const knownAction = new Set<NodeId>()
    for (const spec of raw.addActions ?? []) {
      if (!spec || typeof spec.prompt !== "string" || !spec.prompt.trim()) continue
      const id = spec.id && spec.id.startsWith("action:") ? spec.id : AttackGraph.newActionId()
      if (knownAction.has(id)) continue
      knownAction.add(id)
      const action: ActionNode = {
        id,
        objective: (spec.objective || "llm-action").slice(0, 80),
        agent: spec.agent || "general",
        prompt: spec.prompt,
        priority: clampInt(spec.priority ?? 3, 1, 5),
        score: clampNum(spec.score ?? 3, 0, 100),
        expectedGain: clampNum(spec.expectedGain ?? 2, 0, 10),
        classId: spec.classId,
        endpointKey: spec.endpointKey,
        requires: (spec.requires ?? []).filter((r) => typeof r === "string"),
        produces: [],
        spawnedRound: round,
        status: "queued",
      }
      addNodes.push(action)
      for (const req of action.requires) addEdges.push(AttackGraph.edge(action.id, req, "requires", round))
    }
    return {
      addNodes,
      addEdges,
      reprioritize: (raw.reprioritize ?? [])
        .filter((r) => r && typeof r.id === "string" && typeof r.score === "number")
        .map((r) => ({ id: r.id, score: clampNum(r.score, 0, 100) })),
      prune: (raw.prune ?? []).filter((id) => typeof id === "string"),
      dispatch: [],
      rationale: (raw.rationale ?? "llm-update").slice(0, 240),
    }
  }

  /** Exposed for tests. */
  export function buildUser(input: ControllerInput): string {
    const { target, round, findings, coverageGaps, coverageSummary, lastRoundDelta, budgetRemainingUsd, currentFrontierIds, combinationGaps } = input
    const topFindings = findings.slice(0, 20).map(
      (f) => `- [${f.severity}${f.status === "verified" ? "|verified" : ""}] ${f.title}${f.affected_component ? ` — ${f.affected_component}` : ""}${f.cwe ? ` (${f.cwe})` : ""} (hash=${f.hash.slice(0, 8)})`,
    )
    const topGaps = coverageGaps.slice(0, 20).map((g) => `- ${g.method.toUpperCase()} ${g.endpoint} — ${g.className} (${g.classId})`)
    const combos: string[] = []
    if (combinationGaps) {
      combos.push(`### Method-tuple gaps (top 10)`)
      combos.push(...combinationGaps.methods.slice(0, 10).map((g) => `- ${g.endpoint} — missing [${g.missingMethods.join(", ")}]`))
      combos.push(`### Payload-family gaps (top 10)`)
      combos.push(...combinationGaps.payloads.slice(0, 10).map((g) => `- ${g.method} ${g.endpoint} × ${g.className} — missing [${g.missingFamilies.join(", ")}]`))
      combos.push(`### Chain-pair gaps (top 10)`)
      combos.push(...combinationGaps.chains.slice(0, 10).map((g) => `- ${g.classA}@${g.methodA} ${g.endpointA}  →  ${g.classB}@${g.methodB} ${g.endpointB}`))
      combos.push(`### Per-finding open combos (top 5 findings)`)
      for (const pf of combinationGaps.perFinding.slice(0, 5)) {
        combos.push(`- [${pf.severity}] ${pf.title} (class=${pf.classId ?? "?"}): ${pf.missingCombos.length} open combos${pf.chainHints.length ? `; chains-with: ${pf.chainHints.join(", ")}` : ""}`)
      }
      combos.push(`(Universe ${combinationGaps.universeSize} combos; ${combinationGaps.satisfiedSize} satisfied; ${Math.max(0, combinationGaps.universeSize - combinationGaps.satisfiedSize)} open.)`)
    }
    return [
      `# Round ${round} — target: ${target}`,
      ``,
      `Last round: +${lastRoundDelta.newFindings} findings, +${lastRoundDelta.newHigh} high-value, cost $${lastRoundDelta.costUsd.toFixed(2)}.`,
      `Budget remaining: $${budgetRemainingUsd.toFixed(2)}.`,
      coverageSummary
        ? `Coverage: ${coverageSummary.tested}/${coverageSummary.cells} cells tested (${coverageSummary.percent}%), ${coverageSummary.vulnerable} vulnerable.`
        : `Coverage: not populated yet.`,
      ``,
      `## Findings so far (top 20)`,
      topFindings.length ? topFindings.join("\n") : "(none)",
      ``,
      `## Untested coverage cells (top 20)`,
      topGaps.length ? topGaps.join("\n") : "(none)",
      ``,
      `## Untested combinations`,
      combos.length ? combos.join("\n") : "(not computed this round)",
      ``,
      `## Current frontier action ids (do NOT re-emit these)`,
      currentFrontierIds.slice(0, 40).join(", ") || "(empty)",
    ].join("\n")
  }

  const SYSTEM =
    `You are OpenHack's attack-graph controller. Each round you receive a compact snapshot ` +
    `(new findings + coverage gaps + last round's delta + budget) and return the next batch ` +
    `of candidate actions. Rules:\n` +
    `- Emit at most 12 addActions. Each MUST target a specific finding or coverage cell.\n` +
    `- Prefer actions that verify an unverified high/critical finding, chain a verified one, ` +
    `or close a coverage gap on a high-priority vuln class (RCE, auth-bypass, injection).\n` +
    `- Set agent to one of: recon, exploit, post-exploit, report, general.\n` +
    `- Prompt bodies must be self-contained: state the target, the objective, and the ` +
    `non-destructive success criterion. Never propose DoS or destructive actions.\n` +
    `- Reprioritize sparingly (only when new evidence changes a queued action's value). ` +
    `Prune only actions that a finding has already invalidated.\n` +
    `- Rationale: one line, ≤ 240 chars, explaining the round's plan.`

  function clampInt(n: number, lo: number, hi: number): number {
    return Math.max(lo, Math.min(hi, Math.floor(Number.isFinite(n) ? n : lo)))
  }
  function clampNum(n: number, lo: number, hi: number): number {
    return Math.max(lo, Math.min(hi, Number.isFinite(n) ? n : lo))
  }

  /** Public no-op — same rationale label the empty path uses. */
  export function noop(): GraphUpdate {
    return emptyUpdate("llm-controller:noop")
  }
}
