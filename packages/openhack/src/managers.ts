import { Automode } from "./automode"
import { Orchestrators } from "./orchestrators"
import { ConfigStore } from "./config-store"
import { Blackboard } from "./blackboard"

/**
 * Phase-manager tier — the middle layer of the main → 5-managers → workers hierarchy.
 *
 * A manager is NOT a nested subagent; it is a cheap LLM PLANNING step run inside the
 * loop each round (one call per active phase). It decides which of its phase's objectives
 * to run, in what order, whether to skip any, and what to tell its peers — then the
 * deterministic loop maps that plan onto the existing `Orchestrators`/`runInstance`
 * dispatch. The loop keeps sole ownership of ROE, budget, rounds and termination.
 *
 * This module is PURE (prompt building + plan parsing + task mapping). The LLM-call glue
 * (`runManagerPlanning`) lives in the loop driver, which owns the subprocess bridge.
 */
export namespace Managers {
  export type PhaseId = "recon" | "enumeration" | "exploitation" | "post-exploitation" | "c2"
  export const PHASE_IDS: PhaseId[] = ["recon", "enumeration", "exploitation", "post-exploitation", "c2"]

  /**
   * Default phase → orchestrator-id ownership. The full attack chain, minus `report`
   * (which stays with the main AI's end-of-run task). Overridable per phase via the
   * `managers.phases.<id>.objectives` config array.
   */
  export const DEFAULT_PHASES: Record<PhaseId, string[]> = {
    recon: ["osint-passive", "recon-depth"],
    enumeration: ["combination-gaps"],
    exploitation: ["internal-access", "chaining-planning", "defense-review"],
    "post-exploitation": ["pii-exposure", "pivoting", "privesc"],
    c2: ["c2-handoff", "cleanup-artifacts"],
  }

  export interface PhaseConfig {
    objectives: string[]
    model?: string
    tier?: "main" | "fast" | "cheap" | "draft"
  }

  export interface Config {
    enabled: boolean
    tier: string
    model?: string
    phases: Record<PhaseId, PhaseConfig>
  }

  /** Read the `managers.*` config section, falling back to DEFAULT_PHASES per phase. */
  export function config(): Config {
    const enabled = Boolean(ConfigStore.get("managers.enabled") ?? false)
    const tier = String(ConfigStore.get("managers.tier") ?? "cheap")
    const model = (ConfigStore.get("managers.model") as string | undefined) || undefined
    const phases = {} as Record<PhaseId, PhaseConfig>
    for (const id of PHASE_IDS) {
      const raw = ConfigStore.get(`managers.phases.${id}`) as Partial<PhaseConfig> | undefined
      const objectives =
        raw && Array.isArray(raw.objectives) && raw.objectives.length ? raw.objectives : DEFAULT_PHASES[id]
      phases[id] = { objectives, model: raw?.model, tier: raw?.tier }
    }
    return { enabled, tier, model, phases }
  }

  /** The objective ids a phase is allowed to dispatch (its whitelist). */
  export function allowedObjectives(phase: PhaseId, cfg: Config = config()): string[] {
    return cfg.phases[phase]?.objectives ?? DEFAULT_PHASES[phase] ?? []
  }

  // ── Plan schema ────────────────────────────────────────────────────────────
  export interface PlanDispatch {
    objective: string
    priority?: number
    instances?: number
    note?: string
  }
  export interface PlanMessage {
    to: PhaseId | "all"
    kind: Blackboard.Kind
    text: string
    refs?: string[]
  }
  export interface Plan {
    phase: PhaseId
    dispatch: PlanDispatch[]
    skip: string[]
    messages: PlanMessage[]
    rationale?: string
  }

  const VALID_KINDS: Blackboard.Kind[] = ["directive", "hint", "request", "ack"]

  /** Build the JSON-only planner prompt for a phase manager. Short + cheap (steps:1). */
  export function buildPlannerPrompt(args: {
    phase: PhaseId
    target: string
    allowed: string[]
    findingsSummary: string
    inbox: string
    coverageGaps: string
  }): string {
    const menu = args.allowed
      .map((id) => {
        const o = Orchestrators.get(id)
        return `  - ${id}${o ? ` (${o.name}; agent ${o.subagentType})` : ""}`
      })
      .join("\n")
    return (
      `You are the ${args.phase} phase-manager for the authorized assessment of ${args.target}.\n` +
      `Your job: decide which of YOUR objectives to run this round, in what order, and what to tell peer managers.\n\n` +
      `Objectives you may dispatch (you may ONLY use these ids):\n${menu}\n\n` +
      `Current findings:\n${args.findingsSummary || "(none yet)"}\n\n` +
      `Messages from peer managers:\n${args.inbox}\n\n` +
      `Open coverage gaps:\n${args.coverageGaps || "(none reported)"}\n\n` +
      `Peer phases you can message: ${PHASE_IDS.join(", ")}, or "all".\n\n` +
      `Return ONLY one minified JSON object — no prose, no markdown, no code fences — of shape:\n` +
      `{"phase":"${args.phase}","dispatch":[{"objective":"<id>","priority":1,"instances":1,"note":"focus hint"}],` +
      `"skip":["<id>"],"messages":[{"to":"exploitation","kind":"directive","text":"...","refs":["FIND-.."]}],` +
      `"rationale":"one line"}`
    )
  }

  /**
   * Parse + VALIDATE a manager plan. `raw` may be the model's raw string output or an
   * already-parsed object. Any dispatch/skip objective not in `allowed` is DROPPED —
   * a hallucinated or out-of-scope objective can never be dispatched. Malformed input
   * yields an empty plan (the loop then falls back to the phase's static objective set).
   */
  export function parsePlan(phase: PhaseId, raw: unknown, allowed: string[]): Plan {
    const empty: Plan = { phase, dispatch: [], skip: [], messages: [] }
    const obj = typeof raw === "string" ? extractJson(raw) : raw
    if (!obj || typeof obj !== "object") return empty
    const o = obj as Record<string, any>
    const allow = new Set(allowed)

    const dispatch: PlanDispatch[] = Array.isArray(o.dispatch)
      ? o.dispatch
          .filter((d: any) => d && typeof d.objective === "string" && allow.has(d.objective))
          .map((d: any) => ({
            objective: d.objective,
            priority: numOrUndef(d.priority),
            instances: clampInstances(d.instances),
            note: typeof d.note === "string" && d.note.trim() ? d.note.trim() : undefined,
          }))
      : []

    const skip: string[] = Array.isArray(o.skip)
      ? o.skip.filter((s: any) => typeof s === "string" && allow.has(s))
      : []

    const messages: PlanMessage[] = Array.isArray(o.messages)
      ? o.messages
          .filter(
            (m: any) =>
              m &&
              typeof m.text === "string" &&
              m.text.trim() &&
              (m.to === "all" || PHASE_IDS.includes(m.to)) &&
              VALID_KINDS.includes(m.kind),
          )
          .map((m: any) => ({
            to: m.to,
            kind: m.kind,
            text: String(m.text).trim(),
            refs: Array.isArray(m.refs) ? m.refs.filter((r: any) => typeof r === "string") : [],
          }))
      : []

    return { phase, dispatch, skip, messages, rationale: typeof o.rationale === "string" ? o.rationale : undefined }
  }

  /**
   * Map a parsed plan to dispatchable TaskSpecs. Each dispatch id is resolved through
   * the existing `Orchestrators` catalog (so ROE doctrine + agent routing are unchanged);
   * a `note` becomes a `[Manager directive: …]` prompt suffix. Objectives listed in `skip`
   * are excluded even if also present in `dispatch`.
   */
  export function toTasks(plan: Plan, target: string): Automode.TaskSpec[] {
    const skip = new Set(plan.skip)
    const tasks: Automode.TaskSpec[] = []
    for (const d of plan.dispatch) {
      if (skip.has(d.objective)) continue
      const o = Orchestrators.get(d.objective)
      if (!o) continue
      const note = d.note ? `\n\n[Manager directive: ${d.note}]` : ""
      tasks.push({
        id: o.id,
        prompt: o.instruction(target) + note,
        agent: o.subagentType,
        priority: d.priority ?? o.priority,
        ...(o.command ? { command: o.command } : {}),
        ...(d.instances ? { instances: d.instances } : {}),
      })
    }
    return tasks
  }

  /**
   * The phase's full static objective set as TaskSpecs — the fallback the loop dispatches
   * when the planner errors, returns no JSON, or a phase has ≤1 objective (no LLM call).
   */
  export function staticTasks(phase: PhaseId, target: string, cfg: Config = config()): Automode.TaskSpec[] {
    return Orchestrators.buildBatch(target, allowedObjectives(phase, cfg))
  }

  function numOrUndef(n: any): number | undefined {
    const v = Number(n)
    return Number.isFinite(v) ? v : undefined
  }
  function clampInstances(n: any): number | undefined {
    const v = Number(n)
    if (!Number.isFinite(v)) return undefined
    return Math.max(1, Math.min(6, Math.round(v)))
  }

  /** Minimal JSON-object extractor (tolerates ```json fences + surrounding prose). */
  function extractJson(text: string): any | null {
    if (!text) return null
    let t = text.trim()
    const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i)
    if (fence?.[1]) t = fence[1].trim()
    const start = t.indexOf("{")
    const end = t.lastIndexOf("}")
    if (start < 0 || end <= start) return null
    try {
      return JSON.parse(t.slice(start, end + 1))
    } catch {
      return null
    }
  }
}
