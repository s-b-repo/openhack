// Real automode execution for `openhack automode`.
//
// Replaces the old placeholder path (which wrote `**Status**: queued` files and
// printed "Done" without running anything). Here each objective is executed for
// REAL by re-invoking this CLI's own `run` subcommand as a subprocess — which
// boots a full session, dispatches specialist subagents via the `task` tool, and
// runs the actual pentest work. Between rounds we read `.openhack/findings/` and
// decide whether to iterate again (iterate-until-goal), terminating on
// convergence (no new vectors), budget, ROE window, or a hard round cap.
//
// The subprocess `llmFn` is injectable so the loop is unit-testable with a fake
// runner (no real model cost). All ROE/scope/safety enforcement still applies —
// it runs inside each spawned `run` session's plugin, not here.
import * as fs from "node:fs"
import * as path from "node:path"
import { EOL } from "node:os"
import { spawn } from "node:child_process"
import { Automode } from "../../../../openhack/src/automode"
import { Orchestrators } from "../../../../openhack/src/orchestrators"
import { Findings } from "../../../../openhack/src/findings"
import { ROE } from "../../../../openhack/src/roe"
import { MOERouter } from "../../../../openhack/src/moe-router"
import { Coverage } from "../../../../openhack/src/coverage"
import { Combinations } from "../../../../openhack/src/combinations"
import { Knowledge } from "../../../../openhack/src/knowledge"
import { ConfigStore } from "../../../../openhack/src/config-store"
import { GlobalConfig } from "../../../../openhack/src/global-config"
import { RoundBudget } from "../../../../openhack/src/round-budget"
import {
  AttackGraph,
  Frontier,
  HeuristicController,
  LlmController,
  Scores,
  type Controller,
  type ControllerInput,
  type FindingLike,
} from "../../../../openhack-orchestration/src"

// `ok:false` marks a run that failed to produce real work — a non-zero/killed
// exit, an empty transcript, or a spawn failure. Callers (Automode.executeTask)
// MUST treat these as failures instead of silently logging success. `error`
// carries a short human reason. Absent `ok` means "assume success" for
// backwards-compatible injected runners in tests.
export type LlmResult = { output: string; tokensIn: number; tokensOut: number; cost: number; ok?: boolean; error?: string }
export type LlmFn = (prompt: string) => Promise<LlmResult>
/**
 * Opts a caller may pass to the factory instead of a bare agent string. Enables
 * per-task tier + macro dispatch: pass `{command: "council"}` to fire the
 * `.opencode/command/council.md` macro instead of a plain `--agent` invocation;
 * pass `{model: "deepseek/deepseek-v4"}` to override the loop's default.
 */
export type LlmFactoryOpts = { agent?: string; command?: string; model?: string }
/** Build an `llmFn` bound to a specific subagent (recon/exploit/…) or macro. */
export type LlmFactory = (agentOrOpts?: string | LlmFactoryOpts) => LlmFn

function out(msg: string) { process.stdout.write(msg + EOL) }

/**
 * How to re-invoke this CLI's `run` subcommand. Honours `OPENHACK_RUN_CMD`
 * (space-separated) for environments where the default self-re-exec doesn't fit
 * (e.g. a wrapper script). Otherwise re-execs the current interpreter + entry
 * script, or the compiled single-file binary.
 */
export function resolveRunCmd(): string[] {
  const override = process.env.OPENHACK_RUN_CMD
  if (override && override.trim()) return override.trim().split(/\s+/)
  const exec = process.execPath
  const script = process.argv[1]
  if (script && /\.(ts|js|mjs|cjs)$/.test(script)) return [exec, script]
  return [exec]
}

/**
 * Default REAL executor: spawns `<cli> run --format json [--agent A] [--model M] <prompt>`,
 * captures the assistant text output, and best-effort-accumulates token/cost
 * usage from the JSON event stream. Never rejects — a spawn/exec failure resolves
 * to an error-shaped result so the loop records it instead of crashing.
 */
export function makeSubprocessLlmFn(opts: { agent?: string; model?: string; cwd?: string; timeoutMs?: number; command?: string }): LlmFn {
  const base = resolveRunCmd()
  return (prompt) =>
    new Promise<LlmResult>((resolve) => {
      const args = [...base.slice(1), "run", "--format", "json"]
      if (opts.model) args.push("--model", opts.model)
      if (opts.command) {
        // invoke a slash-command macro (e.g. council / plan) with `prompt` as its arguments
        args.push("--command", opts.command)
      } else if (opts.agent) {
        args.push("--agent", opts.agent)
      }
      args.push(prompt)

      const child = spawn(base[0], args, { cwd: opts.cwd ?? process.cwd(), env: process.env })
      let buf = ""
      let stderr = ""
      const texts: string[] = []
      let tokensIn = 0
      let tokensOut = 0
      let cost = 0
      const timer = opts.timeoutMs ? setTimeout(() => { try { child.kill("SIGKILL") } catch { /* already gone */ } }, opts.timeoutMs) : undefined

      function consume(line: string) {
        const t = line.trim()
        if (!t) return
        let ev: any
        try { ev = JSON.parse(t) } catch { return } // non-JSON line — ignore
        const part = ev?.part
        if (ev?.type === "text" && typeof part?.text === "string") texts.push(part.text)
        // usage can appear on step-finish parts or an assistant message info block;
        // take the running max so we end with the cumulative turn total.
        const tokens = part?.tokens ?? part?.info?.tokens ?? ev?.info?.tokens
        if (tokens) {
          tokensIn = Math.max(tokensIn, Number(tokens.input) || 0)
          tokensOut = Math.max(tokensOut, Number(tokens.output) || 0)
        }
        const c = part?.cost ?? part?.info?.cost ?? ev?.info?.cost
        if (typeof c === "number") cost = Math.max(cost, c)
      }

      child.stdout.on("data", (d) => {
        buf += d.toString()
        let idx: number
        while ((idx = buf.indexOf("\n")) >= 0) {
          consume(buf.slice(0, idx))
          buf = buf.slice(idx + 1)
        }
      })
      child.stderr.on("data", (d) => { stderr += d.toString() })
      child.on("error", (e) => {
        if (timer) clearTimeout(timer)
        resolve({ output: `[automode: failed to spawn run — ${e.message}. Set OPENHACK_RUN_CMD to override.]`, tokensIn: 0, tokensOut: 0, cost: 0, ok: false, error: `spawn failed: ${e.message}` })
      })
      child.on("close", (code) => {
        if (timer) clearTimeout(timer)
        if (buf.trim()) consume(buf)
        const output = texts.join("\n").trim()
        // A run only counts as real work when it exited cleanly AND produced
        // assistant text. A non-zero/null exit (crash, ROE/spawn abort, or the
        // timeout SIGKILL) or an empty transcript is a FAILURE — otherwise the
        // loop records dead rounds as "successful" (the golecloud.co.za bug).
        if (code !== 0 && !output) {
          resolve({ output: `[run exited ${code}] ${stderr.trim().slice(0, 800)}`, tokensIn, tokensOut, cost, ok: false, error: `run exited ${code}` })
          return
        }
        const ok = code === 0 && output.length > 0
        resolve({
          output: output || stderr.trim(),
          tokensIn,
          tokensOut,
          cost,
          ok,
          error: ok ? undefined : code !== 0 ? `run exited ${code}` : "empty transcript",
        })
      })
    })
}

/**
 * Run any slash-command macro (council / triage / audit / cleanup / findings / …)
 * headlessly from the shell — this is what gives `openhack cmd <name>` full parity
 * with the interactive slash-commands. Blocks on the real `run` session (LLM cost).
 */
export async function runCommandMacro(name: string, args = "", opts: { model?: string; timeoutMs?: number } = {}): Promise<LlmResult> {
  const fn = makeSubprocessLlmFn({ command: name, model: opts.model, timeoutMs: opts.timeoutMs ?? 30 * 60 * 1000 })
  return fn(args)
}

// Pull the first JSON object out of a model transcript, tolerating ```json
// fences and surrounding prose. Returns null when nothing parses.
export function extractJsonObject(text: string): any | null {
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

const GRAPH_JSON_INSTRUCTION =
  `\n\n---\nReturn ONLY a single minified JSON object — no prose, no markdown, no code fences — ` +
  `matching this shape (omit empty arrays):\n` +
  `{"addActions":[{"objective":"...","agent":"recon|exploit|post-exploit|report|general",` +
  `"prompt":"...","priority":1,"score":50,"classId":"...","endpointKey":"...","requires":["action:..."]}],` +
  `"reprioritize":[{"id":"action:...","score":80}],"prune":["action:..."],"rationale":"one line"}`

/**
 * Build the LLM graph controller's `generate` callable from the subprocess `run`
 * bridge. Previously `LoopOptions.graphGenerate` was never populated, so the
 * "AI attack-graph controller" always degraded to the deterministic heuristic
 * (`LlmController.make` returns `HeuristicController.run` when `generate` is
 * absent). This wires a real, cheap model to it: it runs the controller model
 * with a JSON-only instruction and parses the transcript into a `GeneratedUpdate`,
 * returning null on any failure so the controller falls back cleanly.
 */
export function makeGraphGenerate(opts: { model?: string; log?: (m: string) => void } = {}): LlmController.Generate {
  return async ({ system, user, timeoutMs }) => {
    try {
      const fn = makeSubprocessLlmFn({ agent: "general", model: opts.model, timeoutMs })
      const res = await fn(`${system}\n\n${user}${GRAPH_JSON_INSTRUCTION}`)
      if (res.ok === false) {
        opts.log?.(`graphGenerate: controller run failed (${res.error ?? "unknown"}) → heuristic`)
        return null
      }
      const parsed = extractJsonObject(res.output)
      if (!parsed || typeof parsed !== "object") {
        opts.log?.(`graphGenerate: no JSON object in controller output → heuristic`)
        return null
      }
      return parsed as LlmController.GeneratedUpdate
    } catch (e: any) {
      opts.log?.(`graphGenerate: error (${e?.message ?? e}) → heuristic`)
      return null
    }
  }
}

/** Available slash-command macros (from the cwd and the OpenHack repo) for `openhack cmd --list`. */
export function listMacros(): string[] {
  const dirs = [path.join(process.cwd(), ".opencode", "command")]
  if (process.env.HOME) dirs.push(path.join(process.env.HOME, "openhack", ".opencode", "command"))
  const names = new Set<string>()
  for (const d of dirs) {
    try { for (const f of fs.readdirSync(d)) if (f.endsWith(".md")) names.add(f.slice(0, -3)) } catch {}
  }
  return [...names].sort()
}

function loadFindings(target: string): any[] {
  try { return Findings.load(target).findings ?? [] } catch { return [] }
}
function countHighValue(findings: any[]): number {
  return findings.filter((f) => (f.severity === "critical" || f.severity === "high") && f.status !== "false_positive").length
}
function roeBlocked(target: string): { blocked: boolean; reason?: string } {
  try { return ROE.enforce(ROE.load(), target, "task") } catch { return { blocked: false } }
}

export interface LoopOptions {
  ids?: string[]
  maxRounds: number
  model?: string
  outputDir?: string
  /** Hard batch budget in USD; overrides the automode default. */
  costCap?: number
  /** Injectable for tests; defaults to the subprocess runner. */
  makeLlmFn: LlmFactory
  log?: (msg: string) => void
  /** Parallel instances per objective (diverse lenses, each its own context). Default 3. */
  instances?: number
  /** Run same-priority objectives concurrently. Default true. */
  parallel?: boolean
  /** Stop when methodology coverage reaches this % (if coverage data is populated). */
  coverageTarget?: number
  /** Run a council QA review after every round. Default true. */
  council?: boolean
  /** Run a planning step before the first round. Default true. */
  plan?: boolean
  /**
   * Enable the AI-driven attack-graph controller. When on, round 1 uses the static
   * Orchestrators batch (warm start), and rounds 2+ dispatch the top-k frontier the
   * controller produced from the previous round's findings + coverage gaps. Any
   * controller error degrades to the static batch for that round.
   *
   * Reads `graph.controller_enabled` from `.openhack/openhack.jsonc` when not set
   * explicitly here (default off — flag becomes visible on the next release).
   */
  graph?: boolean
  /** Frontier width per round when the graph is active. Default 6. */
  frontierK?: number
  /**
   * Optional generator for the LLM graph controller — the caller (usually the
   * `openhack automode` CLI) resolves it from `Provider.getSmallModel` +
   * `generateObject` from `"ai"`. When absent, the deterministic heuristic
   * controller is used both for warm-up and for graceful fallback.
   */
  graphGenerate?: LlmController.Generate
}

/**
 * Adapter — a per-round observation object handed to the controller. Broken out
 * of `runOrchestrationLoop` so the shape is testable in isolation and so the
 * loop stays readable.
 */
function buildControllerInput(args: {
  target: string
  round: number
  snapshot: ReturnType<typeof AttackGraph.load>
  findings: any[]
  coverageSummary: Coverage.Summary | null
  coverageGaps: ReturnType<typeof Coverage.gaps>
  lastRoundDelta: { newFindings: number; newHigh: number; costUsd: number }
  budgetRemainingUsd: number
}): ControllerInput {
  const findingsForCtrl: FindingLike[] = args.findings.map((f) => ({
    hash: f.hash ?? "",
    severity: f.severity ?? "info",
    status: f.status ?? "uncertain",
    title: f.title ?? "",
    cwe: f.cwe,
    affected_component: f.affected_component,
  }))
  const currentFrontierIds = AttackGraph.frontier(args.snapshot, 100).map((a) => a.id)
  // Combinatorial-coverage checklist — pure derivation from Coverage + Findings +
  // Knowledge. Cheap (< 1 ms on the largest fixture). Feeds the controller the
  // "what combinations are open" view alongside the single-cell gaps.
  let combinationGaps: any = null
  try {
    const report = Combinations.checklist(args.target)
    // Weight each payload gap by the MAX family weight across its missing set
    // and each chain gap by the vulnerable A-leg's severity. Heuristic uses
    // these to bias frontier scores toward high-impact combos.
    const weightRank: Record<string, number> = { high: 3, medium: 2, low: 1 }
    const maxWeightForClass = (classId: string): "high" | "medium" | "low" => {
      let best: "high" | "medium" | "low" = "low"
      for (const f of Knowledge.payloadFamilies(classId)) {
        const w = f.weight ?? "medium"
        if (weightRank[w]! > weightRank[best]!) best = w
      }
      return best === "low" ? "medium" : best
    }
    const maxWeight = (classId: string, missing: string[]): "high" | "medium" | "low" => {
      if (!missing.length) return maxWeightForClass(classId)
      let best: "high" | "medium" | "low" = "low"
      for (const fid of missing) {
        const w = Knowledge.familyWeight(classId, fid)
        if (weightRank[w]! > weightRank[best]!) best = w
      }
      return best
    }
    combinationGaps = {
      methods: report.methods,
      payloads: report.payloads.map((g) => ({ ...g, weight: maxWeight(g.classId, g.missingFamilies) })),
      // Chain weight = the higher of the A/B class' family-weight ceiling.
      chains: report.chains.map((g) => {
        const wa = maxWeightForClass(g.classA)
        const wb = maxWeightForClass(g.classB)
        const w: "high" | "medium" | "low" = weightRank[wa]! >= weightRank[wb]! ? wa : wb
        return { ...g, weight: w }
      }),
      perFinding: report.perFinding,
      universeSize: report.universeSize,
      satisfiedSize: report.satisfiedSize,
    }
  } catch { combinationGaps = null }
  return {
    target: args.target,
    round: args.round,
    snapshot: args.snapshot,
    findings: findingsForCtrl,
    coverageSummary: args.coverageSummary,
    coverageGaps: args.coverageGaps,
    combinationGaps,
    lastRoundDelta: args.lastRoundDelta,
    budgetRemainingUsd: args.budgetRemainingUsd,
    currentFrontierIds,
    // MoE routing threaded into the controller — see
    // `packages/openhack/src/moe-router.ts`. Records usage per expert on every
    // call so `.openhack/moe-stats.json` accumulates the routing history.
    routeAgent: (prompt: string) => {
      try {
        const { expert } = MOERouter.route(prompt)
        return expert.targetAgent
      } catch { return "general" }
    },
  }
}

const PLAN_PROMPT = (t: string) =>
  `Plan the authorized assessment of ${t}. Enumerate the objectives (recon → internal access → PII/pivoting/privesc → chaining), map the vulnerability-class checklist (\`openhack checklist\`) to the expected attack surface, note the current gaps (\`openhack coverage --target ${t} --gaps\`), and produce a prioritized plan. Save it under .openhack/plans/. Plan only — do NOT execute.`

const COUNCIL_PROMPT = (t: string) =>
  `Run the council QA review for ${t} exactly per the /council protocol: read .openhack/findings/, launch council.instances reviewers in parallel (task subagent_type "council") with DISTINCT lenses (defense/skeptic, severity-auditor, gap-analyst), cross-judge (each challenges the others' verdicts), then tally by confidence-weighted majority — confirm/drop only above threshold, ESCALATE splits/low-confidence. Write the outcome + escalated items + new gap vectors to .openhack/reviews/. Base everything on the real findings; never fabricate.`

// Diverse angles for the N parallel instances of an objective — same model, distinct
// lens, each its own subagent context (stands in for cross-model diversity).
const INSTANCE_LENSES = [
  "",
  "\n\n[Instance angle: be maximally exhaustive — try EVERY technique/variant for this objective, not just the obvious one.]",
  "\n\n[Instance angle: think adversarially about CHAINING — for anything you find, ask what it combines with, what was missed, and 'if this is true, what else?']",
  "\n\n[Instance angle: hunt what a scanner misses — business logic, auth/authz nuance, edge cases, second-order effects.]",
]

/**
 * Iterate-until-goal orchestration loop. Each round runs the objective batch grouped
 * by priority (recon → access → post-exploit → chaining), running each priority group
 * — and N diverse instances per objective — CONCURRENTLY, each in its own subagent
 * context. MoE routing is consulted for every objective (recorded per phase). Findings
 * writes are lock-serialized across the parallel subprocesses. Terminates on: coverage
 * target reached, convergence (no new findings/high-value), budget, closed ROE window,
 * or the `maxRounds` cap. Always runs `report` once at the end.
 */
export async function runOrchestrationLoop(target: string, opts: LoopOptions): Promise<Automode.AutomodeSession> {
  const log = opts.log ?? (() => {})
  // Instance fan-out. An explicit `instances` (CLI/config) is honoured uniformly;
  // otherwise a per-agent doctrine cuts the blind ×3 fan-out — high-volume, low-
  // reasoning agents run once, judgment agents twice, deep-reasoning agents up to
  // three — so we stop re-sending three full cold sessions for a port scan.
  const explicitInstances = opts.instances != null
  const instances = Math.max(1, Math.min(6, opts.instances ?? 3))
  const INSTANCE_DOCTRINE: Record<string, number> = {
    recon: 1, osint: 1, report: 1, cleanup: 1,
    council: 2, triage: 2, general: 2, defense: 2, "defense-review": 2, plan: 2, planner: 2,
    exploit: 3, "post-exploit": 3, c2: 3,
  }
  const instancesForTask = (agent?: string): number =>
    explicitInstances ? instances : Math.max(1, Math.min(instances, INSTANCE_DOCTRINE[agent ?? "general"] ?? instances))
  const parallel = opts.parallel !== false
  const council = opts.council !== false
  const plan = opts.plan !== false
  const batch = Orchestrators.buildBatch(target, opts.ids)
  if (batch.length === 0) throw new Error(`No orchestrators matched: ${opts.ids?.join(", ")}`)

  const reportTask = batch.find((t) => t.id === "report")
  const roundTasks = batch.filter((t) => t.id !== "report")
  const priorities = [...new Set(roundTasks.map((t) => t.priority ?? 3))].sort((a, b) => a - b)

  const session = Automode.createSession(batch, target, opts.outputDir, {
    confirm_if_above: Number.MAX_SAFE_INTEGER,
    ...(opts.costCap ? { max_cost_per_batch: opts.costCap } : {}),
  })

  let prevTotal = loadFindings(target).length
  let prevHigh = countHighValue(loadFindings(target))
  log(`Starting from ${prevTotal} findings (${prevHigh} high-value). instances=${explicitInstances ? String(instances) : `doctrine(≤${instances})`} parallel=${parallel} plan=${plan} council=${council}`)

  // Attack-graph controller — opt-in via LoopOptions.graph or `graph.controller_enabled`
  // in .openhack/openhack.jsonc. When active: round 1 uses the static batch (warm start
  // — no observations to graph yet), rounds 2+ dispatch the top-k frontier that the
  // controller produced from the previous round's findings + coverage gaps.
  const graphOn =
    typeof opts.graph === "boolean"
      ? opts.graph
      : Boolean((ConfigStore.get("graph.controller_enabled") as unknown as boolean) ?? false)
  const frontierK = Math.max(1, Math.min(20, opts.frontierK ?? 6))
  const graphSnapshot = graphOn ? AttackGraph.load(target) : null
  const controller: Controller | null = graphOn
    ? LlmController.make({ generate: opts.graphGenerate, logger: (m) => log(`  ${m}`) })
    : null
  if (graphSnapshot) {
    // Seed with the static batch's actions + already-known findings + coverage gaps.
    // Idempotent: repeat runs simply update lastSeenRound and reuse existing ids.
    const seedActions = roundTasks.map((t) => AttackGraph.toActionNode(t as any, 1))
    const initFindings: FindingLike[] = loadFindings(target).map((f: any) => ({
      hash: f.hash ?? "", severity: f.severity ?? "info", status: f.status ?? "uncertain",
      title: f.title ?? "", cwe: f.cwe, affected_component: f.affected_component,
    }))
    let initGaps: Awaited<ReturnType<typeof Coverage.gaps>> = []
    try { initGaps = Coverage.gaps(Coverage.load(target)) } catch {}
    AttackGraph.withLock(target, () => {
      AttackGraph.seed(graphSnapshot, 1, seedActions, initFindings, initGaps)
      AttackGraph.save(graphSnapshot)
    })
    log(`  graph: seeded ${Object.keys(graphSnapshot.nodes).length} nodes (frontierK=${frontierK})`)
  }

  // Dispatch one objective instance: consult MoE (records routing every phase), apply
  // the instance lens, and execute. A distinct id per instance keeps result files apart.
  //
  // Two dispatch modes:
  //  • Normal agent dispatch — `task.agent` names a specialist; the factory
  //    resolves the model via `resolveModelForAgent` and spawns `run --agent X`.
  //  • Macro dispatch — `task.command` names a slash-command macro (e.g.
  //    "council", "triage", "plan"); the factory spawns `run --command X` so
  //    the .opencode/command/<X>.md file is the single source of truth for the
  //    protocol. Introduced by the loop-graph hybrid — see AGENTS.md.
  const runInstance = async (task: Automode.TaskSpec, i: number) => {
    let agent = task.agent
    try {
      const { expert, confidence } = MOERouter.route(task.prompt)
      if (!agent) agent = expert.targetAgent
      log(`    moe ${task.id}#${i + 1} → ${expert.name} (${confidence.toFixed(2)}) agent=${agent}${task.command ? ` command=${task.command}` : ""}`)
    } catch {}
    const lens = INSTANCE_LENSES[i % INSTANCE_LENSES.length]
    const variant: Automode.TaskSpec = i === 0 ? task : { ...task, id: `${task.id}#${i + 1}`, prompt: task.prompt + lens }
    // Per-task model resolution: explicit tier hint > agent doctrine > loop default.
    let taskModel: string | undefined
    try {
      taskModel = task.agent_tier ? GlobalConfig.tierModel(task.agent_tier) : GlobalConfig.resolveForAgent(agent)
    } catch {}
    const llmFn = task.command
      ? opts.makeLlmFn({ command: task.command, model: taskModel, agent })
      : opts.makeLlmFn({ agent, model: taskModel })
    await Automode.executeTask(variant, session, llmFn)
  }

  // Planning phase (default on): produce a prioritized plan before executing.
  // Prefer the `/plan` slash-command macro so the protocol lives in one place
  // (`.opencode/command/plan.md` if present); fall back to the inline
  // PLAN_PROMPT paraphrase when the macro isn't available or errors out.
  if (plan) {
    log(`  ▶ planning (plan agent)`)
    let macroOk = false
    try {
      if (listMacros().includes("plan")) {
        const t0 = Date.now()
        const r = await runCommandMacro("plan", target, { model: GlobalConfig.resolveForAgent("plan") })
        macroOk = !!r.output && !r.output.includes("[Not executed")
        log(`    plan macro: ${macroOk ? "ok" : "no-op"} · ${Date.now() - t0}ms`)
      }
    } catch (e: any) {
      log(`    plan macro error (soft): ${e?.message ?? e}`)
    }
    if (!macroOk) {
      await Automode.executeTask({ id: "planning", prompt: PLAN_PROMPT(target), agent: "plan", priority: 0 }, session, opts.makeLlmFn("plan"))
    }
  }

  let round = 0
  let prevCost = 0
  // Adaptive round budget: the caller-supplied `opts.maxRounds` is the starting
  // ceiling but the loop can extend it up to `RoundBudget.hardCeiling` if the
  // last round was productive AND remaining budget covers another round.
  // `budgetCap` is mutated in-place at end-of-round when the budget grants an
  // extension. `openhack automode --loop --max-rounds 3 --graph` therefore
  // now runs 3 rounds MINIMUM but may run more when the pentest is still
  // clearly making progress. Disabled by `round_budget.adaptive=false` in
  // `.openhack/openhack.jsonc` — the old fixed ceiling is preserved.
  const rbCfg = RoundBudget.config()
  const adaptiveOn = (ConfigStore.get("round_budget.adaptive") as unknown as boolean | undefined) !== false
  let budgetCap = opts.maxRounds
  while (round < budgetCap) {
    round++
    log(`── Round ${round}/${budgetCap}${budgetCap > opts.maxRounds ? ` (extended from ${opts.maxRounds})` : ""} ──`)

    // Choose this round's task set:
    //  - Round 1 (or graph off): the static Orchestrators batch (warm start).
    //  - Rounds 2+ with graph on: the top-k queued frontier the controller shaped
    //    from the previous round. If the frontier is empty for any reason (e.g. the
    //    controller returned nothing), fall back to the static batch so we never
    //    starve a round.
    let activeTasks: Automode.TaskSpec[] = roundTasks
    if (graphSnapshot && round > 1) {
      const front = AttackGraph.frontier(graphSnapshot, frontierK)
      if (front.length) {
        activeTasks = front.map((a) => {
          const spec = AttackGraph.toTaskSpec(a)
          return { id: spec.id, prompt: spec.prompt, agent: spec.agent, priority: spec.priority } as Automode.TaskSpec
        })
        // Mark dispatched so the frontier doesn't re-emit these next round.
        AttackGraph.withLock(target, () => {
          AttackGraph.apply(graphSnapshot, {
            addNodes: [], addEdges: [], reprioritize: [], prune: [],
            dispatch: front.map((a) => a.id), rationale: `dispatched round ${round}`,
          }, round)
          AttackGraph.save(graphSnapshot)
        })
        log(`  graph: dispatching ${activeTasks.length} frontier action(s)`)
      } else {
        log(`  graph: empty frontier — falling back to static batch`)
      }
    }

    const activePriorities = [...new Set(activeTasks.map((t) => t.priority ?? 3))].sort((a, b) => a - b)
    for (const pri of activePriorities) {
      const group = activeTasks.filter((t) => (t.priority ?? 3) === pri)
      const jobs = group.flatMap((task) => Array.from({ length: instancesForTask(task.agent) }, (_, i) => ({ task, i })))
      log(`  phase p${pri}: ${group.map((g) => `${g.id}×${instancesForTask(g.agent)}`).join(", ")}`)
      if (parallel) {
        await Promise.all(jobs.map((j) => runInstance(j.task, j.i).catch((e) => log(`    ! ${j.task.id}#${j.i + 1}: ${e?.message}`))))
      } else {
        for (const j of jobs) {
          await runInstance(j.task, j.i)
          if (session.status === "cost_limited") break
        }
      }
      if (session.status === "cost_limited") { log("  budget reached mid-round"); break }
    }

    // Council QA after every round (default on): multi-instance cross-judging review
    // of the round's findings — confirm/drop/escalate before the next round builds on them.
    if (council && session.status !== "cost_limited") {
      log(`  ▶ council review (round ${round})`)
      let macroOk = false
      try {
        if (listMacros().includes("council")) {
          const t0 = Date.now()
          const r = await runCommandMacro("council", target, { model: GlobalConfig.resolveForAgent("council") })
          macroOk = !!r.output && !r.output.includes("[Not executed")
          log(`    council macro: ${macroOk ? "ok" : "no-op"} · ${Date.now() - t0}ms`)
        }
      } catch (e: any) {
        log(`    council macro error (soft): ${e?.message ?? e}`)
      }
      if (!macroOk) {
        await Automode.executeTask({ id: `council-r${round}`, prompt: COUNCIL_PROMPT(target), agent: "general", priority: 90 }, session, opts.makeLlmFn("general"))
      }
    }

    const findings = loadFindings(target)
    const total = findings.length
    const high = countHighValue(findings)
    const newFindings = total - prevTotal
    const newHigh = high - prevHigh
    let cov: Coverage.Summary | null = null
    try { cov = Coverage.summary(Coverage.load(target)) } catch {}
    log(`  round ${round}: +${newFindings} findings (+${newHigh} high-value); cost $${session.totalCost.toFixed(2)}${cov && cov.cells ? `; coverage ${cov.percent}%` : ""}`)

    // Attack-graph controller — after the round's observations are in, before the
    // termination checks. Feeds the delta forward so rounds 2+ can dispatch a
    // frontier shaped by what actually happened. Every failure mode (throw /
    // timeout / schema error / empty response) degrades to the deterministic
    // heuristic inside LlmController; controller errors here are soft.
    if (graphSnapshot && controller) {
      const t0 = Date.now()
      try {
        let gaps: Awaited<ReturnType<typeof Coverage.gaps>> = []
        try { gaps = Coverage.gaps(Coverage.load(target)).slice(0, 40) } catch {}
        const budgetLeft = Math.max(0, session.costConfig.max_cost_per_batch - session.totalCost)
        const input = buildControllerInput({
          target, round, snapshot: graphSnapshot, findings,
          coverageSummary: cov, coverageGaps: gaps,
          lastRoundDelta: { newFindings, newHigh, costUsd: session.totalCost - prevCost },
          budgetRemainingUsd: budgetLeft,
        })
        const update = await controller(input)
        const { keptAddNodes, addEdges: policyEdges } = Frontier.pruneAndAnnotateEdges(update.addNodes, target, round)
        AttackGraph.withLock(target, () => {
          AttackGraph.apply(graphSnapshot, {
            ...update,
            addNodes: keptAddNodes,
            addEdges: [...update.addEdges, ...policyEdges],
          }, round)
          AttackGraph.gc(graphSnapshot, round)
          AttackGraph.save(graphSnapshot)
        })
        const blockedCount = keptAddNodes.filter((n: any) => n.status === "blocked").length
        log(`  graph: +${update.addNodes.length}n +${update.addEdges.length}e -${update.prune.length}p; blocked=${blockedCount}; ${Date.now() - t0}ms`)
      } catch (e: any) {
        log(`  graph controller error (soft): ${e?.message ?? e}`)
      }
    }
    // Per-round telemetry — one JSONL line per round to .openhack/rounds/<target>.jsonl.
    // This is the source-of-truth stream a post-hoc analyzer or the bench harness reads
    // to visualize convergence, cost, controller latency, and combo-close rate across
    // rounds without having to reconstruct anything from opaque log lines.
    try {
      const roundsDir = path.join(".openhack", "rounds")
      fs.mkdirSync(roundsDir, { recursive: true })
      const safeTgt = target.replace(/[^a-zA-Z0-9.-]/g, "_")
      const rec = {
        target, round, at: new Date().toISOString(),
        findingsTotal: total, findingsHigh: high,
        newFindings, newHigh,
        totalCostUsd: session.totalCost,
        roundCostUsd: session.totalCost - prevCost,
        coverage: cov ? { endpoints: cov.endpoints, cells: cov.cells, tested: cov.tested, percent: cov.percent, vulnerable: cov.vulnerable } : null,
        combos: (() => {
          try {
            const r = Combinations.checklist(target)
            return { open: r.methods.length + r.payloads.length + r.chains.length, universeSize: r.universeSize, satisfiedSize: r.satisfiedSize }
          } catch { return null }
        })(),
        frontierSize: graphSnapshot ? AttackGraph.frontier(graphSnapshot, 100).length : 0,
        rssMb: Math.round((process.memoryUsage().rss / 1024 / 1024) * 10) / 10,
      }
      fs.appendFileSync(path.join(roundsDir, `${safeTgt}.jsonl`), JSON.stringify(rec) + "\n")
    } catch {}

    // Graph-controller score persistence — record what agent kinds were
    // dispatched this round and what deltas they produced. Cross-run: on the
    // NEXT session's round 1 the heuristic already has priors from every kind
    // that produced findings before. Failure is soft: we never break the loop
    // to record a stat.
    if (graphSnapshot) {
      try {
        const dispatchedKinds = activeTasks.map((t) => t.agent).filter((a): a is string => typeof a === "string" && a.length > 0)
        if (dispatchedKinds.length > 0) {
          const store = Scores.load(target)
          Scores.record(store, {
            roundNumber: round,
            dispatchedKinds,
            newFindings,
            newHigh,
            roundCostUsd: session.totalCost - prevCost,
          })
          Scores.save(store)
        }
      } catch (e: any) {
        log(`  scores: soft error — ${e?.message ?? e}`)
      }
    }

    prevCost = session.totalCost

    if (session.status === "cost_limited") { log("Terminating: batch budget reached."); break }
    const roe = roeBlocked(target)
    if (roe.blocked) { log(`Terminating: ROE window closed — ${roe.reason}`); break }
    if (opts.coverageTarget && cov && cov.cells > 0 && cov.percent >= opts.coverageTarget) {
      log(`Terminating: coverage target ${opts.coverageTarget}% reached (${cov.percent}%).`)
      break
    }
    // Graph-frontier termination: if the controller has no more work AND the
    // methodology has no untested cells left AND every combinatorial-coverage
    // axis is closed (methods, payload families, chain-pairs), we're done —
    // even if convergence hasn't decided we are. The combinatorial checks make
    // this stricter than before: we don't declare "done" while the checklist
    // still has "GET was tested but not POST/DELETE" style holes.
    if (graphSnapshot) {
      const frontLeft = AttackGraph.frontier(graphSnapshot, 1).length
      let gapsLeft = 0
      try { gapsLeft = Coverage.gaps(Coverage.load(target)).length } catch {}
      let comboGapsLeft = 0
      let universe = 0
      try {
        const r = Combinations.checklist(target)
        comboGapsLeft = r.methods.length + r.payloads.length + r.chains.length
        universe = r.universeSize
      } catch {}
      if (frontLeft === 0 && gapsLeft === 0 && comboGapsLeft === 0) {
        // All three axes empty is only a *clean* completion when there was real
        // discovery. When nothing was ever found (0 findings, 0 coverage cells,
        // 0-combo universe) the three counters are ALSO zero — that is a no-op
        // engagement (scanners unreachable / ROE blocked / target down), not a
        // finished assessment. Terminate distinctly so the summary stays honest.
        const discovered = total > 0 || (cov?.cells ?? 0) > 0 || universe > 0
        if (discovered) {
          log("Terminating: attack graph frontier + coverage gaps + combinatorial checklist all empty.")
        } else {
          session.status = "no_discovery"
          log("Terminating: no attack surface discovered (0 findings, 0 coverage cells). NOT a clean completion — check MCP scanners / ROE / target reachability.")
        }
        break
      }
    }
    // Adaptive termination + extension: consults RoundBudget which reads the
    // per-round JSONL we just appended (so it sees this round's delta) and
    // returns a verdict. It replaces the old fixed
    // `if (newHigh <= 0 && newFindings <= 0) break` — that check missed rounds
    // where nothing was found but combos closed, and it also never granted an
    // extension when progress was still real. Legacy behavior available via
    // `round_budget.adaptive = false`.
    if (adaptiveOn) {
      const recs = RoundBudget.readRoundLog(target)
      const v = RoundBudget.verdict(recs, rbCfg)
      if (v.terminate) {
        log(`Terminating: ${v.reason ?? "converged"} (dry=${v.dryStreak}, combosClosed=${v.combosClosed}).`)
        break
      }
      // Extension check: if we're at or past the caller ceiling but the last
      // round was productive AND budget headroom permits it, bump budgetCap +1
      // and keep going. Bounded by `round_budget.hard_ceiling`.
      if (round >= budgetCap) {
        const remaining = Math.max(0, session.costConfig.max_cost_per_batch - session.totalCost)
        const ex = RoundBudget.shouldExtend({ currentRound: round, callerMaxRounds: budgetCap, records: recs, remainingBudgetUsd: remaining, cfg: rbCfg })
        if (ex.extend) {
          log(`Extending: ${ex.reason} → maxRounds=${ex.newMax}`)
          budgetCap = ex.newMax
        } else {
          log(`Not extending: ${ex.reason}`)
        }
      }
    } else {
      // Legacy fixed-ceiling behavior.
      if (newHigh <= 0 && newFindings <= 0) { log("Terminating: converged — no new vectors this round."); break }
    }

    prevTotal = total
    prevHigh = high
  }

  if (reportTask) {
    log(`  ▶ ${reportTask.id} (${reportTask.agent})`)
    await Automode.executeTask(reportTask, session, opts.makeLlmFn(reportTask.agent))
  }

  session.endTime = new Date().toISOString()
  if (session.status === "running") {
    // Catch-all for the non-graph / adaptive-convergence exit paths: a run that
    // discovered nothing (0 findings, 0 coverage cells) is `no_discovery`, not a
    // clean `completed`. See the in-loop graph-frontier guard for the rationale.
    const finalFindings = loadFindings(target)
    let finalCells = 0
    try { finalCells = Coverage.summary(Coverage.load(target)).cells } catch {}
    session.status = finalFindings.length > 0 || finalCells > 0 ? "completed" : "no_discovery"
  }
  Automode.saveSummary(session)
  Automode.saveLog(session)
  Automode.saveCheckpoint(session)
  return session
}

/**
 * CLI entry for the `openhack automode` subcommand. Modes:
 *  --orchestrate            → write specialized objective files (plan only; honest, no fake run)
 *  --orchestrate --execute  → run one round of the orchestrators for real
 *  --loop [--max-rounds N]  → iterate-until-goal (implies orchestrate+execute over --target)
 *  --batch/--prompts        → task list; with --execute runs them for real, else lists them
 */
export async function runAutomodeCli(argv: any): Promise<void> {
  // Default `--model` from GlobalConfig when unset — closes the long-standing
  // no-op where `openhack model --set X` was silently ignored by automode.
  // Explicit `--model` on the CLI still wins.
  let defaultModel: string | undefined
  try { defaultModel = GlobalConfig.main() } catch {}
  const model: string | undefined = argv.model ?? defaultModel
  const timeoutMs = argv.timeout ? Number(argv.timeout) * 1000 : 30 * 60 * 1000
  // Factory accepts either a bare agent string (backward-compat) OR a
  // {agent, command, model} opts bag (loop-graph hybrid path). When `command`
  // is set, spawns `run --command <name>` — dispatching a slash-command macro.
  const makeLlmFn: LlmFactory = (agentOrOpts) => {
    const opts = typeof agentOrOpts === "string" || agentOrOpts == null
      ? { agent: agentOrOpts ?? undefined }
      : agentOrOpts
    return makeSubprocessLlmFn({ agent: opts.agent, model: opts.model ?? model, command: opts.command, timeoutMs })
  }

  // ── Orchestrator modes (loop / execute / plan) ────────────────────────────
  if (argv.loop || argv.orchestrate) {
    const target: string | undefined = argv.target
    if (!target) { out("Use --target <target> with --orchestrate/--loop"); return }
    const ids = argv.objectives
      ? String(argv.objectives).split(",").map((s: string) => s.trim()).filter(Boolean)
      : undefined

    // Plan-only (no --execute, no --loop): honest objective files, nothing faked.
    if (!argv.execute && !argv.loop) {
      const batch = Orchestrators.buildBatch(target, ids)
      if (batch.length === 0) { out(`No orchestrators matched: ${argv.objectives}`); return }
      const outputDir = argv.output || `.openhack/automode-results/${target.replace(/[^a-zA-Z0-9.-]/g, "_")}`
      if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true })
      for (const t of batch) {
        const file = `${outputDir}/${t.id}.objective.md`
        fs.writeFileSync(file, `# Objective: ${t.id}  (subagent: ${t.agent})\n\nRun for real with:  openhack automode --target ${target} --execute\nor dispatch manually:  task(subagent_type: "${t.agent}", prompt: <below>)\n\n---\n\n${t.prompt}\n`)
        out(`  ${t.id} → ${file}`)
      }
      fs.writeFileSync(`${outputDir}/orchestration-plan.md`, `# Orchestration plan for ${target}\n\nExecute: openhack automode --target ${target} --loop\n\n${batch.map((t: any, i: number) => `${i + 1}. ${t.id} → ${t.agent}`).join("\n")}\n`)
      out(`Wrote ${batch.length} objectives to ${outputDir}. Run for real with --execute (single round) or --loop (iterate-until-goal).`)
      return
    }

    const maxRounds = argv.loop ? Math.max(1, Number(argv["max-rounds"] ?? argv.maxRounds ?? 3)) : 1
    out(`Automode: executing ${target} (${argv.loop ? `loop, ≤${maxRounds} rounds` : "single round"})…`)
    const cfgInstances = Number(ConfigStore.get("automode.instances") ?? 0) || undefined
    const cfgCoverage = Number(ConfigStore.get("automode.coverage_target") ?? 0) || undefined
    // Resolve the graph controller's model: explicit `graph.controller_model`,
    // else the cheap "fast" tier (haiku) — a small model is plenty for the
    // once-per-round GraphUpdate and keeps the controller call inexpensive.
    let controllerModel: string | undefined
    try { controllerModel = (ConfigStore.get("graph.controller_model") as unknown as string | undefined) || GlobalConfig.fast() } catch {}
    const session = await runOrchestrationLoop(target, {
      ids, maxRounds, model, outputDir: argv.output,
      costCap: argv["cost-cap"] ? Number(argv["cost-cap"]) : undefined,
      instances: argv.instances != null ? Number(argv.instances) : cfgInstances,
      parallel: argv.parallel !== false,
      coverageTarget: argv["coverage-target"] != null ? Number(argv["coverage-target"]) : cfgCoverage,
      council: argv.council !== false,
      plan: argv.plan !== false,
      graph: argv.graph === true ? true : argv.graph === false ? false : undefined,
      frontierK: argv["frontier-k"] != null ? Number(argv["frontier-k"]) : undefined,
      graphGenerate: makeGraphGenerate({ model: controllerModel, log: out }),
      makeLlmFn, log: out,
    })
    const findings = loadFindings(target)
    out(`Done. status=${session.status}, ${session.results.length} objective runs, $${session.totalCost.toFixed(2)}, ${findings.length} findings (${countHighValue(findings)} high-value).`)
    out(`Results: ${session.outputDir}  ·  Findings: .openhack/findings/`)
    return
  }

  // ── Task-list modes (--batch / --prompts) ─────────────────────────────────
  let tasks: Automode.TaskSpec[] = []
  if (argv.batch) {
    if (!fs.existsSync(argv.batch)) { out(`Not found: ${argv.batch}`); return }
    tasks = Automode.parseBatchJSON(argv.batch).tasks || []
  } else if (argv.prompts) {
    if (!fs.existsSync(argv.prompts)) { out(`Not found: ${argv.prompts}`); return }
    tasks = Automode.parseTasksFile(argv.prompts)
  } else { out("Use --batch/--prompts (task list) or --target with --orchestrate/--loop"); return }

  if (tasks.length === 0) { out("No tasks parsed."); return }

  if (!argv.execute) {
    out(`${tasks.length} tasks parsed (dry run — add --execute to run them for real):`)
    for (const t of tasks) out(`  ${t.id}: ${t.prompt.slice(0, 80)}`)
    return
  }

  const session = Automode.createSession(tasks, argv.target, argv.output, { confirm_if_above: Number.MAX_SAFE_INTEGER })
  out(`Automode: executing ${tasks.length} tasks for real…`)
  for (const t of session.tasks) {
    out(`  ▶ ${t.id}`)
    await Automode.executeTask(t, session, makeLlmFn(t.agent))
    if (session.status === "cost_limited") { out("  budget reached"); break }
  }
  session.endTime = new Date().toISOString()
  if (session.status === "running") session.status = "completed"
  Automode.saveSummary(session)
  Automode.saveLog(session)
  out(`Done. status=${session.status}, ${session.results.length} results, $${session.totalCost.toFixed(2)} → ${session.outputDir}`)
}
