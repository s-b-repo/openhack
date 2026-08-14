import * as fs from "node:fs"
import * as path from "node:path"
import { ModelCosts } from "../model-costs"

export namespace Automode {
  export interface TaskSpec {
    id: string
    prompt: string
    agent?: string
    timeout?: number
    priority?: number       // 1=highest, 5=lowest
    save?: string
    cost_estimate?: number
    /**
     * Slash-command macro name (e.g. "council", "triage", "plan"). When set,
     * the loop dispatches this task via `runCommandMacro(command, prompt)`
     * instead of the agent path — so the single source of truth for the
     * protocol is `.openhack/command/<command>.md`.
     *
     * Consumed one level up in `runInstance`; `executeTask` itself doesn't
     * read this field (the dispatch decision happens at the CLI boundary).
     */
    command?: string
    /**
     * Per-task tier hint override — resolved by `GlobalConfig.resolveForAgent`
     * one level up. Set to "cheap" for recon-adjacent objectives, "main" for
     * exploit work, etc. Absent → the agent's doctrine tier is used.
     */
    agent_tier?: "main" | "fast" | "cheap" | "draft"
  }

  export interface BatchConfig {
    target?: string
    tasks: TaskSpec[]
  }

  export interface TaskResult {
    id: string
    prompt: string
    output: string
    error?: string
    startTime: string
    endTime: string
    durationMs: number
    success: boolean
    costActual?: number
    tokensUsed?: { input: number; output: number }
    save?: string
  }

  export interface CostConfig {
    max_cost_per_batch: number
    max_cost_per_task: number
    confirm_if_above: number
    cheap_model_for_planning: string
    expensive_model_for_exploitation: string
    token_budget_per_task: number
  }

  export interface Checkpoint {
    batchId: string
    target?: string
    startTime: string
    lastCheckpoint: string
    outputDir: string
    completedTasks: TaskResult[]
    pendingTasks: TaskSpec[]
    currentTask?: TaskSpec
    totalCostSoFar: number
    totalTokensSoFar: number
  }

  export interface AutomodeSession {
    batchId: string
    target?: string
    startTime: string
    endTime?: string
    tasks: TaskSpec[]
    results: TaskResult[]
    outputDir: string
    costConfig: CostConfig
    totalCost: number
    totalTokens: number
    // `no_discovery` = the loop ran to a natural stop but nothing was ever found
    // (0 findings, 0 coverage cells). It is NOT a clean "completed" — it usually
    // means the MCP scanners weren't reachable, the ROE blocked everything, or the
    // target was unreachable. Kept distinct so summaries can't claim a clean run.
    status: "running" | "paused" | "completed" | "failed" | "cost_limited" | "no_discovery"
  }

  const DEFAULT_COST_CONFIG: CostConfig = {
    max_cost_per_batch: 10.0,
    max_cost_per_task: 2.5,
    confirm_if_above: 5.0,
    cheap_model_for_planning: "anthropic/claude-haiku-4-5",
    expensive_model_for_exploitation: "anthropic/claude-sonnet-4",
    token_budget_per_task: 100000,
  }

  export function parseBatchJSON(filepath: string): BatchConfig {
    const raw = fs.readFileSync(filepath, "utf-8")
    return JSON.parse(raw) as BatchConfig
  }

  export function parseTasksFile(filepath: string): TaskSpec[] {
    const raw = fs.readFileSync(filepath, "utf-8")
    const tasks: TaskSpec[] = []
    let index = 1

    const blocks = raw.split(/\n\s*\n/)
    for (const block of blocks) {
      const trimmed = block.trim()
      if (trimmed.length === 0 || trimmed.startsWith("#")) continue

      tasks.push({
        id: `task-${String(index).padStart(3, "0")}`,
        prompt: trimmed,
        priority: 3,
      })
      index++
    }

    return tasks
  }

  export function sortByPriority(tasks: TaskSpec[]): TaskSpec[] {
    return [...tasks].sort((a, b) => (a.priority || 3) - (b.priority || 3))
  }

  export function estimateCost(task: TaskSpec, model: string): number {
    // Shared rate table (see model-costs.ts) — one source of truth for the
    // pre-flight confirm gate and the MoE cost hint.
    return Math.round(ModelCosts.estimateUsd(model, task.prompt.length) * 100) / 100
  }

  export function createSession(
    tasks: TaskSpec[],
    target?: string,
    outputDir?: string,
    costConfig?: Partial<CostConfig>,
  ): AutomodeSession {
    const now = new Date().toISOString()
    const batchId = `batch-${Date.now()}`
    const targetDir = target ? target.replace(/[^a-zA-Z0-9.-]/g, "_") : `session-${Date.now()}`
    const sortedTasks = sortByPriority(tasks)

    const config = { ...DEFAULT_COST_CONFIG, ...costConfig }
    let totalEstimate = 0
    for (const task of sortedTasks) {
      task.cost_estimate = estimateCost(task, config.cheap_model_for_planning)
      totalEstimate += task.cost_estimate!
    }

    if (totalEstimate > config.confirm_if_above) {
      throw new Error(
        `Batch cost estimate: $${totalEstimate.toFixed(2)} exceeds confirmation threshold of $${config.confirm_if_above.toFixed(2)}. Use --confirm to proceed.`,
      )
    }

    return {
      batchId,
      target,
      startTime: now,
      tasks: sortedTasks,
      results: [],
      outputDir: outputDir || path.join(".openhack", "automode-results", targetDir),
      costConfig: config,
      totalCost: 0,
      totalTokens: 0,
      status: "running",
    }
  }

  export function saveTaskResult(session: AutomodeSession, result: TaskResult): void {
    session.results.push(result)
    session.totalCost += result.costActual || 0
    session.totalTokens += (result.tokensUsed?.input || 0) + (result.tokensUsed?.output || 0)

    if (!fs.existsSync(session.outputDir)) {
      fs.mkdirSync(session.outputDir, { recursive: true })
    }

    const filename = result.save || `${result.id}-result.md`
    const filepath = path.join(session.outputDir, filename)

    const content = `# ${result.id}: ${result.prompt.slice(0, 80)}${result.prompt.length > 80 ? "..." : ""}

**Status**: ${result.success ? "SUCCESS" : "FAILED"}
**Duration**: ${(result.durationMs / 1000).toFixed(1)}s
**Cost**: $${(result.costActual || 0).toFixed(4)}
**Tokens**: ${(result.tokensUsed?.input || 0) + (result.tokensUsed?.output || 0)}
**Started**: ${result.startTime}
**Completed**: ${result.endTime}

${result.error ? `## Error\n\`\`\`\n${result.error}\n\`\`\`\n` : ""}

## Output

${result.output}
`
    fs.writeFileSync(filepath, content, "utf-8")
  }

  export function saveCheckpoint(session: AutomodeSession, currentTask?: TaskSpec): void {
    if (!fs.existsSync(session.outputDir)) {
      fs.mkdirSync(session.outputDir, { recursive: true })
    }

    const checkpoint: Checkpoint = {
      batchId: session.batchId,
      target: session.target,
      startTime: session.startTime,
      lastCheckpoint: new Date().toISOString(),
      outputDir: session.outputDir,
      completedTasks: session.results,
      pendingTasks: session.tasks.slice(session.results.length),
      currentTask,
      totalCostSoFar: session.totalCost,
      totalTokensSoFar: session.totalTokens,
    }

    fs.writeFileSync(
      path.join(session.outputDir, "checkpoint.json"),
      JSON.stringify(checkpoint, null, 2),
      "utf-8",
    )
  }

  export function loadCheckpoint(outputDir: string): Checkpoint | null {
    const checkpointPath = path.join(outputDir, "checkpoint.json")
    if (!fs.existsSync(checkpointPath)) return null
    try {
      return JSON.parse(fs.readFileSync(checkpointPath, "utf-8"))
    } catch {
      return null
    }
  }

  export function restoreFromCheckpoint(checkpoint: Checkpoint, costConfig?: Partial<CostConfig>): AutomodeSession {
    const config = { ...DEFAULT_COST_CONFIG, ...costConfig }
    return {
      batchId: checkpoint.batchId,
      target: checkpoint.target,
      startTime: checkpoint.startTime,
      tasks: [...checkpoint.pendingTasks],
      results: [...checkpoint.completedTasks],
      outputDir: checkpoint.outputDir,
      costConfig: config,
      totalCost: checkpoint.totalCostSoFar,
      totalTokens: checkpoint.totalTokensSoFar,
      status: "running",
    }
  }

  export function checkCostLimit(session: AutomodeSession, result: TaskResult): boolean {
    if (session.totalCost + (result.costActual || 0) > session.costConfig.max_cost_per_batch) {
      session.status = "cost_limited"
      return false
    }
    if ((result.costActual || 0) > session.costConfig.max_cost_per_task) {
      result.error = `Task cost $${result.costActual?.toFixed(2)} exceeds per-task limit of $${session.costConfig.max_cost_per_task.toFixed(2)}`
      return true
    }
    return true
  }

  export function saveLog(session: AutomodeSession): void {
    if (!fs.existsSync(session.outputDir)) {
      fs.mkdirSync(session.outputDir, { recursive: true })
    }

    fs.writeFileSync(
      path.join(session.outputDir, "automode-log.json"),
      JSON.stringify({
        batchId: session.batchId,
        target: session.target,
        startTime: session.startTime,
        endTime: session.endTime,
        status: session.status,
        taskCount: session.tasks.length,
        successCount: session.results.filter((r) => r.success).length,
        failCount: session.results.filter((r) => !r.success).length,
        totalDurationMs: session.results.reduce((sum, r) => sum + r.durationMs, 0),
        totalCost: session.totalCost,
        totalTokens: session.totalTokens,
        results: session.results.map((r) => ({
          id: r.id,
          success: r.success,
          durationMs: r.durationMs,
          cost: r.costActual,
          error: r.error || undefined,
        })),
      }, null, 2),
      "utf-8",
    )

    fs.writeFileSync(
      path.join(session.outputDir, "automode-cost.json"),
      JSON.stringify({
        batchCost: session.totalCost,
        batchTokens: session.totalTokens,
        perTask: session.results.map((r) => ({
          id: r.id,
          cost: r.costActual || 0,
          tokens: r.tokensUsed || { input: 0, output: 0 },
        })),
        limits: session.costConfig,
      }, null, 2),
      "utf-8",
    )
  }

  export function saveSummary(session: AutomodeSession): void {
    if (!fs.existsSync(session.outputDir)) {
      fs.mkdirSync(session.outputDir, { recursive: true })
    }

    const successCount = session.results.filter((r) => r.success).length
    const failCount = session.results.filter((r) => !r.success).length

    let summary = `# Automode Summary: ${session.target || "Session"}

**Date**: ${session.startTime}
**Status**: ${session.status}
**Total Tasks**: ${session.tasks.length}
**Successful**: ${successCount}
**Failed**: ${failCount}
**Total Duration**: ${(session.results.reduce((sum, r) => sum + r.durationMs, 0) / 1000).toFixed(1)}s
**Total Cost**: $${session.totalCost.toFixed(4)}
**Total Tokens**: ${session.totalTokens}

## Task Results

| ID | Task | Status | Duration | Cost |
|---|---|---|---|---|
`

    for (const result of session.results) {
      const taskPrompt = result.prompt.slice(0, 60)
      summary += `| ${result.id} | ${taskPrompt}${result.prompt.length > 60 ? "..." : ""} | ${result.success ? "OK" : "FAIL"} | ${(result.durationMs / 1000).toFixed(1)}s | $${(result.costActual || 0).toFixed(3)} |\n`
    }

    if (failCount > 0) {
      summary += `\n## Errors\n\n`
      for (const result of session.results.filter((r) => r.error)) {
        summary += `### ${result.id}\n\`\`\`\n${result.error}\n\`\`\`\n\n`
      }
    }

    fs.writeFileSync(path.join(session.outputDir, "automode-summary.md"), summary, "utf-8")
  }

  // Output shapes the subprocess runner emits when a run failed but resolved
  // (rather than threw). Used as a fallback when a runner didn't set `ok`.
  const FAILED_OUTPUT = /^\[(?:run exited|automode: failed)/

  export async function executeTask(
    task: TaskSpec,
    session: AutomodeSession,
    llmFn?: (
      prompt: string,
    ) => Promise<{ output: string; tokensIn: number; tokensOut: number; cost: number; ok?: boolean; error?: string }>,
  ): Promise<TaskResult> {
    const start = Date.now()
    const startISO = new Date().toISOString()
    try {
      if (!llmFn) {
        // Be honest: there is no LLM runner in a one-shot CLI context, so the task
        // was NOT executed. Report it as such rather than faking success — live
        // execution happens via the /automode macro (real subagents).
        return {
          id: task.id, prompt: task.prompt,
          output: "[Not executed — no LLM runner in this context. Run objectives via the /automode macro (real subagents), or provide an llmFn.]",
          error: "no_llm_runner",
          startTime: startISO, endTime: new Date().toISOString(),
          durationMs: Date.now() - start, success: false,
          save: task.save,
        }
      }
      const result = await llmFn(task.prompt)
      // A resolved-but-failed run (non-zero/killed exit, empty transcript, spawn
      // failure) must NOT be logged as success. Honor the runner's `ok` flag, and
      // fall back to sniffing the error-shaped output for runners that don't set it.
      const failed = result.ok === false || (result.ok === undefined && FAILED_OUTPUT.test(result.output))
      if (failed) {
        const errResult: TaskResult = {
          id: task.id, prompt: task.prompt,
          output: result.output,
          error: result.error ?? "run failed (no output)",
          startTime: startISO, endTime: new Date().toISOString(),
          durationMs: Date.now() - start, success: false,
          costActual: result.cost,
          tokensUsed: { input: result.tokensIn, output: result.tokensOut },
          save: task.save,
        }
        saveTaskResult(session, errResult)
        return errResult
      }
      // NB: do not accumulate totals here — saveTaskResult() is the single point
      // that adds cost/tokens to the session. checkCostLimit() below projects the
      // new total from the not-yet-added result, so pre-adding would double-count.
      const taskResult: TaskResult = {
        id: task.id, prompt: task.prompt,
        output: result.output,
        startTime: startISO, endTime: new Date().toISOString(),
        durationMs: Date.now() - start, success: true,
        costActual: result.cost,
        tokensUsed: { input: result.tokensIn, output: result.tokensOut },
        save: task.save,
      }
      if (!checkCostLimit(session, taskResult)) {
        session.status = "cost_limited"
        return { ...taskResult, success: false, error: "Batch cost limit exceeded" }
      }
      saveTaskResult(session, taskResult)
      return taskResult
    } catch (e: any) {
      const errResult: TaskResult = {
        id: task.id, prompt: task.prompt,
        output: "", error: e.message,
        startTime: startISO, endTime: new Date().toISOString(),
        durationMs: Date.now() - start, success: false,
        save: task.save,
      }
      saveTaskResult(session, errResult)
      return errResult
    }
  }
}
