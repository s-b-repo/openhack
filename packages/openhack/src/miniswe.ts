export * as MiniSwe from "./miniswe"

import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { Exec } from "./exec"
import { Vendors } from "./vendors"

/**
 * mini-swe-agent execution backend (vendored at `vendor/mini-swe-agent`).
 *
 * An alternative runner for automode loop instances: instead of spawning the
 * openhack CLI's own `run` subcommand, a task with `runner: "mini-swe"` runs
 * the vendored SWE-agent (`mini -m <model> -y --exit-immediately -t <prompt>`)
 * and maps its JSON trajectory back into the loop's `LlmResult` shape. Selected
 * per task via `TaskSpec.runner`, or loop-wide via `automode.runner` config.
 *
 * Resolution/status/bootstrap all go through the Vendors registry — a missing
 * backend fails the task with the exact fix in the error (never silently
 * falls back).
 */

export interface RunResult {
  ok: boolean
  /** Final agent submission text (what the loop treats as the task output). */
  output: string
  exitStatus: string
  cost: number
  apiCalls: number
  tokensIn: number
  tokensOut: number
  latencyMs: number
  error?: string
  timedOut?: boolean
}

export interface ParsedTrajectory {
  output: string
  exitStatus: string
  cost: number
  apiCalls: number
}

/**
 * Parse a mini-swe-agent trajectory file (format "mini-swe-agent-1.1"). Tolerant
 * of missing fields; null when the file is not a trajectory at all.
 */
export function parseTrajectory(json: string): ParsedTrajectory | null {
  let data: any
  try {
    data = JSON.parse(json)
  } catch {
    return null
  }
  if (!data || typeof data !== "object" || !Array.isArray(data.messages)) return null
  const info = data.info ?? {}
  const stats = info.model_stats ?? {}
  const submission = info.submission
  // Fall back to the last non-exit assistant content when no submission was set.
  const lastAssistant = [...data.messages].reverse().find((m: any) => m?.role === "assistant" && typeof m?.content === "string")
  const output =
    typeof submission === "string" && submission.length > 0
      ? submission
      : typeof lastAssistant?.content === "string"
        ? lastAssistant.content
        : ""
  return {
    output,
    exitStatus: String(info.exit_status ?? ""),
    cost: Number(stats.instance_cost ?? 0) || 0,
    apiCalls: Number(stats.api_calls ?? 0) || 0,
  }
}

/** Resolved `mini` binary path, or null (recorded in Vendors status). */
export function resolveBin(): string | null {
  return Vendors.resolve("mini-swe-agent").bin
}

/**
 * Run one task through the vendored mini-swe-agent. Never rejects: failures
 * resolve to `{ ok: false, error }` so the loop records them like any other
 * task outcome.
 */
export async function run(input: { prompt: string; model?: string; cwd?: string; timeoutMs?: number }): Promise<RunResult> {
  const startedAt = Date.now()
  const bin = resolveBin()
  if (!bin)
    return {
      ok: false,
      output: "",
      exitStatus: "",
      cost: 0,
      apiCalls: 0,
      tokensIn: 0,
      tokensOut: 0,
      latencyMs: 0,
      error:
        "mini-swe-agent backend not bootstrapped. Fix: `openhack vendors --bootstrap mini-swe-agent` (or bash vendor/mini-swe-agent/bootstrap.sh), or remove runner=mini-swe from the task / automode.runner config.",
    }
  const output = path.join(os.tmpdir(), `mini-swe-${process.pid}-${Date.now()}.json`)
  const args = ["--exit-immediately", "-o", output]
  if (input.model) args.push("-m", input.model)
  args.push("-y", "-t", input.prompt)
  const result = await Exec.execBounded(bin, args, {
    timeoutMs: input.timeoutMs ?? 30 * 60_000,
    maxBuffer: 64 * 1024 * 1024,
    cwd: input.cwd ?? process.cwd(),
  })
  const latencyMs = Date.now() - startedAt

  let trajectory: ParsedTrajectory | null = null
  let readError: string | null = null
  try {
    trajectory = parseTrajectory(fs.readFileSync(output, "utf8"))
  } catch (error) {
    readError = error instanceof Error ? error.message : String(error)
  }
  try {
    fs.rmSync(output, { force: true })
  } catch {}

  if (result.timedOut)
    return {
      ok: false,
      output: trajectory?.output ?? "",
      exitStatus: trajectory?.exitStatus ?? "",
      cost: trajectory?.cost ?? 0,
      apiCalls: trajectory?.apiCalls ?? 0,
      tokensIn: 0,
      tokensOut: 0,
      latencyMs,
      timedOut: true,
      error: "mini-swe-agent timed out",
    }
  if (!trajectory)
    return {
      ok: false,
      output: "",
      exitStatus: "",
      cost: 0,
      apiCalls: 0,
      tokensIn: 0,
      tokensOut: 0,
      latencyMs,
      error: `mini-swe-agent failed: ${result.spawnError ?? result.stderr.trim().slice(0, 400) ?? `no trajectory (${readError ?? "unreadable"})`}`,
    }
  // Exit status "Submitted" is mini-swe's success marker; anything else is
  // still reported with whatever the agent produced (recorded, honest).
  const ok = trajectory.exitStatus === "Submitted"
  return {
    ok,
    output: trajectory.output,
    exitStatus: trajectory.exitStatus,
    cost: trajectory.cost,
    apiCalls: trajectory.apiCalls,
    tokensIn: 0,
    tokensOut: 0,
    latencyMs,
    ...(ok ? {} : { error: `mini-swe-agent exit_status=${trajectory.exitStatus || "unknown"} (full trajectory fields: info.submission / messages)` }),
  }
}
