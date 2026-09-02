export * as DeepPlan from "./deepplan"

import fs from "node:fs"
import path from "node:path"
import { Exec } from "./exec"
import { Vendors } from "./vendors"

/**
 * deepagents planning backend (vendored at `vendor/deepagents`).
 *
 * Alternative backend for the manager tier (`managers.backend = "deepagents"`):
 * instead of one cheap LLM call, the phase-manager prompt is run through the
 * vendored LangGraph-based deep-agent harness (`create_deep_agent`), which can
 * plan with sub-agents, a scratch filesystem and tool loops. The output is the
 * SAME plan-JSON contract as the native path, so validation
 * (`Managers.parsePlan`) and task mapping are shared — only the planner changes.
 *
 * The harness runs `packages/openhack/python/deepplan.py` on the vendored venv.
 * Any failure resolves to `{ ok: false, error }` (recorded, visible) and the
 * caller falls back to the native planner — a phase is never starved.
 */

export interface CompleteResult {
  ok: boolean
  /** Raw planner text (plan JSON), for the shared `Managers.parsePlan` path. */
  output: string
  error?: string
  latencyMs?: number
}

/** Resolved vendored venv python, or null (recorded in Vendors status). */
export function resolvePython(): string | null {
  return Vendors.resolve("deepagents").bin
}

/** Path to the harness script, resolved from this module's location. */
export function harnessPath(): string {
  // deepplan.ts lives in packages/openhack/src; the harness in packages/openhack/python.
  return path.resolve(import.meta.dir, "..", "python", "deepplan.py")
}

/** Status of the deepagents backend — surfaced by diagnostics and tests. */
export function status(): { python: string | null; harness: string | null; runs: number; failures: number; lastError: string | null } {
  const harness = harnessPath()
  return {
    python: resolvePython(),
    harness: fs.existsSync(harness) ? harness : null,
    runs: state.runs,
    failures: state.failures,
    lastError: state.lastError,
  }
}

const state = { runs: 0, failures: 0, lastError: null as string | null }

/**
 * Run the phase-manager prompt through the vendored deepagents harness. Never
 * rejects — the caller decides on fallback (and must surface the reason).
 */
export async function complete(input: { prompt: string; model?: string; timeoutMs?: number }): Promise<CompleteResult> {
  const startedAt = Date.now()
  const python = resolvePython()
  if (!python)
    return {
      ok: false,
      output: "",
      error:
        "deepagents backend not bootstrapped. Fix: `openhack vendors --bootstrap deepagents` (or bash vendor/deepagents/bootstrap.sh), or set managers.backend=native.",
    }
  const harness = harnessPath()
  if (!fs.existsSync(harness)) return { ok: false, output: "", error: `deepagents harness missing: ${harness}` }
  state.runs++
  const result = await Exec.execBounded(python, [harness], {
    timeoutMs: input.timeoutMs ?? 300_000,
    maxBuffer: 16 * 1024 * 1024,
    input: JSON.stringify({ prompt: input.prompt, model: input.model ?? null }),
  })
  const latencyMs = Date.now() - startedAt
  if (result.timedOut) {
    state.failures++
    state.lastError = "deepagents planning timed out"
    return { ok: false, output: result.stdout.slice(0, 4_000), error: state.lastError, latencyMs }
  }
  if (result.spawnError) {
    state.failures++
    state.lastError = `deepagents harness failed to start: ${result.spawnError}`
    return { ok: false, output: result.stdout.slice(0, 4_000), error: state.lastError, latencyMs }
  }
  const text = result.stdout.trim()
  if (!text) {
    state.failures++
    state.lastError = `deepagents harness produced no output${result.stderr ? `: ${result.stderr.slice(0, 400)}` : ""}`
    return { ok: false, output: "", error: state.lastError, latencyMs }
  }
  // Harness reports failures on a final `__DEEPPLAN_ERROR__:` line while
  // still emitting anything it produced — surfaced, never swallowed.
  const marker = text.lastIndexOf("__DEEPPLAN_ERROR__:")
  if (marker >= 0) {
    const message = text.slice(marker + "__DEEPPLAN_ERROR__:".length).trim()
    const body = text.slice(0, marker).trim()
    state.failures++
    state.lastError = message
    return { ok: false, output: body, error: message || undefined, latencyMs }
  }
  return { ok: true, output: text, latencyMs }
}
