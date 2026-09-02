export * as Temporal from "./temporal"

import fs from "node:fs"
import path from "node:path"
import { ConfigStore } from "./config-store"
import { Exec } from "./exec"
import { Vendors } from "./vendors"

/**
 * Temporal durable-execution seam (vendored server at `vendor/temporal`).
 *
 * The automode loop already appends one durable round record per round to
 * `.openhack/rounds/<target>.jsonl` — the local source of truth for resume.
 * When `temporal.enabled` is set, each round record is ALSO mirrored into a
 * Temporal workflow as a durable, queryable event via the `temporal` CLI
 * (`workflow start` records the event even while no worker processes it yet —
 * processing comes with the docker-compose service + a worker, the documented
 * Phase-3b path).
 *
 * Mirroring is best-effort and always visible: failures are returned, counted
 * and logged by the loop — never swallowed — and never break the round.
 */

export interface Config {
  enabled: boolean
  address: string
  namespace: string
  taskQueue: string
}

export function config(): Config {
  const result: Config = { enabled: false, address: "localhost:7233", namespace: "default", taskQueue: "openhack" }
  try {
    const block = ConfigStore.getObject("temporal")
    if (block) {
      if (typeof block.enabled === "boolean") result.enabled = block.enabled
      if (typeof block.address === "string" && block.address) result.address = block.address
      if (typeof block.namespace === "string" && block.namespace) result.namespace = block.namespace
      if (typeof block.task_queue === "string" && block.task_queue) result.taskQueue = block.task_queue
      if (typeof block.taskQueue === "string" && block.taskQueue) result.taskQueue = block.taskQueue
    }
  } catch (error) {
    console.warn(`[temporal] failed to read engagement config temporal block: ${error instanceof Error ? error.message : String(error)}`)
  }
  return result
}

export interface MirrorResult {
  ok: boolean
  workflowID: string | null
  error?: string
}

const state = { mirrors: 0, failures: 0, lastError: null as string | null }

/** Mirror counters — surfaced by diagnostics, never reset silently. */
export function status() {
  return { ...state, serverBin: resolveServerBin() }
}

/** Vendored/PATH `temporal-server` resolution (via the Vendors registry). */
export function resolveServerBin(): string | null {
  return Vendors.resolve("temporal").bin
}

/**
 * `temporal` client CLI on PATH — the server binary and the client CLI ship in
 * the same distribution, so the vendored server's bin directory is checked too.
 */
export function resolveCli(): string | null {
  const server = resolveServerBin()
  if (server) {
    const sibling = server.replace(/temporal-server$/, "temporal")
    try {
      // eslint-disable-next-line no-constant-condition
      if (sibling !== server && require("node:fs").existsSync(sibling)) return sibling
    } catch {}
  }
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue
    try {
      const candidate = path.join(dir, "temporal")
      if (fs.existsSync(candidate)) return candidate
    } catch {}
  }
  return null
}

/**
 * Mirror one round record into a Temporal workflow event. Never rejects.
 * `record` must be a JSON-serializable round telemetry object.
 */
export async function mirrorRound(record: Record<string, unknown>, cfg = config(), timeoutMs = 15_000): Promise<MirrorResult> {
  state.mirrors++
  if (!cfg.enabled) return { ok: false, workflowID: null, error: "disabled (temporal.enabled=false)" }
  const cli = resolveCli()
  if (!cli)
    return {
      ok: false,
      workflowID: null,
      error: "temporal server not bootstrapped. Fix: `openhack vendors --bootstrap temporal` (or bash vendor/temporal/bootstrap.sh); client on PATH for mirroring.",
    }
  const target = typeof record.target === "string" && record.target ? record.target : "target"
  const round = Number(record.round ?? 0)
  const workflowID = `openhack-round-${target}-${round}`.replace(/[^a-zA-Z0-9._-]/g, "_")
  const payload = JSON.stringify({
    workflow_type: "openhack.round.mirror",
    task_queue: cfg.taskQueue,
    round_record: record,
  })
  const result = await Exec.execBounded(
    cli,
    [
      "workflow", "start",
      "--address", cfg.address,
      "--namespace", cfg.namespace,
      "--workflow-id", workflowID,
      "--task-queue", cfg.taskQueue,
      "--type", "openhack.round.mirror",
      "--input", payload,
    ],
    { timeoutMs: timeoutMs, maxBuffer: 4 * 1024 * 1024 },
  )
  if (result.timedOut) {
    const message = `temporal mirror timed out after ${timeoutMs}ms (is the server at ${cfg.address} up?)`
    state.failures++
    state.lastError = message
    return { ok: false, workflowID, error: message }
  }
  if (result.spawnError) {
    const message = `${result.spawnError}${result.stderr ? ` — ${result.stderr.trim().slice(0, 300)}` : ""}`
    state.failures++
    state.lastError = message
    return { ok: false, workflowID, error: message }
  }
  return { ok: true, workflowID }
}
