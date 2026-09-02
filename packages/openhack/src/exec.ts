export * as Exec from "./exec"

import { execFile } from "node:child_process"

/**
 * Bounded, promise-shaped subprocess execution for the vendored-component
 * bridges (Lattice, DCR, mini-swe-agent, deepagents, Temporal). One typed
 * result shape instead of five ad-hoc execFile wrappers: exit codes, spawn
 * failures and timeouts are all explicit values — never thrown away.
 */

export interface ExecResult {
  /** stdout (empty when the process could not be spawned). */
  stdout: string
  /** stderr (empty when the process could not be spawned). */
  stderr: string
  /** Process exit code; null when killed by the timeout or never spawned. */
  code: number | null
  /** True when the timeout killed the process. */
  timedOut: boolean
  /** Spawn/startup failure message (e.g. ENOENT), null on a real run. */
  spawnError: string | null
}

export interface ExecOptions {
  timeoutMs?: number
  maxBuffer?: number
  cwd?: string
  /** Text written to the child's stdin, then the pipe is closed. */
  input?: string
}

export function execBounded(bin: string, args: string[], opts: ExecOptions = {}): Promise<ExecResult> {
  return new Promise((resolve) => {
    const child = execFile(
      bin,
      args,
      { timeout: opts.timeoutMs ?? 30_000, maxBuffer: opts.maxBuffer ?? 32 * 1024 * 1024, cwd: opts.cwd },
      (error, stdout, stderr) => {
        if (!error) return resolve({ stdout, stderr, code: 0, timedOut: false, spawnError: null })
        // ExecFileException carries `killed` and a numeric-or-string `code`:
        // a numeric code is a real exit; string codes (ENOENT, EACCES…) are
        // spawn/startup failures; `killed` marks a timeout kill.
        if (error.killed) return resolve({ stdout, stderr, code: null, timedOut: true, spawnError: null })
        if (typeof error.code === "number") return resolve({ stdout, stderr, code: error.code, timedOut: false, spawnError: null })
        resolve({ stdout, stderr, code: null, timedOut: false, spawnError: error.message })
      },
    )
    if (opts.input !== undefined) child.stdin?.end(opts.input)
  })
}
