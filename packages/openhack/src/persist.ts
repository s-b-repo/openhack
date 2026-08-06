import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import * as path from "node:path"

/**
 * Tiny JSON state helpers for `.openhack/` files, mirroring the pattern already
 * used by Orchestrator (tool-scores.json). Used to persist feature state that
 * would otherwise be lost between the long-running server process and the
 * one-shot `openhack <cmd>` CLI (MoE usage counts, advisor toggle, model config).
 */

/** Read `file` as JSON, returning `fallback` when it is missing or unreadable. */
export function loadJSON<T>(file: string, fallback: T): T {
  try {
    if (existsSync(file)) return JSON.parse(readFileSync(file, "utf-8")) as T
  } catch {}
  return fallback
}

/** Write `data` to `file` as pretty JSON, creating parent dirs. Never throws. */
export function saveJSON(file: string, data: unknown): void {
  try {
    const dir = path.dirname(file)
    if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true })
    writeFileSync(file, JSON.stringify(data, null, 2))
  } catch {}
}
