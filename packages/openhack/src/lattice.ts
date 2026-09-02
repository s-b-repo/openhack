export * as Lattice from "./lattice"

import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { ConfigStore } from "./config-store"
import { Exec } from "./exec"

/**
 * Lattice bridge — the vendored structural-analysis engine
 * (`vendor/lattice`, source of truth `src/lattice`, a Python engine) wired into
 * the AI coding loop.
 *
 * Two jobs, one engine:
 *
 * 1. **Write-path structural gate** — every time the AI writes or edits source
 *    code (`write` / `edit` / `apply_patch` tools), a bounded differential
 *    `lattice verify` against `HEAD` checks whether the change regressed the
 *    project's structure (broken symbols, unresolved imports, removed public
 *    API). Regressions are appended to the tool output so the model self-
 *    corrects in the same turn — structural bugs never get a free ride.
 * 2. **Read-path annotation** — when the AI reads a source file, known findings
 *    for that file from the latest `/codeaudit` report are surfaced at zero
 *    engine cost, so prior audit knowledge follows the code around.
 *
 * Honesty contract (unchanged from the CLI audit): Lattice proves structural
 * reachability and taint, not exploitability. Engine resolution mirrors the DCR
 * bridge: `$OPENHACK_LATTICE_BIN` → `vendor/lattice/.venv/bin/lattice` → PATH.
 * Nothing here swallows errors: every failure is recorded in `status()` and
 * surfaced in tool output exactly once per condition.
 */

export interface Settings {
  enabled: boolean
  bin: string
  timeoutMs: number
  cooldownMs: number
  readAnnotate: boolean
  maxNoteChars: number
}

export const DEFAULTS: Settings = {
  enabled: process.env.OPENHACK_LATTICE_DISABLED !== "1",
  bin: process.env.OPENHACK_LATTICE_BIN ?? "lattice",
  timeoutMs: 20_000,
  cooldownMs: 45_000,
  readAnnotate: true,
  maxNoteChars: 1_500,
}

/** Merge the engagement-config `lattice` block over the env-driven defaults. */
export function config(): Settings {
  const result = { ...DEFAULTS }
  try {
    const block = ConfigStore.getObject("lattice")
    if (block) {
      if (typeof block.enabled === "boolean") result.enabled = block.enabled
      if (typeof block.bin === "string" && block.bin) result.bin = block.bin
      if (typeof block.timeoutMs === "number" && block.timeoutMs > 0) result.timeoutMs = block.timeoutMs
      if (typeof block.cooldownMs === "number" && block.cooldownMs >= 0) result.cooldownMs = block.cooldownMs
      if (typeof block.read_annotate === "boolean") result.readAnnotate = block.read_annotate
      if (typeof block.timeout_ms === "number" && block.timeout_ms > 0) result.timeoutMs = block.timeout_ms
      if (typeof block.cooldown_ms === "number" && block.cooldown_ms >= 0) result.cooldownMs = block.cooldown_ms
      if (typeof block.max_note_chars === "number" && block.max_note_chars > 0) result.maxNoteChars = block.max_note_chars
      if (typeof block.readAnnotate === "boolean") result.readAnnotate = block.readAnnotate
      if (typeof block.maxNoteChars === "number" && block.maxNoteChars > 0) result.maxNoteChars = block.maxNoteChars
    }
  } catch (error) {
    // Visible, not fatal: unreadable engagement config falls back to defaults.
    console.warn(`[lattice] failed to read engagement config lattice block: ${describe(error)}`)
  }
  return result
}

const describe = (error: unknown) => (error instanceof Error ? `${error.name}: ${error.message}` : String(error))

// ─── observability — nothing degrades silently ───────────────────────────────

export interface Status {
  bin: string
  /** Resolved engine path, or null when the engine is not installed. */
  resolvedBin: string | null
  runs: number
  failures: number
  lastError: string | null
  lastRunAt: number | null
  cooldownSkips: number
  engineMissingNoted: boolean
}

const state = {
  bin: DEFAULTS.bin,
  runs: 0,
  failures: 0,
  lastError: null as string | null,
  lastRunAt: null as number | null,
  cooldownSkips: 0,
  engineMissingNoted: false,
}

/** Mutable status snapshot — consumed by `openhack vendors` and tests. */
export function status(): Status {
  return {
    bin: config().bin,
    resolvedBin: resolveBin(),
    runs: state.runs,
    failures: state.failures,
    lastError: state.lastError,
    lastRunAt: state.lastRunAt,
    cooldownSkips: state.cooldownSkips,
    engineMissingNoted: state.engineMissingNoted,
  }
}

const recordFailure = (error: unknown) => {
  state.failures++
  state.lastError = describe(error)
  state.lastRunAt = Date.now()
}

// ─── engine resolution ───────────────────────────────────────────────────────

/**
 * Engine resolution, mirroring the DCR pattern:
 *   1. an absolute/explicit `bin` from config or $OPENHACK_LATTICE_BIN
 *   2. the vendored engine at <repo>/vendor/lattice/.venv/bin/lattice
 *   3. a bare name resolved on PATH
 * Returns null (recorded) when nothing resolves — callers surface the
 * bootstrap hint instead of failing silently.
 */
export function resolveBin(bin = config().bin): string | null {
  state.bin = bin
  if (bin.includes("/")) {
    try {
      return fs.existsSync(bin) ? bin : null
    } catch (error) {
      recordFailure(error)
      return null
    }
  }
  let directory = process.cwd()
  for (let depth = 0; depth < 8; depth++) {
    const candidate = path.join(directory, "vendor", "lattice", ".venv", "bin", bin)
    try {
      if (fs.existsSync(candidate)) return candidate
    } catch (error) {
      recordFailure(error)
    }
    const parent = path.dirname(directory)
    if (parent === directory) break
    directory = parent
  }
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue
    try {
      if (fs.existsSync(path.join(dir, bin))) return path.join(dir, bin)
    } catch (error) {
      recordFailure(error)
    }
  }
  return null
}

// ─── language mapping (mirrors the engine's `_LANG` table) ───────────────────

const LANG_BY_EXT: Record<string, string> = {
  ts: "ts", tsx: "ts", mts: "ts", cts: "ts",
  js: "js", jsx: "js", mjs: "js", cjs: "js",
  py: "py", pyi: "py",
  go: "go", rs: "rs", rb: "rb", sol: "sol",
  c: "c", h: "c",
  cpp: "cpp", cc: "cpp", cxx: "cpp", hpp: "cpp", hh: "cpp",
  cu: "cu", cuh: "cu",
  sh: "sh", bash: "sh", zsh: "sh",
  sql: "sql",
  yml: "iac", yaml: "iac", tf: "iac",
  dockerfile: "iac",
}

export const SOURCE_EXTENSIONS = new Set(Object.keys(LANG_BY_EXT))

/** Lattice language for a file path, or null when it is not a source file. */
export function detectLang(filePath: string): string | null {
  const base = path.basename(filePath).toLowerCase()
  if (base === "dockerfile" || base.startsWith("dockerfile.")) return "iac"
  const ext = base.includes(".") ? base.slice(base.lastIndexOf(".") + 1) : ""
  return LANG_BY_EXT[ext] ?? null
}

/** Walk up from a file to the containing repository root (git or vendored repo). */
export function repoRootFor(filePath: string): string {
  let directory = path.dirname(path.resolve(filePath))
  for (let depth = 0; depth < 12; depth++) {
    try {
      if (fs.existsSync(path.join(directory, ".git"))) return directory
    } catch (error) {
      recordFailure(error)
    }
    const parent = path.dirname(directory)
    if (parent === directory) break
    directory = parent
  }
  return process.cwd()
}

// ─── bounded engine invocation ───────────────────────────────────────────────

// ─── differential verify (write-path structural gate) ────────────────────────

export interface VerifyReport {
  verdict: "clean" | "regressed" | "unverifiable"
  regressions: string[]
  brokenByRemoval: string[]
  newUnresolvedImports: string[]
  newErrorDiagnostics: string[]
  removedPublicAPI: string[]
  errorDiagnostics: string[]
  addedVertices: number
  removedVertices: number
}

const asStringList = (value: unknown): string[] =>
  Array.isArray(value) ? value.map((item) => (typeof item === "string" ? item : JSON.stringify(item))) : []

/**
 * Differential structural check of `root` against a git ref (default HEAD).
 * The engine's own exit codes are verdicts: 0 clean, 1 regressed, 2
 * unverifiable — all three parse the `--out` report. Only spawn failures and
 * timeouts degrade (recorded in `status()`, surfaced by the caller).
 */
export async function verify(
  root: string,
  opts: { lang?: string; against?: string; timeoutMs?: number; bin?: string } = {},
): Promise<VerifyReport | null> {
  const settings = config()
  if (!settings.enabled) return null
  const bin = resolveBin(opts.bin ?? settings.bin)
  if (!bin) return null
  const out = path.join(os.tmpdir(), `lattice-verify-${process.pid}-${Date.now()}.json`)
  const args = ["verify", path.resolve(root), "--against", opts.against ?? "HEAD", "--out", out]
  if (opts.lang) args.push("--lang", opts.lang)
  state.runs++
  state.lastRunAt = Date.now()
  try {
    const result = await Exec.execBounded(bin, args, { timeoutMs: opts.timeoutMs ?? settings.timeoutMs })
    if (result.timedOut) throw new Error(`lattice verify timed out after ${opts.timeoutMs ?? settings.timeoutMs}ms`)
    if (result.spawnError) throw new Error(`lattice failed to run: ${result.spawnError}`)
    let raw: any
    try {
      raw = JSON.parse(fs.readFileSync(out, "utf8"))
    } catch (error) {
      // Exit 0 with an unreadable report is an engine contract violation, not a
      // clean verdict — record it.
      recordFailure(new Error(`verify wrote no parsable report (exit ${result.code}): ${describe(error)}`))
      return null
    }
    const verdict = String(raw.verdict ?? "unverifiable")
    return {
      verdict: verdict === "clean" ? "clean" : verdict === "regressed" ? "regressed" : "unverifiable",
      regressions: asStringList(raw.regressions),
      brokenByRemoval: asStringList(raw.broken_by_removal),
      newUnresolvedImports: asStringList(raw.new_unresolved_imports),
      newErrorDiagnostics: asStringList(raw.new_error_diagnostics),
      removedPublicAPI: asStringList(raw.removed_public_api),
      errorDiagnostics: asStringList(raw.error_diagnostics),
      addedVertices: Number(raw.added_vertices?.length ?? raw.added_vertices ?? 0) || 0,
      removedVertices: Number(raw.removed_vertices?.length ?? raw.removed_vertices ?? 0) || 0,
    }
  } catch (error) {
    recordFailure(error)
    return null
  } finally {
    try {
      fs.rmSync(out, { force: true })
    } catch (error) {
      recordFailure(new Error(`temp report cleanup failed: ${describe(error)}`))
    }
  }
}

const elide = (items: string[], maxChars: number) => {
  const lines: string[] = []
  let used = 0
  for (const item of items) {
    const line = `  - ${item}`
    if (used + line.length > maxChars) {
      lines.push(`  - … ${items.length - lines.length} more (full report: /codeaudit <path>)`)
      break
    }
    lines.push(line)
    used += line.length
  }
  return lines
}

/**
 * Render a verify report as a tool-output note, prioritizing regressions that
 * touch `filePath` (the file the model just wrote) and keeping the rest as a
 * counted summary. Null when there is nothing to say (clean verdict).
 */
export function formatVerifyNote(filePath: string, report: VerifyReport, maxChars = DEFAULTS.maxNoteChars): string | null {
  if (report.verdict === "clean") return null
  const touch = (items: string[]) => items.filter((item) => item.includes(filePath))
  if (report.verdict === "unverifiable") {
    const lines = [
      `[LATTICE verify] UNVERIFIABLE — ingest errors prevented a structural verdict vs HEAD.`,
      ...(report.errorDiagnostics.length ? elide(report.errorDiagnostics, Math.max(0, maxChars - 200)) : []),
    ]
    return lines.join("\n")
  }
  const regressions = [...touch(report.regressions), ...report.regressions.filter((r) => !r.includes(filePath))]
  const related = [
    ...regressions,
    ...report.brokenByRemoval.map((r) => `broken by removal: ${r}`),
    ...report.newUnresolvedImports.map((r) => `new unresolved import: ${r}`),
    ...report.newErrorDiagnostics.map((r) => `new error diagnostic: ${r}`),
    ...report.removedPublicAPI.map((r) => `removed public API: ${r}`),
  ]
  if (!related.length) return null
  const lines = [
    `[LATTICE verify vs HEAD] REGRESSED — ${regressions.length} structural regression(s) (+${report.addedVertices}/-${report.removedVertices} vertices). Fix before continuing:`,
    ...elide(related, Math.max(0, maxChars - 160)),
  ]
  return lines.join("\n")
}

// ─── the AI coding loop: write-path guard + read-path annotation ─────────────

const lastGuardAt = new Map<string, number>()
const lastReadAnnotateAt = new Map<string, number>()

/**
 * Write-path structural gate. Called by the runtime plugin after every
 * `write` / `edit` / `apply_patch` of a source file. Returns a note for the
 * tool output (advisory — never blocks the write) or null when there is
 * nothing to say. Cooldown-bounded per repo; engine-missing and failures are
 * surfaced once with the fix, never swallowed.
 */
export async function guardWrittenFile(filePath: string): Promise<string | null> {
  const settings = config()
  if (!settings.enabled) return null
  if (!detectLang(filePath)) return null
  try {
    if (!fs.existsSync(filePath)) return null
  } catch (error) {
    recordFailure(error)
    return null
  }
  const root = repoRootFor(filePath)
  const now = Date.now()
  const last = lastGuardAt.get(root) ?? 0
  if (now - last < settings.cooldownMs) {
    state.cooldownSkips++
    return null
  }
  lastGuardAt.set(root, now)

  if (!resolveBin()) {
    if (!state.engineMissingNoted) {
      state.engineMissingNoted = true
      return "[lattice] structural write-gate skipped — engine not bootstrapped. Run `vendor/lattice/bootstrap.sh` (or set OPENHACK_LATTICE_BIN). Install: bash install.sh"
    }
    return null
  }
  const report = await verify(root, { lang: detectLang(filePath) ?? undefined })
  if (!report) {
    const current = status()
    return `[lattice] structural check failed (${current.failures} recorded) — last error: ${current.lastError}. Fix the engine (vendor/lattice/bootstrap.sh) or disable via config lattice.enabled=false.`
  }
  return formatVerifyNote(filePath, report, settings.maxNoteChars)
}

/**
 * Read-path annotation: surface known findings for the file being read from the
 * latest `/codeaudit` report — zero engine cost (the audit already ran).
 * Returns a note or null when there is nothing to add; unreadable reports are
 * recorded, never swallowed.
 */
export async function annotateRead(filePath: string): Promise<string | null> {
  const settings = config()
  if (!settings.enabled || !settings.readAnnotate) return null
  if (!detectLang(filePath)) return null
  const now = Date.now()
  const last = lastReadAnnotateAt.get(filePath) ?? 0
  if (now - last < settings.cooldownMs) return null
  lastReadAnnotateAt.set(filePath, now)

  const auditDir = latestAuditDir()
  if (!auditDir) return null
  const base = path.basename(filePath)
  const findings: string[] = []
  try {
    for (const name of fs.readdirSync(auditDir)) {
      if (!name.endsWith(".json") || name.endsWith("-graph.json")) continue
      let data: any
      try {
        data = JSON.parse(fs.readFileSync(path.join(auditDir, name), "utf8"))
      } catch (error) {
        recordFailure(new Error(`audit report ${name} unreadable: ${describe(error)}`))
        continue
      }
      const items: any[] = Array.isArray(data) ? data.filter((x) => x && typeof x === "object") : Array.isArray(data?.findings) ? data.findings : Array.isArray(data?.bugs) ? data.bugs : []
      for (const item of items) {
        const haystack = `${item.symbol ?? ""} ${item.detail ?? ""} ${item.source ?? ""} ${item.sink ?? ""} ${item.kind ?? ""}`
        if (haystack.includes(base) || haystack.includes(filePath))
          findings.push(`[${String(item.severity ?? "info")}] ${String(item.kind ?? "finding")} — ${String(item.detail ?? item.sink ?? item.symbol ?? "")}`)
      }
    }
  } catch (error) {
    recordFailure(error)
    return null
  }
  if (!findings.length) return null
  return [`[LATTICE known findings for ${base} — from ${path.relative(process.cwd(), auditDir) || auditDir}]`, ...elide(findings, settings.maxNoteChars)].join("\n")
}

const latestAuditDir = (): string | null => {
  const dir = String(ConfigStore.get("automode.codeaudit_dir") ?? "") || path.join(".openhack", "codeaudit")
  try {
    if (!fs.existsSync(dir)) return null
    const latest = fs
      .readdirSync(dir)
      .filter((name) => name.endsWith("-latest"))
      .map((name) => path.join(dir, name))
      .filter((p) => fs.statSync(p).isDirectory())
      .map((p) => ({ p, m: fs.statSync(p).mtimeMs }))
      .sort((a, b) => b.m - a.m)
    return latest[0]?.p ?? null
  } catch (error) {
    recordFailure(error)
    return null
  }
}

/** Test-only: reset module state (cooldowns, counters). */
export function __resetForTests() {
  lastGuardAt.clear()
  lastReadAnnotateAt.clear()
  state.runs = 0
  state.failures = 0
  state.lastError = null
  state.lastRunAt = null
  state.cooldownSkips = 0
  state.engineMissingNoted = false
}
