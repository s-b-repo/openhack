// Cross-revision compare for bench:loop. Runs `bench:attack-loop` at two git
// refs (default HEAD~1 vs HEAD) inside `git worktree`s (never `git checkout` on
// the caller's tree), diffs the METRIC lines, and prints a Markdown delta.
//
// Fails (exit 1) if any of the regression-sensitive metrics worsens by more
// than the threshold: total cost, wall seconds, or rounds to goal (with a small
// absolute floor to ignore noise on cheap benches).
//
// Usage:
//   bun run bench:loop:compare HEAD~1 HEAD
//   BENCH_TARGET=example.com BENCH_FIXTURE=perf/fixtures/site1.json bun run bench:loop:compare HEAD~1 HEAD
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { spawnSync } from "node:child_process"

const REGRESS = new Set(["loop_total_cost_usd", "loop_wall_seconds", "loop_rounds_to_goal"])
const THRESHOLD_PCT = 15   // >15% worse fails
const ABS_FLOOR = 0.001    // ignore diffs where BOTH values are near zero

interface BenchOut {
  ref: string
  metrics: Record<string, number | string>
  raw: string
}

function repoRoot(): string {
  const out = spawnSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf-8" })
  if (out.status !== 0) throw new Error(`bench:loop:compare: not a git repo (${out.stderr})`)
  return out.stdout.trim()
}

function runAtRef(ref: string, env: NodeJS.ProcessEnv, root: string): BenchOut {
  const wt = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-bench-wt-"))
  // Create an isolated worktree — never touches the caller's checkout.
  let created = false
  try {
    const add = spawnSync("git", ["worktree", "add", "--detach", wt, ref], { cwd: root, encoding: "utf-8" })
    if (add.status !== 0) throw new Error(`git worktree add ${ref} failed:\n${add.stderr}`)
    created = true
    // Install workspace deps in the worktree (Bun re-uses global cache — usually fast).
    // Best-effort: skip if bun install fails since scripts import via relative paths.
    spawnSync("bun", ["install"], { cwd: wt, stdio: "ignore" })
    const proc = spawnSync(
      "bun",
      ["run", "script/bench-attack-loop.ts"],
      {
        cwd: path.join(wt, "packages", "openhack-cli"),
        env: { ...env, BENCH_OUT: "" },
        encoding: "utf-8",
      },
    )
    if (proc.status !== 0) throw new Error(`bench script failed at ${ref}:\n${proc.stderr}`)
    return { ref, metrics: parseMetrics(proc.stdout), raw: proc.stdout }
  } finally {
    if (created) spawnSync("git", ["worktree", "remove", "--force", wt], { cwd: root, stdio: "ignore" })
    try { fs.rmSync(wt, { recursive: true, force: true }) } catch {}
  }
}

function parseMetrics(stdout: string): Record<string, number | string> {
  const out: Record<string, number | string> = {}
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^METRIC\s+([A-Za-z0-9_]+)=(.+)$/.exec(line)
    if (!m || !m[1] || !m[2]) continue
    const raw = m[2].trim()
    const num = Number(raw)
    out[m[1]] = Number.isFinite(num) && !/^0\d/.test(raw) ? num : raw
  }
  return out
}

function fmt(v: number | string): string {
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(4)
  return String(v)
}

function pctChange(baseline: number, current: number): number {
  if (baseline === 0) return current === 0 ? 0 : 100
  return ((current - baseline) / baseline) * 100
}

function main(): void {
  const [baseRef = "HEAD~1", newRef = "HEAD"] = process.argv.slice(2)
  const root = repoRoot()

  const env = {
    ...process.env,
    BENCH_TARGET: process.env.BENCH_TARGET ?? "example.com",
    BENCH_FIXTURE: process.env.BENCH_FIXTURE ?? path.join(root, "perf", "fixtures", "site1.json"),
    BENCH_ROUNDS: process.env.BENCH_ROUNDS ?? "3",
    BENCH_MODE: process.env.BENCH_MODE ?? "graph",
    BENCH_INSTANCES: process.env.BENCH_INSTANCES ?? "1",
  }

  process.stderr.write(`bench:loop:compare — baseline=${baseRef} current=${newRef}\n`)
  const base = runAtRef(baseRef, env, root)
  const cur = runAtRef(newRef, env, root)

  // Emit a Markdown delta table sorted by absolute % change on the numeric metrics.
  const keys = Array.from(new Set([...Object.keys(base.metrics), ...Object.keys(cur.metrics)])).sort()
  const rows: Array<{ k: string; b: number | string; c: number | string; d: string; regressed: boolean }> = []
  for (const k of keys) {
    const b = base.metrics[k] ?? "n/a"
    const c = cur.metrics[k] ?? "n/a"
    let delta = "—"
    let regressed = false
    if (typeof b === "number" && typeof c === "number") {
      const pct = pctChange(b, c)
      delta = `${pct >= 0 ? "+" : ""}${pct.toFixed(1)}%`
      if (REGRESS.has(k) && Math.max(Math.abs(b), Math.abs(c)) > ABS_FLOOR && pct > THRESHOLD_PCT) regressed = true
    }
    rows.push({ k, b, c, d: delta, regressed })
  }

  process.stdout.write(`\n| metric | ${baseRef} | ${newRef} | delta |\n|---|---:|---:|---:|\n`)
  for (const r of rows) {
    process.stdout.write(
      `| ${r.regressed ? "**⚠ " : ""}${r.k}${r.regressed ? "**" : ""} | ${fmt(r.b)} | ${fmt(r.c)} | ${r.d} |\n`,
    )
  }

  const regressed = rows.filter((r) => r.regressed)
  if (regressed.length) {
    process.stderr.write(`\nbench:loop:compare: ${regressed.length} regression(s) > ${THRESHOLD_PCT}%: ${regressed.map((r) => r.k).join(", ")}\n`)
    process.exit(1)
  }
  process.stderr.write(`\nbench:loop:compare: no regressions (> ${THRESHOLD_PCT}%) on ${REGRESS.size} guarded metrics.\n`)
}

try {
  main()
} catch (e: any) {
  process.stderr.write(`bench:loop:compare failed: ${e?.message ?? e}\n`)
  process.exit(2)
}
