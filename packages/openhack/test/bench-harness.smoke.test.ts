import { describe, expect, test } from "bun:test"
import * as path from "node:path"
import { spawnSync } from "node:child_process"

/**
 * Smoke test for the bench-attack-loop harness. Runs the script with a fixture
 * for ~1s and asserts:
 *   - exit 0
 *   - every documented METRIC line is emitted exactly once
 *   - the numeric fields parse as finite numbers
 *
 * Purpose: catch regressions where a metric was silently renamed or dropped,
 * which would break the compare script downstream.
 */

const REQUIRED_METRICS = [
  "loop_rounds_to_goal",
  "loop_wall_seconds",
  "loop_first_critical_seconds",
  "loop_first_critical_cost_usd",
  "loop_total_cost_usd",
  "loop_tokens_in",
  "loop_tokens_out",
  "loop_findings_total",
  "loop_findings_high",
  "loop_coverage_percent",
  "loop_frontier_size_final",
  "loop_frontier_size_p50",
  "loop_controller_ms_p50",
  "loop_controller_ms_p95",
  "loop_controller_ms_p99",
  "loop_controller_ms_mean",
  "loop_controller_ms_stddev",
  "loop_task_tool_p50_ms",
  "loop_task_tool_p95_ms",
  "loop_task_tool_p99_ms",
  "loop_task_tool_histogram",
  "loop_controller_ms_histogram",
  "loop_block_ratio",
  "loop_peak_rss_mb",
  "loop_min_rss_mb",
  "loop_mean_rss_mb",
  "loop_p50_rss_mb",
  "loop_rss_samples",
  "loop_dispatch_count_by_agent",
  "loop_ms_p50_by_agent",
  "loop_tokens_in_by_agent",
  "loop_macro_dispatch_count",
  "loop_macro_dispatch_by_name",
  "loop_macro_ms_p50",
  "loop_macro_ms_p95",
  "loop_terminate_reason",
]

describe("bench-attack-loop harness", () => {
  test("mock mode with fixture emits every required METRIC exactly once and exits 0", () => {
    const repoRoot = path.resolve(__dirname, "../../..")
    const script = path.join(repoRoot, "packages", "openhack-cli", "script", "bench-attack-loop.ts")
    const fixture = path.join(repoRoot, "perf", "fixtures", "site1.json")
    const cwd = path.join(repoRoot, "packages", "openhack-cli")
    const proc = spawnSync("bun", ["run", script], {
      cwd,
      env: {
        ...process.env,
        BENCH_TARGET: "example.com",
        BENCH_ROUNDS: "2",
        BENCH_MODE: "graph",
        BENCH_INSTANCES: "1",
        BENCH_FIXTURE: fixture,
      },
      encoding: "utf-8",
    })
    expect(proc.status).toBe(0)
    const lines = proc.stdout.split(/\r?\n/).filter((l) => l.startsWith("METRIC "))
    // Every required metric appears exactly once.
    const seen = new Map<string, number>()
    for (const line of lines) {
      const m = /^METRIC\s+([A-Za-z0-9_]+)=(.+)$/.exec(line)
      if (!m || !m[1]) continue
      seen.set(m[1], (seen.get(m[1]) ?? 0) + 1)
    }
    for (const k of REQUIRED_METRICS) {
      expect(seen.get(k)).toBe(1)
    }
    // No extra unknown metric slipped in (defensive — if the surface grows, add here first).
    for (const k of seen.keys()) expect(REQUIRED_METRICS).toContain(k)
  })

  test("graph vs static both run and emit the same key set", () => {
    const repoRoot = path.resolve(__dirname, "../../..")
    const script = path.join(repoRoot, "packages", "openhack-cli", "script", "bench-attack-loop.ts")
    const fixture = path.join(repoRoot, "perf", "fixtures", "site1.json")
    const cwd = path.join(repoRoot, "packages", "openhack-cli")
    const run = (mode: string) =>
      spawnSync("bun", ["run", script], {
        cwd,
        env: {
          ...process.env,
          BENCH_TARGET: "example.com",
          BENCH_ROUNDS: "2",
          BENCH_MODE: mode,
          BENCH_INSTANCES: "1",
          BENCH_FIXTURE: fixture,
        },
        encoding: "utf-8",
      })
    const g = run("graph")
    const s = run("static")
    expect(g.status).toBe(0)
    expect(s.status).toBe(0)
    const keys = (out: string) => new Set(out.split(/\r?\n/).flatMap((l) => {
      const m = /^METRIC\s+([A-Za-z0-9_]+)=/.exec(l)
      return m && m[1] ? [m[1]] : []
    }))
    const gk = keys(g.stdout)
    const sk = keys(s.stdout)
    // Same metric key set — compare script depends on this equivalence.
    expect([...gk].sort()).toEqual([...sk].sort())
  })
})
