// Self-optimizing harness tuner.
//
// Published ablations show harness design moves agentic-benchmark outcomes by
// up to ~48 points while model choice moves ~5 — so OpenHack treats its own
// loop knobs as a search space, not doctrine. This script sweeps the attack
// loop's harness knobs (frontier width × instance fan-out) against the
// DETERMINISTIC mock-LLM bench (`bench:loop` — zero cost, zero network),
// scores every run with the LoopPhysics tuner kernel, and persists the winner
// to `.openhack/harness-tuning.json`, which `automode --loop` picks up as the
// default frontier width on subsequent runs. Stanford-harness energy, applied
// to the pentest loop: measure, keep what wins, re-run when the surface changes.
//
// Env:
//   TUNE_TARGET=example.com     (required)
//   TUNE_ROUNDS=5               (rounds per bench run)
//   TUNE_FIXTURE=perf/fixtures/site1.json
//   TUNE_FRONTIER_KS=2,4,6,10   (comma list)
//   TUNE_INSTANCES=1,2          (comma list)
//   TUNE_MODE=graph             (bench mode passed through)
//   TUNE_OUT=<abs|.openhack/harness-tuning.json>
//
// Output: METRIC lines for CI + a Markdown table + the tuning JSON. Exit 0 when
// a winner was persisted; 2 on usage errors; 1 if no run produced any findings
// (a broken fixture is not a "tuned" harness).
import * as fs from "node:fs"
import * as path from "node:path"
import { spawnSync } from "node:child_process"
import { LoopPhysics } from "../../openhack-orchestration/src"

interface RunResult {
  frontierK: number
  instances: number
  score: number
  metrics: Record<string, number | string>
  nums: { high: number; total: number; cov: number; cost: number; wall: number }
}

function readEnv(k: string, def: string): string {
  return process.env[k] ?? def
}
function envList(k: string, def: string): number[] {
  return readEnv(k, def)
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n) && n > 0)
}

function runBench(repoDir: string, target: string, rounds: number, mode: string, fixture: string | undefined, frontierK: number, instances: number): Record<string, number | string> {
  const out = spawnSync(process.execPath, ["run", "script/bench-attack-loop.ts"], {
    cwd: repoDir,
    encoding: "utf-8",
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      BENCH_TARGET: target,
      BENCH_ROUNDS: String(rounds),
      BENCH_MODE: mode,
      ...(fixture ? { BENCH_FIXTURE: fixture } : {}),
      BENCH_FRONTIER_K: String(frontierK),
      BENCH_INSTANCES: String(instances),
    },
  })
  const metrics: Record<string, number | string> = {}
  for (const line of (out.stdout ?? "").split("\n")) {
    const m = /^METRIC\s+([A-Za-z0-9_]+)=(.+)$/.exec(line)
    if (!m) continue
    const v = m[2].trim()
    metrics[m[1]] = Number.isFinite(Number(v)) && v !== "" ? Number(v) : v
  }
  if (out.status !== 0 && Object.keys(metrics).length === 0) {
    process.stderr.write(`tune: bench failed for k=${frontierK} i=${instances}:\n${out.stderr?.slice(0, 2000)}\n`)
  }
  return metrics
}

function num(m: Record<string, number | string>, k: string): number {
  const v = m[k]
  return typeof v === "number" ? v : 0
}

function bounds(rs: Array<{ nums: RunResult["nums"] }>): {
  highs: [number, number]; covs: [number, number]; totals: [number, number]; costs: [number, number]; walls: [number, number]
} {
  const loHi = (vals: number[]): [number, number] => [Math.min(...vals), Math.max(...vals)]
  return {
    highs: loHi(rs.map((r) => r.nums.high)),
    covs: loHi(rs.map((r) => r.nums.cov)),
    totals: loHi(rs.map((r) => r.nums.total)),
    costs: loHi(rs.map((r) => r.nums.cost)),
    walls: loHi(rs.map((r) => r.nums.wall)),
  }
}

async function main() {
  const target = readEnv("TUNE_TARGET", "")
  if (!target) {
    process.stderr.write("bench:tune: TUNE_TARGET is required\n")
    process.exit(2)
  }
  const rounds = parseInt(readEnv("TUNE_ROUNDS", "5"), 10) || 5
  const mode = readEnv("TUNE_MODE", "graph")
  const fixture = process.env.TUNE_FIXTURE ? path.resolve(process.cwd(), process.env.TUNE_FIXTURE) : undefined
  const ks = [...new Set(envList("TUNE_FRONTIER_KS", "2,6,10"))].map((k) => Math.min(20, k))
  const inst = [...new Set(envList("TUNE_INSTANCES", "1,2"))].map((i) => Math.min(6, i))

  // The bench script lives in this package; resolve it regardless of caller cwd.
  const here = path.dirname(new URL(import.meta.url).pathname)
  const repoDir = path.resolve(here, "..")

  const runs: RunResult[] = []
  for (const k of ks) {
    for (const i of inst) {
      process.stderr.write(`tune: bench frontier_k=${k} instances=${i} …\n`)
      const m = runBench(repoDir, target, rounds, mode, fixture, k, i)
      runs.push({
        frontierK: k,
        instances: i,
        score: 0,
        metrics: m,
        nums: {
          high: num(m, "loop_findings_high"),
          total: num(m, "loop_findings_total"),
          cov: num(m, "loop_coverage_percent"),
          cost: num(m, "loop_total_cost_usd"),
          wall: num(m, "loop_wall_seconds"),
        },
      })
    }
  }
  if (!runs.length) {
    process.stderr.write("bench:tune: no runs completed\n")
    process.exit(1)
  }

  const bw = bounds(runs)
  for (const r of runs) {
    r.score = Math.round(LoopPhysics.scoreRun(
      { high: r.nums.high, cov: r.nums.cov, total: r.nums.total, cost: r.nums.cost, wall: r.nums.wall },
      bw,
    ) * 1000) / 1000
  }
  // Re-score through pickWinner for deterministic tie-breaking; keep both.
  const winner = LoopPhysics.pickWinner(runs)

  // Markdown table — sorted best-first so the operator sees the Pareto head.
  const sorted = [...runs].sort((a, b) => b.score - a.score)
  const table = [
    "| rank | frontier_k | instances | high | total | cov% | cost$ | wall_s | score |",
    "|---|---|---|---|---|---|---|---|---|",
    ...sorted.map((r, idx) =>
      `| ${idx + 1} | ${r.frontierK} | ${r.instances} | ${r.nums.high} | ${r.nums.total} | ${r.nums.cov} | ${r.nums.cost.toFixed(4)} | ${r.nums.wall.toFixed(2)} | ${r.score.toFixed(3)} |`),
  ].join("\n")
  process.stdout.write(table + "\n")

  console.log(`METRIC tune_grid_size=${runs.length}`)
  console.log(`METRIC tune_best_score=${winner?.score ?? 0}`)
  console.log(`METRIC tune_best_frontier_k=${winner?.frontierK ?? -1}`)
  console.log(`METRIC tune_best_instances=${winner?.instances ?? -1}`)
  console.log(`METRIC tune_worst_score=${Math.min(...runs.map((r) => r.score))}`)

  const productive = runs.some((r) => r.nums.total > 0 || r.nums.cov > 0)
  if (!productive) {
    process.stderr.write("bench:tune: no run produced findings/coverage — refusing to persist a tuning from a dead fixture\n")
    process.exit(1)
  }

  const outPath = path.resolve(readEnv("TUNE_OUT", path.join(".openhack", "harness-tuning.json")))
  fs.mkdirSync(path.dirname(outPath), { recursive: true })
  fs.writeFileSync(outPath, JSON.stringify({
    target,
    tunedAt: new Date().toISOString(),
    rounds,
    mode,
    weights: LoopPhysics.TUNER_WEIGHTS,
    recommended: { frontier_k: winner!.frontierK, instances: winner!.instances },
    grid: sorted.map((r) => ({
      frontier_k: r.frontierK,
      instances: r.instances,
      score: r.score,
      high: r.nums.high,
      total: r.nums.total,
      coverage_percent: r.nums.cov,
      cost_usd: r.nums.cost,
      wall_seconds: r.nums.wall,
    })),
  }, null, 2) + "\n")
  console.log(`METRIC tune_out=${outPath}`)
  process.stdout.write(`bench:tune: winner frontier_k=${winner!.frontierK} instances=${winner!.instances} → ${outPath}\n`)
}

main().catch((e) => {
  process.stderr.write(`bench:tune failed: ${e?.stack ?? e}\n`)
  process.exit(1)
})
