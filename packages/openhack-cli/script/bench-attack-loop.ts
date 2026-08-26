// Attack-loop performance harness. Runs `runOrchestrationLoop` end-to-end
// against a deterministic mock LLM factory (no network, no cost), reads the
// per-round artefacts the loop already produces (findings, coverage, session
// log), and emits METRIC lines the compare script (`bench-attack-loop-compare.ts`)
// can diff across git revisions.
//
// Env:
//   BENCH_TARGET=example.com      (required)
//   BENCH_ROUNDS=5                (int; max loop rounds)
//   BENCH_MODE=graph|static       (with or without the AttackGraph controller)
//   BENCH_FIXTURE=perf/fixtures/site1.json   (canned findings/coverage seeds)
//   BENCH_COVERAGE_TARGET=90      (optional; % that terminates the loop)
//   BENCH_FRONTIER_K=6            (graph frontier width per round)
//   BENCH_INSTANCES=1             (parallel instances per objective; keep low for perf)
//   BENCH_OUT=perf/results/<sha>.json   (optional; JSON dump alongside METRIC lines)
//
// Emits (one METRIC line each — see the plan file for the full list):
//   METRIC loop_rounds_to_goal, loop_wall_seconds, loop_first_critical_seconds,
//          loop_first_critical_cost_usd, loop_total_cost_usd,
//          loop_tokens_in, loop_tokens_out, loop_findings_total, loop_findings_high,
//          loop_coverage_percent, loop_frontier_size_final, loop_frontier_size_p50,
//          loop_controller_ms_p50, loop_task_tool_p50_ms, loop_task_tool_p95_ms,
//          loop_block_ratio, loop_terminate_reason
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { runOrchestrationLoop, type LlmFactory, type LlmFn } from "../src/cli/cmd/openhack.automode"
import { AttackGraph, GraphStore, LoopPhysics } from "../../openhack-orchestration/src"
import { Findings } from "../../openhack/src/findings"
import { Coverage } from "../../openhack/src/coverage"

interface Fixture {
  findings?: Array<{
    title: string
    severity: "critical" | "high" | "medium" | "low" | "info"
    status?: "verified" | "uncertain" | "false_positive"
    cwe?: string
    affected_component?: string
  }>
  coverage?: {
    endpoints?: Array<{ endpoint: string; method: string; classes?: Array<{ id: string; result?: string }> }>
  }
  /** For each round index (1-based), how much output/tokens/cost each mock LLM
   *  call should report. Cycles if the loop runs more rounds than provided. */
  perRound?: Array<{ tokensIn?: number; tokensOut?: number; cost?: number; newCriticalOnFirstCall?: boolean }>
}

function readEnvInt(k: string, def: number): number {
  const v = process.env[k]
  if (!v) return def
  const n = parseInt(v, 10)
  return Number.isFinite(n) ? n : def
}

function readEnv(k: string, def: string): string {
  return process.env[k] ?? def
}

function loadFixture(fp: string | undefined): Fixture {
  if (!fp) return {}
  try {
    return JSON.parse(fs.readFileSync(fp, "utf-8"))
  } catch (e) {
    process.stderr.write(`bench:loop: could not read fixture ${fp}: ${e}\n`)
    return {}
  }
}

function seedFromFixture(target: string, f: Fixture): void {
  // Coverage seed → real Coverage.mark() cells (untested by default so gaps stay non-empty).
  if (f.coverage?.endpoints) {
    let store = Coverage.load(target)
    for (const ep of f.coverage.endpoints) {
      Coverage.addEndpoint(store, ep.endpoint, ep.method)
      for (const cls of ep.classes ?? []) {
        store = Coverage.mark(store, {
          endpoint: ep.endpoint,
          method: ep.method,
          classId: cls.id,
          result: (cls.result as any) ?? "untested",
        })
      }
    }
  }
  // Findings seed → real Findings.add so the loop's convergence math sees them.
  const fs2 = Findings.load(target)
  for (const spec of f.findings ?? []) {
    Findings.add(fs2, {
      id: "",
      timestamp: new Date().toISOString(),
      target,
      title: spec.title,
      description: `[fixture] ${spec.title}`,
      severity: spec.severity,
      status: spec.status ?? "uncertain",
      cwe: spec.cwe,
      affected_component: spec.affected_component,
      source_agent: "fixture",
      source_session: "bench",
      evidence_files: [],
      manual_verify_required: (spec.status ?? "uncertain") !== "verified",
      audit_trail: [],
      promotionChain: [],
      challengedByCouncils: [],
      hash: "",
      hmac: "",
      tags: [],
    })
  }
}

/** Deterministic mock factory. Records per-call latency + tokens for percentile
 *  stats, plus per-agent and macro-dispatch breakdowns for richer regression
 *  comparisons across git revisions. */
function makeMockFactory(
  fixture: Fixture,
  taskTiming: number[],
  perAgentTiming: Record<string, number[]>,
  perAgentTokens: Record<string, { in: number; out: number }>,
  macroTiming: number[],
  macroDispatchCount: { count: number; byName: Record<string, number> },
  target: string,
  firstCriticalRef: { at?: number; cost?: number },
  startedAt: number,
): { factory: LlmFactory; totalCost: () => number; totalTokens: () => { in: number; out: number } } {
  let call = 0
  let round = 1
  let firstCallOfRound = true
  let totalCost = 0
  let tokensIn = 0
  let tokensOut = 0

  const buildFn = (opts: { agent?: string; command?: string }): LlmFn => async (prompt) => {
    call++
    const agent = opts.agent ?? "unknown"
    const start = performance.now()
    // Simulate a small amount of "work" so timings aren't zero.
    await new Promise((r) => setTimeout(r, 1))
    const roundSpec = fixture.perRound?.[(round - 1) % (fixture.perRound?.length || 1)]
    const tIn = roundSpec?.tokensIn ?? 400
    const tOut = roundSpec?.tokensOut ?? 200
    const cost = roundSpec?.cost ?? 0.001
    tokensIn += tIn
    tokensOut += tOut
    totalCost += cost

    // Per-agent + macro-dispatch bookkeeping.
    ;(perAgentTokens[agent] ??= { in: 0, out: 0 }).in += tIn
    perAgentTokens[agent]!.out += tOut

    // Model side-effects: on the first call of a round the fixture may ask us to
    // inject a fresh critical finding (so the convergence check doesn't
    // short-circuit and the graph controller has something to grow from).
    if (firstCallOfRound) {
      firstCallOfRound = false
      if (roundSpec?.newCriticalOnFirstCall) {
        const store = Findings.load(target)
        const id = Findings.generateId()
        Findings.add(store, {
          id: "",
          timestamp: new Date().toISOString(),
          target,
          title: `Mock critical r${round} #${id}`,
          description: `[mock] round=${round}`,
          severity: "critical",
          status: "uncertain",
          source_agent: "mock",
          source_session: "bench",
          evidence_files: [],
          manual_verify_required: true,
          audit_trail: [],
          promotionChain: [],
          challengedByCouncils: [],
          hash: "",
          hmac: "",
          tags: [],
        })
        if (firstCriticalRef.at === undefined) {
          firstCriticalRef.at = (performance.now() - startedAt) / 1000
          firstCriticalRef.cost = totalCost
        }
      }
    }
    const dur = performance.now() - start
    taskTiming.push(dur)
    ;(perAgentTiming[agent] ??= []).push(dur)
    if (opts.command) {
      macroTiming.push(dur)
      macroDispatchCount.count++
      macroDispatchCount.byName[opts.command] = (macroDispatchCount.byName[opts.command] ?? 0) + 1
    }
    return { output: `mock out ${call}`, tokensIn: tIn, tokensOut: tOut, cost }
  }

  // Factory accepts either a bare agent string OR the {agent, command, model} opts bag.
  const factory: LlmFactory = (agentOrOpts) => {
    const opts = typeof agentOrOpts === "string" || agentOrOpts == null
      ? { agent: agentOrOpts ?? undefined }
      : agentOrOpts
    return buildFn(opts)
  }
  return {
    factory,
    totalCost: () => totalCost,
    totalTokens: () => ({ in: tokensIn, out: tokensOut }),
  }
}

function pct(sorted: number[], p: number): number {
  if (!sorted.length) return 0
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[idx] ?? 0
}

function median(arr: number[]): number { return pct([...arr].sort((a, b) => a - b), 50) }
function p95(arr: number[]): number { return pct([...arr].sort((a, b) => a - b), 95) }
function p99(arr: number[]): number { return pct([...arr].sort((a, b) => a - b), 99) }
function mean(arr: number[]): number { return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0 }
function stddev(arr: number[]): number {
  if (arr.length < 2) return 0
  const m = mean(arr)
  return Math.sqrt(arr.reduce((s, x) => s + (x - m) ** 2, 0) / arr.length)
}

/**
 * Compact fixed-bucket histogram — 8 log-spaced buckets covering 0-10s. Emitted
 * as one comma-separated string per metric so downstream compare scripts can
 * diff the distribution shape, not just the median.
 */
function histogram(values: number[]): string {
  const buckets = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
  const counts = new Array(buckets.length + 1).fill(0)
  for (const v of values) {
    let i = 0
    while (i < buckets.length && v > buckets[i]!) i++
    counts[i]++
  }
  // Labels: <=1ms, <=2ms, ..., >10s
  const labels = buckets.map((b) => `le${b}`).concat(["gt10000"])
  return labels.map((l, i) => `${l}:${counts[i]}`).join(",")
}

/** Peak RSS across polls — Bun's process.memoryUsage() is synchronous and cheap. */
function pollRss(peakRef: { rss: number }): void {
  const rss = process.memoryUsage().rss
  if (rss > peakRef.rss) peakRef.rss = rss
}

async function main() {
  const target = readEnv("BENCH_TARGET", "")
  if (!target) {
    process.stderr.write("bench:loop: BENCH_TARGET is required\n")
    process.exit(2)
  }
  const rounds = readEnvInt("BENCH_ROUNDS", 5)
  const mode = readEnv("BENCH_MODE", "graph")
  // Resolve fixture path BEFORE chdir'ing into the scratch dir so a relative
  // BENCH_FIXTURE is interpreted against the invoker's cwd, not the scratch.
  const fixturePath = process.env.BENCH_FIXTURE ? path.resolve(process.cwd(), process.env.BENCH_FIXTURE) : undefined
  const coverageTarget = process.env.BENCH_COVERAGE_TARGET ? Number(process.env.BENCH_COVERAGE_TARGET) : undefined
  const frontierK = readEnvInt("BENCH_FRONTIER_K", 6)
  const instances = readEnvInt("BENCH_INSTANCES", 1)

  // Isolated scratch cwd so the bench doesn't touch a real engagement.
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-bench-"))
  const origCwd = process.cwd()
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })

  const fixture = loadFixture(fixturePath)
  seedFromFixture(target, fixture)

  const taskTiming: number[] = []
  const perAgentTiming: Record<string, number[]> = {}
  const perAgentTokens: Record<string, { in: number; out: number }> = {}
  const macroTiming: number[] = []
  const macroDispatch = { count: 0, byName: {} as Record<string, number> }
  const firstCriticalRef: { at?: number; cost?: number } = {}
  const startedAt = performance.now()
  const mock = makeMockFactory(fixture, taskTiming, perAgentTiming, perAgentTokens, macroTiming, macroDispatch, target, firstCriticalRef, startedAt)
  // Sampled RSS timeline — one point every 50ms. Enables mean/min/max
  // regressions distinct from the peak, and drift-detection over long runs.
  const rssPeak = { rss: process.memoryUsage().rss }
  const rssSamples: number[] = [process.memoryUsage().rss]
  const rssPoller = setInterval(() => { const r = process.memoryUsage().rss; if (r > rssPeak.rss) rssPeak.rss = r; rssSamples.push(r) }, 50)

  const logLines: string[] = []
  const session = await runOrchestrationLoop(target, {
    maxRounds: rounds,
    makeLlmFn: mock.factory,
    plan: false,
    council: false,
    instances,
    graph: mode === "graph",
    frontierK,
    coverageTarget,
    log: (m) => { logLines.push(m) },
  })

  clearInterval(rssPoller)
  pollRss(rssPeak) // one final sample
  const wallSeconds = (performance.now() - startedAt) / 1000
  const findings = Findings.load(target)
  const cov = (() => { try { return Coverage.summary(Coverage.load(target)) } catch { return null } })()
  const highCount = findings.findings.filter((f) => (f.severity === "critical" || f.severity === "high") && f.status !== "false_positive").length

  const snap = mode === "graph" ? GraphStore.load(target) : null
  const frontierFinal = snap ? AttackGraph.frontier(snap, 100).length : 0

  // Approximate frontier p50 by reading the graph's queued+dispatched ActionNodes
  // (best-effort — we didn't sample per round). This is an aggregate view.
  const frontierP50 = snap
    ? (() => {
        const counts = Object.values(snap.nodes).filter((n: any) => n.status === "queued" || n.status === "dispatched").length
        return counts
      })()
    : 0

  const totals = mock.totalTokens()
  const totalCost = mock.totalCost()

  // Loop physics — mean per-instance transcript estimate and its retrieval-
  // fidelity verdict, plus the compounded reliability of one round's dispatch
  // batch (per-step DEFAULT_STEP_P over the mean objectives per round). These
  // make context-cliff and chain-decay regressions visible to the comparer.
  const dispatchCount = Math.max(1, taskTiming.length)
  const perInstanceTokens = Math.round((totals.in + totals.out) / dispatchCount)
  const ctx = LoopPhysics.ContextHealth.verdict(perInstanceTokens)
  const planReliability = LoopPhysics.Reliability.compound(LoopPhysics.DEFAULT_STEP_P, dispatchCount)

  const roundsRun = session.results.filter((r) => /council|planning|report/.test(r.id) === false || /council/.test(r.id))
    .length
  // Termination reason from the final log line — cheap best-effort parse.
  const terminationLine = [...logLines].reverse().find((l) => /Terminating:/.test(l)) ?? ""
  const reason = /coverage target/.test(terminationLine) ? "coverage"
    : /converged/.test(terminationLine) ? "convergence"
    : /budget/.test(terminationLine) ? "budget"
    : /ROE window/.test(terminationLine) ? "roe"
    : /frontier \+ coverage gaps both empty/.test(terminationLine) ? "frontier_empty"
    : "maxRounds"

  const controllerTimings = extractControllerTimings(logLines)
  const rssMb = Math.round((rssPeak.rss / 1024 / 1024) * 10) / 10
  const rssMinMb = Math.round((Math.min(...rssSamples) / 1024 / 1024) * 10) / 10
  const rssMeanMb = Math.round(((rssSamples.reduce((a, b) => a + b, 0) / rssSamples.length) / 1024 / 1024) * 10) / 10
  const rssP50Mb = Math.round((median(rssSamples) / 1024 / 1024) * 10) / 10
  // Per-agent breakdowns — comma-separated key:value pairs so the compare
  // script can diff them dimension-by-dimension without exploding the metric list.
  const dispatchByAgent = Object.entries(perAgentTiming)
    .map(([a, arr]) => `${a}:${arr.length}`)
    .sort()
    .join(",")
  const msP50ByAgent = Object.entries(perAgentTiming)
    .map(([a, arr]) => `${a}:${median(arr).toFixed(2)}`)
    .sort()
    .join(",")
  const tokensInByAgent = Object.entries(perAgentTokens)
    .map(([a, t]) => `${a}:${t.in}`)
    .sort()
    .join(",")
  const macroByName = Object.entries(macroDispatch.byName)
    .map(([n, c]) => `${n}:${c}`)
    .sort()
    .join(",")
  const metrics: Record<string, string | number> = {
    loop_rounds_to_goal: Math.min(rounds, Math.max(1, session.results.filter((r) => /council-r/.test(r.id)).length + 1)),
    loop_wall_seconds: wallSeconds.toFixed(3),
    loop_first_critical_seconds: (firstCriticalRef.at ?? -1).toFixed(3),
    loop_first_critical_cost_usd: (firstCriticalRef.cost ?? -1).toFixed(4),
    loop_total_cost_usd: totalCost.toFixed(4),
    loop_tokens_in: totals.in,
    loop_tokens_out: totals.out,
    loop_findings_total: findings.findings.length,
    loop_findings_high: highCount,
    loop_coverage_percent: cov?.percent ?? 0,
    loop_frontier_size_final: frontierFinal,
    loop_frontier_size_p50: frontierP50,
    loop_controller_ms_p50: median(controllerTimings).toFixed(2),
    loop_controller_ms_p95: p95(controllerTimings).toFixed(2),
    loop_controller_ms_p99: p99(controllerTimings).toFixed(2),
    loop_controller_ms_mean: mean(controllerTimings).toFixed(2),
    loop_controller_ms_stddev: stddev(controllerTimings).toFixed(2),
    loop_task_tool_p50_ms: median(taskTiming).toFixed(2),
    loop_task_tool_p95_ms: p95(taskTiming).toFixed(2),
    loop_task_tool_p99_ms: p99(taskTiming).toFixed(2),
    loop_task_tool_histogram: histogram(taskTiming),
    loop_controller_ms_histogram: histogram(controllerTimings),
    loop_block_ratio: computeBlockRatio(logLines).toFixed(3),
    loop_peak_rss_mb: rssMb,
    loop_min_rss_mb: rssMinMb,
    loop_mean_rss_mb: rssMeanMb,
    loop_p50_rss_mb: rssP50Mb,
    loop_rss_samples: rssSamples.length,
    loop_dispatch_count_by_agent: dispatchByAgent,
    loop_ms_p50_by_agent: msP50ByAgent,
    loop_tokens_in_by_agent: tokensInByAgent,
    loop_macro_dispatch_count: macroDispatch.count,
    loop_macro_dispatch_by_name: macroByName,
    loop_macro_ms_p50: median(macroTiming).toFixed(2),
    loop_macro_ms_p95: p95(macroTiming).toFixed(2),
    loop_terminate_reason: reason,
    loop_context_fidelity: ctx.fidelity,
    loop_context_band: ctx.band,
    loop_per_instance_tokens: perInstanceTokens,
    loop_plan_reliability: planReliability.toFixed(4),
  }

  for (const [k, v] of Object.entries(metrics)) console.log(`METRIC ${k}=${v}`)

  // Optional JSON dump for the compare script.
  const outPath = process.env.BENCH_OUT
  if (outPath) {
    const dir = path.dirname(path.resolve(origCwd, outPath))
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.resolve(origCwd, outPath), JSON.stringify({ target, mode, rounds, metrics }, null, 2))
    process.stderr.write(`bench:loop: wrote ${outPath}\n`)
  }

  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
}

function extractControllerTimings(logLines: string[]): number[] {
  const out: number[] = []
  const re = /graph: \+\d+n \+\d+e -\d+p;.*?; (\d+)ms/
  for (const l of logLines) {
    const m = re.exec(l)
    if (m && m[1]) out.push(Number(m[1]))
  }
  return out
}

function computeBlockRatio(logLines: string[]): number {
  let blocked = 0
  let total = 0
  for (const l of logLines) {
    const m = /blocked=(\d+)/.exec(l)
    if (m && m[1]) blocked += Number(m[1])
    if (/graph: \+(\d+)n/.exec(l)) total += Number(/graph: \+(\d+)n/.exec(l)![1]!)
  }
  return total ? blocked / total : 0
}

main().catch((e) => {
  process.stderr.write(`bench:loop failed: ${e?.stack ?? e}\n`)
  process.exit(1)
})
