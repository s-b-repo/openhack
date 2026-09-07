export * as Vendors from "./vendors"

import fs from "node:fs"
import path from "node:path"
import { Exec } from "./exec"

/**
 * Registry of every vendored framework component (`vendor/`). One module owns
 * resolution, status probing and bootstrapping for all of them so nothing in
 * `vendor/` is decoration: each entry names the framework seam it powers, and
 * `openhack vendors` reports the live resolution state of every artifact.
 *
 * Resolution order (same contract as every bridge):
 *   1. the component's explicit env override (e.g. `DCR_BIN`)
 *   2. the vendored artifact inside this repository (pinned, no global install)
 *   3. a legacy install on PATH
 */

export type Kind = "engine" | "backend" | "library" | "server"

/**
 * Probe — a bounded, optional smoke check for a component's artifact. Probes
 * are declared alongside the component and run via `Vendors.probe(name)`. Each
 * probe reports its result to `probeResults` (never thrown away) and is
 * skipped (with a recorded "skipped" result) when its prerequisites are missing.
 */
export type ProbeResult = { ok: true; detail: string } | { ok: false; detail: string; skipped?: boolean }
export type ProbeFn = (rootDir: string) => Promise<ProbeResult>

export interface Component {
  name: string
  /** Directory under `vendor/`. */
  dir: string
  /** Vendored artifact path relative to the repo root. */
  artifact: string
  /** Additional artifact candidates (e.g. workspace-local node_modules). */
  altArtifacts?: string[]
  /** Env var override for the artifact. */
  env: string
  /** Idempotent bootstrap script relative to the repo root. */
  bootstrap: string
  /** The framework seam this component powers — why it is vendored. */
  seam: string
  kind: Kind
  /** Bare name used for the PATH fallback ("-" = no PATH fallback). */
  pathName: string
  /** Optional bounded smoke checks for the component's artifacts. */
  probes?: ProbeFn[]
}

export const COMPONENTS: Component[] = [
  {
    name: "lattice",
    dir: "lattice",
    artifact: "vendor/lattice/.venv/bin/lattice",
    env: "OPENHACK_LATTICE_BIN",
    bootstrap: "vendor/lattice/bootstrap.sh",
    seam: "/codeaudit · write-path structural gate · read-path annotations · source-code-audit orchestrator",
    kind: "engine",
    pathName: "lattice",
  },
  {
    name: "dcr",
    dir: "subnext",
    artifact: "vendor/subnext/bin/dcr",
    env: "DCR_BIN",
    bootstrap: "vendor/subnext/bootstrap.sh",
    seam: "Dynamic Context Runtime — budgeted working sets for V1 and V2 sessions",
    kind: "engine",
    pathName: "dcr",
  },
  {
    name: "mini-swe-agent",
    dir: "mini-swe-agent",
    artifact: "vendor/mini-swe-agent/.venv/bin/mini",
    env: "OPENHACK_MINI_BIN",
    bootstrap: "vendor/mini-swe-agent/bootstrap.sh",
    seam: "automode execution backend (TaskSpec.runner = mini-swe)",
    kind: "backend",
    pathName: "mini",
  },
  {
    name: "gpt-researcher",
    dir: "gpt-researcher",
    artifact: "vendor/gpt-researcher/.venv/bin/python",
    env: "OPENHACK_GPT_RESEARCHER_BIN",
    bootstrap: "vendor/gpt-researcher/bootstrap.sh",
    seam: "osint deep-research MCP server (mcp.osint-research)",
    kind: "backend",
    pathName: "-",
  },
  {
    name: "deepagents",
    dir: "deepagents",
    artifact: "vendor/deepagents/.venv/bin/python",
    env: "OPENHACK_DEEPAGENTS_BIN",
    bootstrap: "vendor/deepagents/bootstrap.sh",
    seam: "manager planning backend (managers.backend = deepagents)",
    kind: "backend",
    pathName: "-",
  },
  {
    name: "langgraph",
    dir: "langgraph",
    artifact: "node_modules/@langchain/langgraph/package.json",
    altArtifacts: ["packages/openhack-orchestration/node_modules/@langchain/langgraph/package.json"],
    env: "",
    bootstrap: "vendor/langgraph/bootstrap.sh",
    seam: "graph round-engine (graph.round_engine = langgraph)",
    kind: "library",
    pathName: "-",
  },
  {
    name: "graphbit",
    dir: "graphbit",
    artifact: "vendor/graphbit/target/release",
    env: "OPENHACK_GRAPHBIT_LIB",
    bootstrap: "vendor/graphbit/bootstrap.sh",
    seam: "native Rust agent-runtime library + Python bindings (PyO3); smoke probe in `Vendors.probe(\"graphbit\")`",
    kind: "library",
    pathName: "-",
    probes: [
      // Node probe: bounded check of the Rust library artifact directory.
      // Recorded as skipped (never swallowed) when the dir doesn't exist.
      async (rootDir) => {
        const dir = path.join(rootDir, "vendor", "graphbit", "target", "release")
        try {
          if (!fs.existsSync(dir))
            return { ok: false, skipped: true, detail: `rust library not built: ${dir} (run \`openhack vendors --bootstrap graphbit\`)` }
          const files = fs.readdirSync(dir).filter((name) => /^libgraphbit.*\.so$/.test(name) || /^libgraphbit.*\.dylib$/.test(name) || /^graphbit.*\.dll$/.test(name))
          if (!files.length) return { ok: false, detail: `rust library dir exists but no libgraphbit shared objects (${dir})` }
          return { ok: true, detail: `rust library present: ${files.length} shared object(s) (${files.slice(0, 3).join(", ")}${files.length > 3 ? ", …" : ""})` }
        } catch (error) {
          return { ok: false, detail: `probe error: ${error instanceof Error ? error.message : String(error)}` }
        }
      },
      // Python binding probe: a bounded `python3 -c "import graphbit"` import.
      // Recorded as skipped (with the build hint) when the module isn't
      // installed — this is the documented boundary between two SDK generations
      // and never thrown away.
      async (rootDir) => {
        const script = "import graphbit; graphbit.init(); print(getattr(graphbit, '__version__', 'unknown'))"
        const result = await Exec.execBounded("python3", ["-c", script], { timeoutMs: 10_000, cwd: rootDir })
        if (result.spawnError) return { ok: false, skipped: true, detail: `python3 unavailable: ${result.spawnError}` }
        if (result.timedOut) return { ok: false, detail: "python3 import probe timed out" }
        if (result.code !== 0) {
          const message = result.stderr.trim().split("\n").pop() ?? `python3 exited ${result.code}`
          return { ok: false, skipped: true, detail: `python binding not installed: ${message} (run \`openhack vendors --bootstrap graphbit --with-python\`)` }
        }
        return { ok: true, detail: `python binding imports cleanly: graphbit ${result.stdout.trim() || "unknown"}` }
      },
    ],
  },
  {
    name: "temporal",
    dir: "temporal",
    artifact: "vendor/temporal/bin/temporal-server",
    env: "OPENHACK_TEMPORAL_BIN",
    bootstrap: "vendor/temporal/bootstrap.sh",
    seam: "durable round mirror (temporal.enabled) · infra docker-compose service",
    kind: "server",
    pathName: "temporal",
  },
]

/** Walk up from cwd to the repository root (the directory containing `vendor/`). */
export function repoRoot(): string | null {
  let directory = process.cwd()
  for (let depth = 0; depth < 8; depth++) {
    try {
      if (fs.existsSync(path.join(directory, "vendor"))) return directory
    } catch {}
    const parent = path.dirname(directory)
    if (parent === directory) break
    directory = parent
  }
  return null
}

const exists = (p: string): boolean => {
  try {
    return fs.existsSync(p)
  } catch {
    return false
  }
}

const onPath = (name: string): string | null => {
  if (name === "-") return null
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue
    const candidate = path.join(dir, name)
    if (exists(candidate)) return candidate
  }
  return null
}

export type ResolutionSource = "env" | "vendored" | "path" | null

export interface Resolution {
  /** Absolute path to the resolved artifact, or null. */
  bin: string | null
  source: ResolutionSource
}

/**
 * Resolve a component by name. `langgraph` resolves through node_modules (the
 * npm dep is the wired artifact); everything else follows env → vendored → PATH.
 */
export function resolve(name: string): Resolution {
  const component = COMPONENTS.find((c) => c.name === name)
  if (!component) return { bin: null, source: null }
  if (component.env) {
    const override = process.env[component.env]
    if (override) {
      // Bare overrides (e.g. DCR_BIN=dcr) fall through to vendored/PATH lookup;
      // path-shaped overrides are used as-is.
      if (override.includes("/")) return exists(override) ? { bin: path.resolve(override), source: "env" } : { bin: null, source: "env" }
      const bare = onPath(override)
      if (bare) return { bin: bare, source: "env" }
      const root = repoRoot()
      if (root && exists(path.join(root, "vendor", component.dir, "bin", override)))
        return { bin: path.join(root, "vendor", component.dir, "bin", override), source: "env" }
    }
  }
  const root = repoRoot()
  if (root) {
    const artifact = path.join(root, component.artifact)
    if (exists(artifact)) return { bin: artifact, source: "vendored" }
    for (const alt of component.altArtifacts ?? []) {
      const candidate = path.join(root, alt)
      if (exists(candidate)) return { bin: candidate, source: "vendored" }
    }
  }
  const fallback = onPath(component.pathName)
  if (fallback) return { bin: fallback, source: "path" }
  return { bin: null, source: null }
}

export interface ComponentStatus extends Resolution {
  name: string
  kind: Kind
  seam: string
  env: string
  bootstrap: string
  /** True when a prior bootstrap attempt failed (error kept in `bootstrapError`). */
  bootstrapFailed: boolean
  bootstrapError: string | null
  /** Number of declared probes (per-component, for `format` summary). */
  probeCount: number
}

const bootstraps = new Map<string, { failed: boolean; error: string | null }>()
const probeResults = new Map<string, ProbeResult[]>()

/** Status of every component (or one, by name) — the live `vendor/` wiring report. */
export function status(name?: string): ComponentStatus[] {
  const components = name ? COMPONENTS.filter((c) => c.name === name) : COMPONENTS
  return components.map((component) => {
    const resolution = resolve(component.name)
    const boot = bootstraps.get(component.name)
    return {
      name: component.name,
      kind: component.kind,
      seam: component.seam,
      env: component.env,
      bootstrap: component.bootstrap,
      bin: resolution.bin,
      source: resolution.source,
      bootstrapFailed: boot?.failed ?? false,
      bootstrapError: boot?.error ?? null,
      probeCount: component.probes?.length ?? 0,
    }
  })
}

export interface ProbeReport {
  name: string
  results: ProbeResult[]
}

const PROBE_TIMEOUT_MS = 15_000

/**
 * Run every probe declared for `name`, bounded, in declaration order. Results
 * are cached in `probeResults` and returned to the caller — failures and
 * skipped steps are both recorded (no silent swallowing).
 */
export async function probe(name: string, opts: { timeoutMs?: number } = {}): Promise<ProbeReport> {
  const component = COMPONENTS.find((c) => c.name === name)
  if (!component) return { name, results: [] }
  const root = repoRoot()
  if (!root) {
    const skip: ProbeResult = { ok: false, skipped: true, detail: "no repository root (vendor/ not found)" }
    probeResults.set(name, [skip])
    return { name, results: [skip] }
  }
  const timeout = opts.timeoutMs ?? PROBE_TIMEOUT_MS
  const probes = component.probes ?? []
  const settled: ProbeResult[] = []
  for (const fn of probes) {
    try {
      const result = await Promise.race([
        fn(root),
        new Promise<ProbeResult>((resolve) => setTimeout(() => resolve({ ok: false, detail: `probe timed out after ${timeout}ms` }), timeout)),
      ])
      settled.push(result)
    } catch (error) {
      settled.push({ ok: false, detail: `probe threw: ${error instanceof Error ? error.message : String(error)}` })
    }
  }
  probeResults.set(name, settled)
  return { name, results: settled }
}

/** Last probe results per component (empty array when never probed). */
export function lastProbe(name: string): ProbeResult[] {
  return probeResults.get(name) ?? []
}

export interface BootstrapResult {
  name: string
  ok: boolean
  code: number | null
  output: string
  error: string | null
}

/**
 * Run a component's idempotent bootstrap script (bounded). Failures are
 * returned and recorded in `status()` — never thrown away.
 *
 * `opts.withPython` is honored only by `graphbit` (and any future component
 * that declares a Python binding) — it runs the `maturin develop` step in
 * addition to the Rust build, marked idempotent by a sentinel file in the
 * component's Python source tree.
 */
export async function bootstrap(name: string, opts: { timeoutMs?: number; withPython?: boolean } = {}): Promise<BootstrapResult> {
  const component = COMPONENTS.find((c) => c.name === name)
  if (!component)
    return { name, ok: false, code: null, output: "", error: `unknown vendored component: ${name} (known: ${COMPONENTS.map((c) => c.name).join(", ")})` }
  const root = repoRoot()
  if (!root)
    return { name, ok: false, code: null, output: "", error: "no repository root (vendor/ not found) — run from inside the openhack repository" }
  const script = path.join(root, component.bootstrap)
  if (!exists(script)) return { name, ok: false, code: null, output: "", error: `bootstrap script missing: ${component.bootstrap}` }
  const timeoutMs = opts.timeoutMs ?? 900_000
  const result = await Exec.execBounded("bash", [script], { timeoutMs, cwd: path.dirname(script) })
  let output = `${result.stdout}${result.stderr}`
  let combinedOk = true
  let combinedMessage: string | null = null

  const record = (ok: boolean, message: string | null) => {
    bootstraps.set(name, { failed: !ok, error: message })
    if (!ok) {
      combinedOk = false
      combinedMessage = message
    }
  }

  if (result.timedOut) {
    record(false, `bootstrap timed out after ${timeoutMs}ms`)
    return { name, ok: false, code: null, output, error: `bootstrap timed out after ${timeoutMs}ms` }
  }
  if (result.spawnError) {
    record(false, result.spawnError)
    return { name, ok: false, code: null, output, error: result.spawnError }
  }
  if (result.code !== 0) {
    const message = `bootstrap exited ${result.code}`
    record(false, message)
    return { name, ok: false, code: result.code, output, error: message }
  }
  record(true, null)

  // Optional Python binding step (e.g. graphbit's `maturin develop`).
  if (opts.withPython && name === "graphbit") {
    const pyResult = await bootstrapGraphbitPython(root)
    output = `${output}\n${pyResult.output}`.trim()
    if (!pyResult.ok) {
      combinedOk = false
      combinedMessage = pyResult.error
      bootstraps.set(name, { failed: true, error: pyResult.error })
      return { name, ok: false, code: pyResult.code, output, error: pyResult.error }
    }
  }

  if (!combinedOk) {
    return { name, ok: false, code: null, output, error: combinedMessage ?? "bootstrap failed" }
  }
  return { name, ok: true, code: 0, output, error: null }
}

const graphbitPythonSentinel = ".graphbit-python-built"

const bootstrapGraphbitPython = async (root: string): Promise<{ ok: boolean; code: number | null; output: string; error: string | null }> => {
  const pyDir = path.join(root, "vendor", "graphbit", "python")
  if (!exists(pyDir)) return { ok: false, code: null, output: "", error: `graphbit python source tree missing: ${pyDir}` }
  const sentinel = path.join(pyDir, graphbitPythonSentinel)
  if (exists(sentinel) && process.env.FORCE !== "1") {
    return { ok: true, code: 0, output: `graphbit python binding already built (sentinel: ${graphbitPythonSentinel})`, error: null }
  }
  const venvPython = path.join(root, "vendor", "graphbit", ".venv", "bin", "python")
  const sysPython = exists(venvPython) ? venvPython : "python3"
  const result = await Exec.execBounded(sysPython, ["-m", "pip", "install", "--break-system-packages", "-e", "."], {
    timeoutMs: 10 * 60_000,
    cwd: pyDir,
  })
  const output = `${result.stdout}${result.stderr}`
  if (result.spawnError) return { ok: false, code: null, output, error: `pip not runnable: ${result.spawnError}` }
  if (result.timedOut) return { ok: false, code: null, output, error: "graphbit python install timed out" }
  if (result.code !== 0) {
    const tail = result.stderr.trim().split("\n").slice(-3).join("\n")
    return { ok: false, code: result.code, output, error: `graphbit python install exited ${result.code}: ${tail}` }
  }
  try {
    fs.writeFileSync(sentinel, new Date().toISOString())
  } catch (error) {
    // Sentinel is a best-effort accelerator; missing it just means the next
    // bootstrap may re-run pip. We still record the issue (never silent).
    return { ok: true, code: 0, output: `${output}\n(warning: failed to write sentinel: ${error instanceof Error ? error.message : String(error)})`, error: null }
  }
  return { ok: true, code: 0, output: `${output}\ngraphbit python binding installed (sentinel: ${graphbitPythonSentinel})`, error: null }
}

const sourceLabel = (source: ResolutionSource): string =>
  source === "env" ? "env override" : source === "vendored" ? "vendored" : source === "path" ? "PATH" : "MISSING"

/** Render a single probe-report block (header + bullet list). */
export function formatProbe(report: ProbeReport): string {
  if (!report.results.length) return `  probe(${report.name}): no probes declared`
  const lines = [`  probe(${report.name}):`]
  for (const [index, result] of report.results.entries()) {
    const tag = result.ok ? "OK  " : result.skipped ? "SKIP" : "FAIL"
    lines.push(`    [${tag}] ${index + 1}: ${result.detail}`)
  }
  return lines.join("\n")
}

/** Render component statuses as a text table for the CLI. */
export function format(statuses: ComponentStatus[]): string {
  const rows = statuses.map((s) => ({
    name: s.name,
    status: s.bin ? sourceLabel(s.source) : s.bootstrapFailed ? "MISSING (bootstrap failed)" : "MISSING",
    where: s.bin ? (s.source === "vendored" ? s.bootstrap : s.bin) : s.bootstrapError ?? `bash ${s.bootstrap}`,
    seam: s.seam,
  }))
  const width = (key: keyof (typeof rows)[number]) => Math.max(...rows.map((r) => r[key].length), key.length)
  const [wn, ws, ww] = [width("name"), width("status"), width("where")]
  const line = `  ${"component".padEnd(wn)}  ${"status".padEnd(ws)}  ${"resolved via".padEnd(ww)}  seam`
  const rule = `  ${"-".repeat(wn)}  ${"-".repeat(ws)}  ${"-".repeat(ww)}  ${"-".repeat(4)}`
  const body = rows.map((r) => `  ${r.name.padEnd(wn)}  ${r.status.padEnd(ws)}  ${r.where.padEnd(ww)}  ${r.seam}`)
  return [line, rule, ...body].join("\n")
}
