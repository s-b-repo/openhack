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
    seam: "native Rust agent-runtime library (artifact probe via `openhack vendors`)",
    kind: "library",
    pathName: "-",
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
}

const bootstraps = new Map<string, { failed: boolean; error: string | null }>()

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
    }
  })
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
 */
export async function bootstrap(name: string, timeoutMs = 900_000): Promise<BootstrapResult> {
  const component = COMPONENTS.find((c) => c.name === name)
  if (!component)
    return { name, ok: false, code: null, output: "", error: `unknown vendored component: ${name} (known: ${COMPONENTS.map((c) => c.name).join(", ")})` }
  const root = repoRoot()
  if (!root)
    return { name, ok: false, code: null, output: "", error: "no repository root (vendor/ not found) — run from inside the openhack repository" }
  const script = path.join(root, component.bootstrap)
  if (!exists(script)) return { name, ok: false, code: null, output: "", error: `bootstrap script missing: ${component.bootstrap}` }
  const result = await Exec.execBounded("bash", [script], { timeoutMs, cwd: path.dirname(script) })
  const output = `${result.stdout}${result.stderr}`
  if (result.timedOut) {
    const message = `bootstrap timed out after ${timeoutMs}ms`
    bootstraps.set(name, { failed: true, error: message })
    return { name, ok: false, code: null, output, error: message }
  }
  if (result.spawnError) {
    bootstraps.set(name, { failed: true, error: result.spawnError })
    return { name, ok: false, code: null, output, error: result.spawnError }
  }
  if (result.code === 0) {
    bootstraps.set(name, { failed: false, error: null })
    return { name, ok: true, code: 0, output, error: null }
  }
  const message = `bootstrap exited ${result.code}`
  bootstraps.set(name, { failed: true, error: message })
  return { name, ok: false, code: result.code, output, error: message }
}

const sourceLabel = (source: ResolutionSource): string =>
  source === "env" ? "env override" : source === "vendored" ? "vendored" : source === "path" ? "PATH" : "MISSING"

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
