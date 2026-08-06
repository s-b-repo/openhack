// Shared runtime primitives for every OpenHack MCP.
//
// Every openhack-mcp-* package ends up duplicating the same 100 lines of
// boilerplate — engagement-dir handling, env-var consent gates, ok/err/json
// tool responses, and the Server + StdioServerTransport bootstrap. This
// module centralizes them so a new MCP is ~40 lines of tools + one call
// to `startStdioServer(name, tools, handler)`.
//
// Zero non-obvious behavior: every function here does exactly what an MCP
// author would write by hand, with the same names. Migrating an existing
// MCP is a straight refactor, not a semantic change.

import { Server } from "@modelcontextprotocol/sdk/server/index.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
} from "@modelcontextprotocol/sdk/types.js"
import * as fs from "node:fs"
import * as path from "node:path"

// ─── tool response helpers ───────────────────────────────────────────────

/** Successful tool call result. */
export function ok(text: string) {
  return { content: [{ type: "text" as const, text }] }
}

/** Errored tool call result — sets `isError: true`. */
export function err(text: string) {
  return { content: [{ type: "text" as const, text }], isError: true }
}

/** Wrap a JSON payload as a fenced code block for readability in text UIs. */
export function jsonBlock(v: unknown): string {
  return "```json\n" + JSON.stringify(v, null, 2) + "\n```"
}

// ─── engagement dir ──────────────────────────────────────────────────────

/**
 * Resolve the engagement dir from `OPENHACK_ENGAGEMENT_DIR` (absolute path)
 * or fall back to `process.cwd()`. Every openhack MCP that reads/writes
 * `.openhack/` should use this so a single MCP can service multiple
 * concurrent engagements by spawning with different env values.
 */
export function resolveEngagementDir(): string {
  return process.env.OPENHACK_ENGAGEMENT_DIR
    ? path.resolve(process.env.OPENHACK_ENGAGEMENT_DIR)
    : process.cwd()
}

/**
 * Make the engagement dir the process's cwd (idempotent). Call once before
 * touching any `.openhack/*` path so relative paths inside the framework
 * modules resolve correctly.
 */
let _installedCwd = false
export function ensureCwd(engagementDir: string = resolveEngagementDir()): void {
  if (_installedCwd) return
  try { fs.mkdirSync(engagementDir, { recursive: true }) } catch {}
  try { process.chdir(engagementDir) } catch {}
  _installedCwd = true
}

// ─── consent gate ────────────────────────────────────────────────────────

export interface ConsentDecision {
  allowed: boolean
  reason?: string
}

export interface ConsentGateOptions {
  /**
   * The env var operator must set to allow the mutating tool (e.g.
   * `OPENHACK_CF_MCP_ALLOW_MUTATE`). Missing or empty → denied.
   */
  envVar: string
  /**
   * Optional strict-mode env var. When set to "1", the main env var's
   * VALUE must match the contents of `strictNoncePath`. Consumed once.
   */
  strictEnvVar?: string
  /** Relative path (from engagement dir) to the consent nonce file. */
  strictNoncePath?: string
  /**
   * Human-readable action name — surfaced in the deny reason so operators
   * know exactly which env var they need to set.
   */
  action?: string
}

/**
 * Two-tier consent gate:
 *   1. `envVar` must be set (non-empty). Denies otherwise.
 *   2. If `strictEnvVar=1`, the value must equal the contents of the nonce file.
 *
 * On successful gated mutation, callers should invoke `consumeNonce` to
 * enforce single-use in strict mode.
 */
export function checkConsent(opts: ConsentGateOptions): ConsentDecision {
  const env = process.env[opts.envVar]
  const action = opts.action ?? "This tool"
  if (!env) {
    return {
      allowed: false,
      reason: `${action} is disabled: set ${opts.envVar}=1 in the MCP env, then restart the MCP.`,
    }
  }
  if (opts.strictEnvVar && process.env[opts.strictEnvVar] === "1") {
    if (!opts.strictNoncePath) return { allowed: false, reason: `strict mode requested but no nonce path configured.` }
    let nonce: string | null = null
    try {
      nonce = fs.readFileSync(path.join(resolveEngagementDir(), opts.strictNoncePath), "utf-8").trim()
    } catch {
      return {
        allowed: false,
        reason: `strict mode: no consent nonce found at ${opts.strictNoncePath}. Operator: create it and set ${opts.envVar} to its contents.`,
      }
    }
    if (env !== nonce) {
      return { allowed: false, reason: `strict mode: env ${opts.envVar} does not match nonce file.` }
    }
  }
  return { allowed: true }
}

/** Delete the strict-mode nonce file after a successful sensitive operation. */
export function consumeNonce(strictNoncePath: string): void {
  try {
    fs.rmSync(path.join(resolveEngagementDir(), strictNoncePath))
  } catch {}
}

// ─── tool + handler shapes ───────────────────────────────────────────────

export interface ToolDef {
  name: string
  description: string
  inputSchema: any
}

export type ToolResult =
  | { content: Array<{ type: "text"; text: string }> }
  | { content: Array<{ type: "text"; text: string }>; isError: true }

export type ToolHandler = (
  name: string,
  args: Record<string, any>,
) => Promise<ToolResult>

// ─── stdio server bootstrap ──────────────────────────────────────────────

export interface StartServerOptions {
  /** MCP server name (surfaces in the client's server list). */
  name: string
  /** MCP server version. */
  version?: string
  /** Every tool the server advertises. */
  tools: ToolDef[]
  /** Called for every `tools/call`. Should return `ok(...)` / `err(...)`. */
  handle: ToolHandler
  /**
   * Optional. When the MCP touches `.openhack/*`, we chdir into the
   * engagement dir before spinning up so downstream code (framework
   * modules) sees the right cwd. Defaults to true.
   */
  chdirToEngagement?: boolean
  /**
   * Optional. Extra stderr text on startup (e.g. auth state, mutate-allowed).
   * Ends up in the parent's log stream — stdout is reserved for MCP RPC.
   */
  banner?: () => string
}

/**
 * Register a stdio MCP server + its tool set, connect the transport, and
 * write a startup banner to stderr. Never returns (`server.connect` awaits
 * the transport indefinitely).
 */
export async function startStdioServer(opts: StartServerOptions): Promise<void> {
  if (opts.chdirToEngagement !== false) ensureCwd()

  const server = new Server(
    { name: opts.name, version: opts.version ?? "0.1.0" },
    { capabilities: { tools: {} } },
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: opts.tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
  }))

  server.setRequestHandler(CallToolRequestSchema, async (req: CallToolRequest) => {
    const args = (req.params.arguments ?? {}) as Record<string, any>
    try {
      return await opts.handle(req.params.name, args)
    } catch (e: any) {
      return err(`Tool '${req.params.name}' threw: ${e?.message ?? e}`)
    }
  })

  const transport = new StdioServerTransport()
  await server.connect(transport)
  const banner = opts.banner ? opts.banner() : ""
  process.stderr.write(`[${opts.name}] ready${banner ? ` · ${banner}` : ""}\n`)
}

// ─── main-loop wrapper ───────────────────────────────────────────────────

/**
 * Wrap `startStdioServer` in a `main` promise that catches fatal errors and
 * prints them to stderr before exiting 1. Every MCP's `main()` boils down to:
 *
 *   runStdioMain({ name: "openhack-foo", tools: [...], handle: async (name, args) => { ... } })
 */
export function runStdioMain(opts: StartServerOptions): void {
  startStdioServer(opts).catch((e) => {
    process.stderr.write(`[${opts.name}] fatal: ${e?.stack ?? e}\n`)
    process.exit(1)
  })
}
