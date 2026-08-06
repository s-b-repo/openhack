import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process"

/**
 * End-to-end smoke test for the openhack-mcp-roe stdio server. Spawns the MCP,
 * speaks JSON-RPC over stdin/stdout, exercises every tool, and verifies:
 *
 *   - list_tools enumerates everything (incl. the new AI-model tools).
 *   - Read tools return the right shape when no ROE is loaded.
 *   - Draft creation + edits persist to `.openhack/roe/active.roe.json` (draft).
 *   - Sign is DENIED without the env-var opt-in.
 *   - Sign SUCCEEDS with OPENHACK_ROE_MCP_ALLOW_SIGN=1 in the child env.
 *   - After signing, roe_validate blocks out-of-scope targets AND unauthorized
 *     models (proving the runtime enforcement contract).
 *   - Revoke is DENIED without OPENHACK_ROE_MCP_ALLOW_REVOKE=1.
 *
 * We spawn the MCP inside a scratch cwd so no real engagement is touched.
 */

interface RpcResponse {
  jsonrpc: "2.0"
  id: number
  result?: any
  error?: any
}

let scratch: string
let origCwd: string
const repoRoot = path.resolve(__dirname, "../../..")

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-mcp-roe-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

/** Small JSON-RPC line-driven client bound to a child process. */
class RpcClient {
  private proc: ChildProcessWithoutNullStreams
  private buf = ""
  private nextId = 1
  private pending = new Map<number, (r: RpcResponse) => void>()

  constructor(env: NodeJS.ProcessEnv) {
    const script = path.join(repoRoot, "packages", "openhack-mcp-roe", "src", "index.ts")
    this.proc = spawn("bun", ["run", script], {
      env: { ...process.env, ...env, OPENHACK_ENGAGEMENT_DIR: scratch },
      stdio: "pipe",
    })
    this.proc.stdout.setEncoding("utf-8")
    this.proc.stderr.setEncoding("utf-8")
    this.proc.stdout.on("data", (chunk: string) => {
      this.buf += chunk
      let nl: number
      while ((nl = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, nl).trim()
        this.buf = this.buf.slice(nl + 1)
        if (!line) continue
        try {
          const msg = JSON.parse(line) as RpcResponse
          const cb = this.pending.get(msg.id)
          if (cb) { this.pending.delete(msg.id); cb(msg) }
        } catch { /* ignore non-JSON lines from the SDK if any */ }
      }
    })
  }

  send(method: string, params?: unknown): Promise<RpcResponse> {
    const id = this.nextId++
    const req = { jsonrpc: "2.0", id, method, params }
    return new Promise<RpcResponse>((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`rpc timeout on ${method}`)) }, 10_000)
      this.pending.set(id, (r) => { clearTimeout(timer); resolve(r) })
      this.proc.stdin.write(JSON.stringify(req) + "\n")
    })
  }

  async initialize(): Promise<void> {
    await this.send("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test", version: "0.0.1" },
    })
    // Some SDKs require the notifications/initialized ping. Fire-and-forget.
    this.proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n")
  }

  async listTools(): Promise<string[]> {
    const r = await this.send("tools/list", {})
    return (r.result?.tools ?? []).map((t: any) => t.name)
  }

  async callTool(name: string, args: Record<string, unknown> = {}): Promise<{ text: string; isError?: boolean }> {
    const r = await this.send("tools/call", { name, arguments: args })
    const content = r.result?.content?.[0]
    return { text: content?.text ?? "", isError: !!r.result?.isError }
  }

  kill(): void { try { this.proc.kill() } catch {} }
}

async function withClient(env: NodeJS.ProcessEnv, fn: (c: RpcClient) => Promise<void>): Promise<void> {
  const c = new RpcClient(env)
  try { await c.initialize(); await fn(c) } finally { c.kill() }
}

describe("openhack-mcp-roe — smoke", () => {
  test("tools/list includes reads, draft tools, model tools, and gated sign/revoke", async () => {
    await withClient({}, async (c) => {
      const names = await c.listTools()
      // Sample: reads
      expect(names).toContain("roe_status")
      expect(names).toContain("roe_validate")
      // Draft
      expect(names).toContain("roe_create_draft")
      expect(names).toContain("roe_set_targets")
      expect(names).toContain("roe_set_authorized_tools")
      expect(names).toContain("roe_set_expiry_days")
      // AI-models
      expect(names).toContain("roe_list_authorized_models")
      expect(names).toContain("roe_set_authorized_models")
      expect(names).toContain("roe_validate_model")
      expect(names).toContain("roe_add_authorized_model")
      expect(names).toContain("roe_remove_authorized_model")
      // Gated
      expect(names).toContain("roe_sign_current")
      expect(names).toContain("roe_revoke")
    })
  })

  test("read tools handle 'no ROE loaded' cleanly", async () => {
    await withClient({}, async (c) => {
      const s = await c.callTool("roe_status")
      expect(s.text).toContain("No ROE loaded")
      const t = await c.callTool("roe_list_authorized_tools")
      expect(t.text).toContain("[]")
      const m = await c.callTool("roe_list_authorized_models")
      expect(m.text).toContain("[]")
    })
  })

  test("draft flow: create → set targets/tools/models/expiry → get reflects edits", async () => {
    await withClient({}, async (c) => {
      await c.callTool("roe_create_draft", { company: "Acme", client: "Acme" })
      await c.callTool("roe_set_targets", { targets: ["golecloud.co.za", "*.golecloud.co.za"] })
      await c.callTool("roe_set_authorized_tools", { tools: ["nmap", "nuclei", "httpx", "sqlmap"] })
      await c.callTool("roe_set_authorized_models", { models: ["deepseek/deepseek-v4", "anthropic/claude-haiku-4-5"] })
      await c.callTool("roe_set_expiry_days", { days: 7 })
      await c.callTool("roe_add_authorized_model", { model: "google/gemini-2.5-flash" })
      const status = await c.callTool("roe_status")
      expect(status.text).toContain("golecloud.co.za")
      expect(status.text).toContain("nmap")
      const models = await c.callTool("roe_list_authorized_models")
      expect(models.text).toContain("deepseek/deepseek-v4")
      expect(models.text).toContain("anthropic/claude-haiku-4-5")
      expect(models.text).toContain("google/gemini-2.5-flash")
      // File on disk is a draft (no signature yet).
      const raw = JSON.parse(fs.readFileSync(path.join(scratch, ".openhack/roe/active.roe.json"), "utf-8"))
      expect(raw.status).toBe("draft")
      expect(raw.signature).toBeUndefined()
    })
  })

  test("sign is DENIED without OPENHACK_ROE_MCP_ALLOW_SIGN in the env", async () => {
    await withClient({}, async (c) => {
      await c.callTool("roe_create_draft")
      const r = await c.callTool("roe_sign_current")
      expect(r.isError).toBe(true)
      expect(r.text).toContain("OPENHACK_ROE_MCP_ALLOW_SIGN")
      const raw = JSON.parse(fs.readFileSync(path.join(scratch, ".openhack/roe/active.roe.json"), "utf-8"))
      expect(raw.status).toBe("draft")
    })
  })

  test("sign SUCCEEDS with OPENHACK_ROE_MCP_ALLOW_SIGN=1, and validate then reflects the signed doc", async () => {
    await withClient({ OPENHACK_ROE_MCP_ALLOW_SIGN: "1" }, async (c) => {
      await c.callTool("roe_create_draft")
      await c.callTool("roe_set_targets", { targets: ["golecloud.co.za"] })
      await c.callTool("roe_set_authorized_tools", { tools: ["nmap", "httpx"] })
      await c.callTool("roe_set_authorized_models", { models: ["deepseek/deepseek-v4", "anthropic/*"] })
      await c.callTool("roe_set_expiry_days", { days: 7 })
      const s = await c.callTool("roe_sign_current")
      expect(s.isError).toBeFalsy()
      expect(s.text).toMatch(/Signed ROE ROE-/)

      // Validate a tool that's allowed → not blocked.
      const okTool = await c.callTool("roe_validate", { target: "golecloud.co.za", tool: "nmap" })
      expect(okTool.text).toContain('"blocked": false')

      // Validate a tool that's NOT in authorized_tools → blocked.
      const badTool = await c.callTool("roe_validate", { target: "golecloud.co.za", tool: "sqlmap" })
      expect(badTool.text).toContain('"blocked": true')

      // Validate a model that's allowed (exact match).
      const okModel = await c.callTool("roe_validate_model", { model: "deepseek/deepseek-v4" })
      expect(okModel.text).toContain('"blocked": false')

      // Validate a model that's allowed via wildcard pattern.
      const okWildcard = await c.callTool("roe_validate_model", { model: "anthropic/claude-sonnet-4" })
      expect(okWildcard.text).toContain('"blocked": false')

      // Validate a model that's NOT allowed.
      const badModel = await c.callTool("roe_validate_model", { model: "openai/gpt-4o" })
      expect(badModel.text).toContain('"blocked": true')
    })
  })

  test("revoke is DENIED without OPENHACK_ROE_MCP_ALLOW_REVOKE", async () => {
    await withClient({ OPENHACK_ROE_MCP_ALLOW_SIGN: "1" }, async (c) => {
      await c.callTool("roe_create_draft")
      await c.callTool("roe_sign_current")
      const r = await c.callTool("roe_revoke")
      expect(r.isError).toBe(true)
      expect(r.text).toContain("OPENHACK_ROE_MCP_ALLOW_REVOKE")
    })
  })

  test("revoke SUCCEEDS with OPENHACK_ROE_MCP_ALLOW_REVOKE=1", async () => {
    await withClient({ OPENHACK_ROE_MCP_ALLOW_SIGN: "1", OPENHACK_ROE_MCP_ALLOW_REVOKE: "1" }, async (c) => {
      await c.callTool("roe_create_draft")
      await c.callTool("roe_sign_current")
      const r = await c.callTool("roe_revoke")
      expect(r.isError).toBeFalsy()
      expect(r.text).toMatch(/Revoked ROE/)
      const s = await c.callTool("roe_status")
      expect(s.text).toContain('"status": "revoked"')
    })
  })

  test("editing a signed ROE via a draft tool clears the signature (tamper detection)", async () => {
    await withClient({ OPENHACK_ROE_MCP_ALLOW_SIGN: "1" }, async (c) => {
      await c.callTool("roe_create_draft")
      await c.callTool("roe_set_targets", { targets: ["golecloud.co.za"] })
      await c.callTool("roe_set_authorized_tools", { tools: ["nmap"] })
      await c.callTool("roe_sign_current")
      // Now edit — this should demote the doc back to draft (no signature).
      await c.callTool("roe_add_authorized_model", { model: "openai/gpt-4o-mini" })
      const raw = JSON.parse(fs.readFileSync(path.join(scratch, ".openhack/roe/active.roe.json"), "utf-8"))
      expect(raw.status).toBe("draft")
      expect(raw.signature).toBeUndefined()
    })
  })

  test("editing a signed ROE preserves every non-mutated field (targets, tools, exclusions, dates)", async () => {
    // This is the regression test for the bug that wiped `targets` back to the
    // fresh-template defaults when any draft tool ran on a signed doc.
    await withClient({ OPENHACK_ROE_MCP_ALLOW_SIGN: "1" }, async (c) => {
      await c.callTool("roe_create_draft", { company: "Acme", client: "Golecloud" })
      await c.callTool("roe_set_targets", { targets: ["golecloud.co.za", "*.golecloud.co.za"] })
      await c.callTool("roe_set_authorized_tools", { tools: ["nmap", "httpx", "nuclei", "ffuf"] })
      await c.callTool("roe_set_authorized_models", { models: ["deepseek/deepseek-v4"] })
      await c.callTool("roe_set_exclusions", { exclusions: ["mail.golecloud.co.za"] })
      await c.callTool("roe_set_expiry_days", { days: 7 })
      await c.callTool("roe_sign_current")

      // Snapshot everything before the post-sign edit.
      const before = JSON.parse(fs.readFileSync(path.join(scratch, ".openhack/roe/active.roe.json"), "utf-8"))
      expect(before.status).toBe("signed")

      // Post-sign edit ONLY authorized_tools. Every other field should survive.
      await c.callTool("roe_set_authorized_tools", { tools: ["*"] })

      const after = JSON.parse(fs.readFileSync(path.join(scratch, ".openhack/roe/active.roe.json"), "utf-8"))
      expect(after.status).toBe("draft")
      expect(after.signature).toBeUndefined()
      // The mutated field changed.
      expect(after.authorized_tools).toEqual(["*"])
      // Every other field must be identical to before.
      expect(after.id).toBe(before.id)
      expect(after.company).toBe(before.company)
      expect(after.client).toBe(before.client)
      expect(after.targets).toEqual(before.targets)
      expect(after.exclusions).toEqual(before.exclusions)
      expect(after.authorized_models).toEqual(before.authorized_models)
      expect(after.date_start).toBe(before.date_start)
      expect(after.date_end).toBe(before.date_end)
      expect(after.expires_at).toBe(before.expires_at)
    })
  })

  test("editing a signed ROE via roe_add_authorized_model preserves the existing model list", async () => {
    await withClient({ OPENHACK_ROE_MCP_ALLOW_SIGN: "1" }, async (c) => {
      await c.callTool("roe_create_draft")
      await c.callTool("roe_set_targets", { targets: ["golecloud.co.za"] })
      await c.callTool("roe_set_authorized_tools", { tools: ["nmap"] })
      await c.callTool("roe_set_authorized_models", { models: ["deepseek/deepseek-v4", "anthropic/*"] })
      await c.callTool("roe_sign_current")

      await c.callTool("roe_add_authorized_model", { model: "google/gemini-2.5-flash" })
      const raw = JSON.parse(fs.readFileSync(path.join(scratch, ".openhack/roe/active.roe.json"), "utf-8"))
      expect(raw.status).toBe("draft")
      expect(raw.authorized_models.sort()).toEqual(["anthropic/*", "deepseek/deepseek-v4", "google/gemini-2.5-flash"])
      // Targets and tools weren't touched — they must still be what we set pre-sign.
      expect(raw.targets).toEqual(["golecloud.co.za"])
      expect(raw.authorized_tools).toEqual(["nmap"])
    })
  })
})
