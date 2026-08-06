// End-to-end driver for the ROE-control MCP.
//
// Spawns the MCP inside the given engagement dir, drives it through:
//   create draft → set targets/tools/models/exclusions/expiry → sign
// then verifies:
//   • the ROE file on disk is signed
//   • `roe_validate` allows in-scope+authorized calls
//   • `roe_validate` blocks unauthorized tools + out-of-scope targets
//   • `roe_validate_model` allows exact + wildcard model ids, blocks the rest
//
// Usage:
//   bun run packages/openhack-mcp-roe/scripts/e2e-demo.ts \
//     --engagement-dir /home/kali/Downloads/openhack-main \
//     --company "Golecloud" --client "Golecloud" \
//     --targets golecloud.co.za,*.golecloud.co.za \
//     --tools nmap,httpx,nuclei,ffuf \
//     --models "deepseek/deepseek-v4,anthropic/*,google/gemini-2.5-flash" \
//     --expiry-days 7

import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process"
import * as path from "node:path"
import * as fs from "node:fs"

interface Args {
  engagementDir: string
  company: string
  client: string
  targets: string[]
  tools: string[]
  models: string[]
  exclusions: string[]
  expiryDays: number
}

function parseArgs(): Args {
  const raw = process.argv.slice(2)
  const get = (k: string, dflt?: string) => {
    const i = raw.indexOf(`--${k}`)
    if (i >= 0) return raw[i + 1] ?? dflt ?? ""
    return dflt ?? ""
  }
  const csv = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean)
  const engagementDir = path.resolve(get("engagement-dir", process.cwd()))
  return {
    engagementDir,
    company: get("company", "COMPANY"),
    client: get("client", "CLIENT"),
    targets: csv(get("targets", "example.com")),
    tools: csv(get("tools", "*")),
    models: csv(get("models", "*")),
    exclusions: csv(get("exclusions", "")),
    expiryDays: Number(get("expiry-days", "7")),
  }
}

// ─── minimal JSON-RPC client over stdio ─────────────────────────────────
class RpcClient {
  private buf = ""
  private nextId = 1
  private pending = new Map<number, (v: any) => void>()

  constructor(private proc: ChildProcessWithoutNullStreams) {
    proc.stdout.setEncoding("utf-8")
    proc.stdout.on("data", (chunk: string) => {
      this.buf += chunk
      let nl: number
      while ((nl = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, nl).trim()
        this.buf = this.buf.slice(nl + 1)
        if (!line) continue
        try {
          const msg = JSON.parse(line)
          const cb = this.pending.get(msg.id)
          if (cb) { this.pending.delete(msg.id); cb(msg) }
        } catch {}
      }
    })
    proc.stderr.setEncoding("utf-8")
    proc.stderr.on("data", (chunk: string) => process.stderr.write(`[mcp] ${chunk}`))
  }

  send(method: string, params?: unknown, timeoutMs = 10_000): Promise<any> {
    const id = this.nextId++
    return new Promise<any>((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`rpc timeout on ${method}`)) }, timeoutMs)
      this.pending.set(id, (r) => { clearTimeout(timer); resolve(r) })
      this.proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n")
    })
  }

  async initialize(): Promise<void> {
    await this.send("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "e2e-demo", version: "0.0.1" } })
    this.proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n")
  }

  async call(name: string, args: Record<string, unknown> = {}): Promise<{ text: string; isError: boolean }> {
    const r = await this.send("tools/call", { name, arguments: args })
    const c = r.result?.content?.[0]
    return { text: c?.text ?? "", isError: !!r.result?.isError }
  }
}

// ─── tiny reporting helpers ─────────────────────────────────────────────
const G = "\x1b[32m", R = "\x1b[31m", Y = "\x1b[33m", D = "\x1b[2m", X = "\x1b[0m"
function step(msg: string) { console.log(`\n${Y}▶${X} ${msg}`) }
function pass(msg: string) { console.log(`  ${G}✓${X} ${msg}`) }
function fail(msg: string, detail?: string) { console.log(`  ${R}✗${X} ${msg}${detail ? "\n    " + detail : ""}`); process.exitCode = 1 }
function info(msg: string) { console.log(`  ${D}${msg}${X}`) }
function heading(msg: string) { console.log(`\n${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${X}\n${msg}\n${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${X}`) }

// ─── main flow ──────────────────────────────────────────────────────────
async function main(): Promise<void> {
  const args = parseArgs()
  heading(`ROE-MCP end-to-end demo · ${args.engagementDir}`)
  info(`targets=[${args.targets.join(", ")}]  tools=[${args.tools.join(", ")}]`)
  info(`models=[${args.models.join(", ")}]  expiry_days=${args.expiryDays}`)

  const mcpScript = path.resolve(__dirname, "..", "src", "index.ts")
  if (!fs.existsSync(mcpScript)) throw new Error(`MCP entry not found: ${mcpScript}`)

  step("Spawning MCP with OPENHACK_ROE_MCP_ALLOW_SIGN=1")
  const proc = spawn("bun", ["run", mcpScript], {
    env: { ...process.env, OPENHACK_ROE_MCP_ALLOW_SIGN: "1", OPENHACK_ENGAGEMENT_DIR: args.engagementDir },
    stdio: "pipe",
  })
  const rpc = new RpcClient(proc)
  await rpc.initialize()
  pass("MCP handshaked")

  // ─── setup ────────────────────────────────────────────────────────────
  step("Creating draft ROE")
  {
    const r = await rpc.call("roe_create_draft", { company: args.company, client: args.client })
    if (r.isError) { fail("roe_create_draft failed", r.text); return } else pass(r.text)
  }
  step("Setting targets")
  {
    const r = await rpc.call("roe_set_targets", { targets: args.targets })
    if (r.isError) { fail("roe_set_targets failed", r.text); return } else pass(r.text)
  }
  step("Setting authorized_tools")
  {
    const r = await rpc.call("roe_set_authorized_tools", { tools: args.tools })
    if (r.isError) { fail("roe_set_authorized_tools failed", r.text); return } else pass(r.text)
  }
  step("Setting authorized_models")
  {
    const r = await rpc.call("roe_set_authorized_models", { models: args.models })
    if (r.isError) { fail("roe_set_authorized_models failed", r.text); return } else pass(r.text)
  }
  if (args.exclusions.length) {
    step("Setting exclusions")
    const r = await rpc.call("roe_set_exclusions", { exclusions: args.exclusions })
    if (r.isError) { fail("roe_set_exclusions failed", r.text); return } else pass(r.text)
  }
  step(`Setting expiry to ${args.expiryDays} days`)
  {
    const r = await rpc.call("roe_set_expiry_days", { days: args.expiryDays })
    if (r.isError) { fail("roe_set_expiry_days failed", r.text); return } else pass(r.text)
  }

  step("Signing the ROE")
  {
    const r = await rpc.call("roe_sign_current")
    if (r.isError) { fail("roe_sign_current failed", r.text); return } else pass(r.text)
  }

  // ─── file-on-disk check ───────────────────────────────────────────────
  step("Reading the ROE file back from disk")
  const roeFile = path.join(args.engagementDir, ".openhack/roe/active.roe.json")
  if (!fs.existsSync(roeFile)) { fail(`missing: ${roeFile}`); return }
  const doc = JSON.parse(fs.readFileSync(roeFile, "utf-8"))
  pass(`file exists · status=${doc.status} · targets=${doc.targets.length} · tools=${doc.authorized_tools.length} · models=${(doc.authorized_models ?? []).length}`)
  if (doc.status !== "signed") { fail(`expected status=signed, got ${doc.status}`); return } else pass("status=signed")
  if (!doc.signature || doc.signature.length < 32) { fail("signature missing or too short"); return } else pass(`signature present (${doc.signature.length} chars)`)

  // ─── round-trip through the openhack CLI ───────────────────────────────
  step("Verifying through the openhack CLI (`openhack roe`)")
  {
    const opencodeRoot = path.join(args.engagementDir, "packages", "opencode")
    const cliScript = path.join(opencodeRoot, "src", "index.ts")
    if (!fs.existsSync(cliScript)) {
      info(`skipping (opencode entry not found at ${cliScript})`)
    } else {
      const r = spawnSync("bun", ["run", cliScript, "openhack", "roe"], { cwd: args.engagementDir, encoding: "utf-8" })
      if (r.status === 0 && /SIGNED/i.test(r.stdout)) {
        pass("openhack CLI reports SIGNED status")
        for (const line of r.stdout.trim().split("\n")) info(line)
      } else {
        info(`CLI verification skipped or failed (status=${r.status})`)
        if (r.stdout) info("stdout: " + r.stdout.split("\n")[0])
        if (r.stderr) info("stderr: " + r.stderr.split("\n")[0])
      }
    }
  }

  // ─── enforcement matrix ────────────────────────────────────────────────
  step("Enforcement matrix — target × tool")
  const targetForCheck = args.targets[0]!.replace(/^\*\./, "www.")
  const allowedTool = args.tools[0]!
  const disallowedTool = ["sqlmap", "hydra", "gobuster"].find((t) => !args.tools.includes(t)) ?? "sqlmap"
  const outOfScopeTarget = "unrelated.example.com"
  {
    const r = await rpc.call("roe_validate", { target: targetForCheck, tool: allowedTool })
    const blocked = /"blocked": true/.test(r.text)
    blocked
      ? fail(`expected ALLOW: ${targetForCheck} × ${allowedTool}`, r.text)
      : pass(`ALLOW: ${targetForCheck} × ${allowedTool}`)
  }
  {
    const r = await rpc.call("roe_validate", { target: targetForCheck, tool: disallowedTool })
    const blocked = /"blocked": true/.test(r.text)
    blocked
      ? pass(`BLOCK: ${targetForCheck} × ${disallowedTool} — ${JSON.parse(r.text.replace(/```json|```/g, "")).reason}`)
      : fail(`expected BLOCK: ${targetForCheck} × ${disallowedTool}`, r.text)
  }
  {
    const r = await rpc.call("roe_validate", { target: outOfScopeTarget, tool: allowedTool })
    const blocked = /"blocked": true/.test(r.text)
    blocked
      ? pass(`BLOCK: ${outOfScopeTarget} × ${allowedTool} (out of scope) — ${JSON.parse(r.text.replace(/```json|```/g, "")).reason}`)
      : fail(`expected BLOCK: ${outOfScopeTarget} × ${allowedTool}`, r.text)
  }

  step("Enforcement matrix — AI models")
  {
    const exact = args.models.find((m) => !m.includes("*")) ?? args.models[0]!
    const r = await rpc.call("roe_validate_model", { model: exact })
    const blocked = /"blocked": true/.test(r.text)
    blocked ? fail(`expected ALLOW model ${exact}`, r.text) : pass(`ALLOW model ${exact} (exact match)`)
  }
  const wildcardPattern = args.models.find((m) => m.endsWith("/*"))
  if (wildcardPattern) {
    const prefix = wildcardPattern.replace(/\*$/, "")
    const wildcardCandidate = `${prefix}some-model`
    const r = await rpc.call("roe_validate_model", { model: wildcardCandidate })
    const blocked = /"blocked": true/.test(r.text)
    blocked ? fail(`expected ALLOW wildcard model ${wildcardCandidate}`, r.text) : pass(`ALLOW model ${wildcardCandidate} (wildcard ${wildcardPattern})`)
  }
  {
    const bogus = "some-unauthorized-vendor/gpt-99"
    const r = await rpc.call("roe_validate_model", { model: bogus })
    const blocked = /"blocked": true/.test(r.text)
    blocked
      ? pass(`BLOCK model ${bogus} — ${JSON.parse(r.text.replace(/```json|```/g, "")).reason}`)
      : fail(`expected BLOCK model ${bogus}`, r.text)
  }

  step("Sanity: current status via roe_status")
  {
    const r = await rpc.call("roe_status")
    for (const line of r.text.split("\n").slice(0, 20)) info(line)
  }

  // ─── shutdown ─────────────────────────────────────────────────────────
  proc.kill()
  heading(process.exitCode === 1 ? `${R}One or more assertions failed${X}` : `${G}All assertions passed · ROE signed and enforced end-to-end${X}`)
}

main().catch((e) => {
  console.error(`fatal: ${e?.stack ?? e}`)
  process.exit(1)
})
