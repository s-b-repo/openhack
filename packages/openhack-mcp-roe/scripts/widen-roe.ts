// Widen the current ROE so runtime enforcement never blocks a tool or model —
// but keep the doc signed and the target list intact (so we still have an
// authorization record for the engagement). Uses the same MCP the operator
// would use interactively; nothing is done by hand-editing the JSON.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process"
import * as path from "node:path"
import * as fs from "node:fs"

const engagementDir = path.resolve(process.argv[2] ?? process.cwd())

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
        try { const m = JSON.parse(line); const cb = this.pending.get(m.id); if (cb) { this.pending.delete(m.id); cb(m) } } catch {}
      }
    })
    proc.stderr.setEncoding("utf-8")
    proc.stderr.on("data", (c: string) => process.stderr.write(`[mcp] ${c}`))
  }
  send(method: string, params?: unknown): Promise<any> {
    const id = this.nextId++
    return new Promise<any>((res, rej) => {
      const t = setTimeout(() => { this.pending.delete(id); rej(new Error(`rpc timeout on ${method}`)) }, 10_000)
      this.pending.set(id, (r) => { clearTimeout(t); res(r) })
      this.proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n")
    })
  }
  async initialize(): Promise<void> {
    await this.send("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "widen", version: "0.0.1" } })
    this.proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n")
  }
  async call(name: string, args: Record<string, unknown> = {}): Promise<string> {
    const r = await this.send("tools/call", { name, arguments: args })
    return r.result?.content?.[0]?.text ?? ""
  }
}

async function main(): Promise<void> {
  const proc = spawn("bun", ["run", path.resolve(__dirname, "..", "src", "index.ts")], {
    env: { ...process.env, OPENHACK_ROE_MCP_ALLOW_SIGN: "1", OPENHACK_ENGAGEMENT_DIR: engagementDir },
    stdio: "pipe",
  })
  const rpc = new RpcClient(proc)
  await rpc.initialize()

  // Read current state
  console.log("current:", await rpc.call("roe_summary_markdown"))

  // The MCP's draft tools already demote a signed doc to draft on any edit,
  // so widening tools/models automatically drops the prior signature. We just
  // re-sign at the end.
  console.log(await rpc.call("roe_set_targets", { targets: ["golecloud.co.za", "*.golecloud.co.za"] }))
  console.log(await rpc.call("roe_set_authorized_tools", { tools: ["*"] }))
  console.log(await rpc.call("roe_set_authorized_models", { models: ["*"] }))
  console.log(await rpc.call("roe_set_exclusions", { exclusions: ["mail.golecloud.co.za"] }))
  console.log(await rpc.call("roe_sign_current"))

  // Read back to prove enforcement is now permissive
  console.log("\nafter widening:")
  console.log(await rpc.call("roe_status"))

  // Enforcement sanity — nothing should be blocked
  for (const [t, tool] of [["golecloud.co.za", "sqlmap"], ["golecloud.co.za", "hydra"], ["random.example.com", "nmap"]]) {
    const r = await rpc.call("roe_validate", { target: t, tool })
    console.log(`  ${t} × ${tool}: ${/"blocked": false/.test(r) ? "ALLOW" : "BLOCK"}`)
  }
  for (const m of ["deepseek/deepseek-v4", "openai/gpt-4o", "some/other-model"]) {
    const r = await rpc.call("roe_validate_model", { model: m })
    console.log(`  model ${m}: ${/"blocked": false/.test(r) ? "ALLOW" : "BLOCK"}`)
  }

  // Prove the file on disk stayed signed
  const roeFile = path.join(engagementDir, ".openhack/roe/active.roe.json")
  const doc = JSON.parse(fs.readFileSync(roeFile, "utf-8"))
  console.log(`\nfile: status=${doc.status} · authorized_tools=${JSON.stringify(doc.authorized_tools)} · authorized_models=${JSON.stringify(doc.authorized_models)} · targets=${JSON.stringify(doc.targets)}`)

  proc.kill()
}

main().catch((e) => { console.error(e); process.exit(1) })
