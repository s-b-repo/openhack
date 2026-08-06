// OpenHack evidence-capture MCP.
//
// Snapshots web-target evidence — PNG screenshots, HTTP-response bundles
// (a mini "HAR" — request headers, status, response headers, body), and
// raw DOM/HTML dumps — into `.openhack/findings/evidence/<target>/`.
// These artifacts are what `openhack finding-verify` expects on the
// evidence-file list to promote an uncertain finding to `verified`.
//
// Design:
//   - Zero heavy deps. Screenshots use the system `chromium` /
//     `google-chrome` binary (headless flag), HAR via `curl -s -D -`,
//     DOM via `curl -sSL`. If none are installed the tools return a
//     descriptive error the model can plan around.
//   - Every write is scope-gated: the URL host must match an in-scope
//     target from `.openhack/scope.json`. This is a hard gate — even
//     with the mutate consent env-var, out-of-scope URLs are refused.
//   - All write tools are env-gated by
//     `OPENHACK_CAPTURE_MCP_ALLOW=1`. Reads (list, open) are ungated.
//   - Artifacts are named `<epoch-ms>-<sha8>.<ext>` so any two captures
//     of the exact same URL are deduplicated by content hash.
//
// Not a browser automation harness — no click/fill/nav interactions.
// If a workflow needs that use the `claude-in-chrome` skill.

import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"
import { spawnSync } from "node:child_process"
import { Scope } from "../../openhack/src/scope"
import { ok, err, jsonBlock as json, checkConsent, resolveEngagementDir, runStdioMain } from "../../openhack-mcp-common/src"

const ENGAGEMENT_DIR = resolveEngagementDir()

function checkMutate() {
  return checkConsent({ envVar: "OPENHACK_CAPTURE_MCP_ALLOW", action: "Evidence-capture write tools" })
}

// Locate an available chromium-family binary. Not cached — checked per-call
// because the operator might install one mid-session. Try the most common
// system names in Kali/Debian and macOS.
function chromiumBinary(): string | null {
  for (const bin of ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]) {
    const which = spawnSync("which", [bin])
    if (which.status === 0) return which.stdout.toString().trim()
  }
  return null
}

function enforceInScope(rawUrl: string): { ok: boolean; host: string; reason?: string } {
  let host = ""
  try { host = new URL(rawUrl).host } catch { return { ok: false, host: "", reason: `invalid URL: ${rawUrl}` } }
  try {
    const cfg = Scope.load()
    if (!cfg.enabled) return { ok: true, host } // scope enforcement disabled → allow
    const chk = Scope.isInScope(host, cfg)
    if (!chk.passed) return { ok: false, host, reason: chk.reason ?? `${host} is not in scope` }
    return { ok: true, host }
  } catch (e: any) {
    return { ok: false, host, reason: `scope check failed: ${e?.message ?? e}` }
  }
}

function evidenceDir(target: string): string {
  const safe = target.replace(/[^a-zA-Z0-9.-]/g, "_")
  const dir = path.join(ENGAGEMENT_DIR, ".openhack", "findings", "evidence", safe)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function shortHash(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex").slice(0, 8)
}

function relFromCwd(abs: string): string {
  const rel = path.relative(ENGAGEMENT_DIR, abs)
  return rel.startsWith("..") ? abs : rel
}

interface CaptureResult {
  url: string
  target: string
  file: string
  bytes: number
  sha256: string
  captured_at: string
}

function saveArtifact(target: string, url: string, ext: string, buf: Buffer): CaptureResult {
  const dir = evidenceDir(target)
  const hash = shortHash(buf)
  const full = crypto.createHash("sha256").update(buf).digest("hex")
  const at = Date.now()
  const file = path.join(dir, `${at}-${hash}.${ext}`)
  fs.writeFileSync(file, buf)
  return { url, target, file: relFromCwd(file), bytes: buf.length, sha256: full, captured_at: new Date(at).toISOString() }
}

const TOOLS = [
  {
    name: "capture_screenshot",
    description: "PNG screenshot of the URL via headless chromium. Writes to .openhack/findings/evidence/<target>/. Scope-gated. GATED: needs OPENHACK_CAPTURE_MCP_ALLOW=1.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Engagement target — used as the evidence subdirectory name." },
        url: { type: "string", description: "Full http(s):// URL to snapshot." },
        wait_ms: { type: "number", description: "Delay before capture (allow JS to settle). Default 1500." },
        width: { type: "number", description: "Viewport width. Default 1280." },
        height: { type: "number", description: "Viewport height. Default 800." },
      },
      required: ["target", "url"],
    },
  },
  {
    name: "capture_har",
    description: "Mini HAR: request line + response status + response headers + response body via curl. GATED.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        url: { type: "string" },
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] },
        headers: { type: "array", items: { type: "string" }, description: "Extra headers, e.g. ['Cookie: session=…']" },
        body: { type: "string", description: "Request body (POST/PUT). Ignored for GET/HEAD." },
        max_body_bytes: { type: "number", description: "Cap response body storage. Default 1MB." },
      },
      required: ["target", "url"],
    },
  },
  {
    name: "capture_dom",
    description: "Raw HTML DOM dump (post-render, via chromium's --dump-dom). GATED.",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string" }, url: { type: "string" }, wait_ms: { type: "number" } },
      required: ["target", "url"],
    },
  },
  {
    name: "capture_full",
    description: "Full-suite capture — PNG + HAR + DOM in a single call. Returns three artifact records. GATED.",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string" }, url: { type: "string" } },
      required: ["target", "url"],
    },
  },
  {
    name: "list_evidence",
    description: "List every artifact captured for a target. Read-only.",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string" }, limit: { type: "number" } },
      required: ["target"],
    },
  },
  {
    name: "evidence_stat",
    description: "Return the on-disk metadata (bytes, sha256, ctime) for one artifact. Read-only.",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string" }, filename: { type: "string" } },
      required: ["target", "filename"],
    },
  },
  {
    name: "evidence_delete",
    description: "Delete one artifact after a finding is closed. GATED.",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string" }, filename: { type: "string" } },
      required: ["target", "filename"],
    },
  },
] as const

export async function handle(name: string, args: Record<string, any>) {
  switch (name) {
    case "capture_screenshot": {
      const c = checkMutate(); if (!c.allowed) return err(c.reason ?? "denied")
      const scope = enforceInScope(String(args.url))
      if (!scope.ok) return err(scope.reason ?? "out of scope")
      const bin = chromiumBinary()
      if (!bin) return err("No chromium/chrome binary in PATH. Install `chromium` or `google-chrome`.")
      const tmp = path.join(ENGAGEMENT_DIR, ".openhack", "tmp")
      fs.mkdirSync(tmp, { recursive: true })
      const tmpFile = path.join(tmp, `shot-${Date.now()}.png`)
      const width = Math.max(200, Math.min(4096, Number(args.width ?? 1280)))
      const height = Math.max(200, Math.min(4096, Number(args.height ?? 800)))
      const waitMs = Math.max(0, Math.min(30_000, Number(args.wait_ms ?? 1500)))
      const flags = [
        "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
        `--window-size=${width},${height}`,
        `--virtual-time-budget=${waitMs}`,
        `--screenshot=${tmpFile}`,
        String(args.url),
      ]
      const r = spawnSync(bin, flags, { encoding: "buffer", timeout: 60_000 })
      if (r.status !== 0 || !fs.existsSync(tmpFile)) {
        return err(`chromium failed: ${(r.stderr ?? Buffer.alloc(0)).toString().slice(0, 500)}`)
      }
      const buf = fs.readFileSync(tmpFile)
      try { fs.unlinkSync(tmpFile) } catch {}
      const out = saveArtifact(String(args.target), String(args.url), "png", buf)
      return ok(`Screenshot saved.\n\n${json(out)}`)
    }
    case "capture_har": {
      const c = checkMutate(); if (!c.allowed) return err(c.reason ?? "denied")
      const scope = enforceInScope(String(args.url))
      if (!scope.ok) return err(scope.reason ?? "out of scope")
      const method = String(args.method ?? "GET").toUpperCase()
      const headers: string[] = Array.isArray(args.headers) ? args.headers.map(String) : []
      const maxBody = Math.max(1024, Math.min(50 * 1024 * 1024, Number(args.max_body_bytes ?? 1024 * 1024)))
      const bodyDir = path.join(ENGAGEMENT_DIR, ".openhack", "tmp")
      fs.mkdirSync(bodyDir, { recursive: true })
      const bodyFile = path.join(bodyDir, `har-${Date.now()}.body`)
      const headerFile = path.join(bodyDir, `har-${Date.now()}.hdr`)
      const cargs = [
        "-sS", "-o", bodyFile, "-D", headerFile,
        "-X", method, "--max-time", "30",
        "--max-filesize", String(maxBody),
      ]
      for (const h of headers) cargs.push("-H", h)
      if (["POST", "PUT", "PATCH"].includes(method) && args.body) cargs.push("--data-binary", String(args.body))
      cargs.push(String(args.url))
      const r = spawnSync("curl", cargs, { encoding: "buffer", timeout: 45_000 })
      if (r.status !== 0) return err(`curl failed: ${(r.stderr ?? Buffer.alloc(0)).toString().slice(0, 300)}`)
      const respHeaders = fs.existsSync(headerFile) ? fs.readFileSync(headerFile, "utf-8") : ""
      const respBody = fs.existsSync(bodyFile) ? fs.readFileSync(bodyFile) : Buffer.alloc(0)
      const har = {
        method, url: String(args.url), request_headers: headers,
        request_body: args.body ? String(args.body).slice(0, 2048) : null,
        response_headers_raw: respHeaders,
        response_bytes: respBody.length,
      }
      try { fs.unlinkSync(headerFile) } catch {}
      const buf = Buffer.from(JSON.stringify(har, null, 2) + "\n\n----- BODY -----\n" + respBody.toString("utf-8"))
      try { fs.unlinkSync(bodyFile) } catch {}
      const out = saveArtifact(String(args.target), String(args.url), "har.txt", buf)
      return ok(`HAR saved (${respHeaders.split("\n")[0]?.trim() ?? "?"}).\n\n${json(out)}`)
    }
    case "capture_dom": {
      const c = checkMutate(); if (!c.allowed) return err(c.reason ?? "denied")
      const scope = enforceInScope(String(args.url))
      if (!scope.ok) return err(scope.reason ?? "out of scope")
      const bin = chromiumBinary()
      if (!bin) return err("No chromium/chrome binary in PATH.")
      const waitMs = Math.max(0, Math.min(30_000, Number(args.wait_ms ?? 1500)))
      const flags = [
        "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
        `--virtual-time-budget=${waitMs}`, "--dump-dom", String(args.url),
      ]
      const r = spawnSync(bin, flags, { encoding: "buffer", timeout: 60_000 })
      if (r.status !== 0 || !r.stdout || r.stdout.length === 0) {
        return err(`chromium --dump-dom failed: ${(r.stderr ?? Buffer.alloc(0)).toString().slice(0, 400)}`)
      }
      const out = saveArtifact(String(args.target), String(args.url), "html", r.stdout)
      return ok(`DOM saved (${out.bytes} bytes).\n\n${json(out)}`)
    }
    case "capture_full": {
      const shot = await handle("capture_screenshot", args)
      const har = await handle("capture_har", args)
      const dom = await handle("capture_dom", args)
      return ok(`Full-capture bundle:\n\n▶ shot:\n${shot.content[0]?.text ?? ""}\n\n▶ har:\n${har.content[0]?.text ?? ""}\n\n▶ dom:\n${dom.content[0]?.text ?? ""}`)
    }
    case "list_evidence": {
      const dir = evidenceDir(String(args.target))
      try {
        const files = fs.readdirSync(dir)
          .filter((f) => !f.startsWith("."))
          .sort()
          .reverse()
        const limit = args.limit ? Math.max(1, Number(args.limit)) : 100
        const items = files.slice(0, limit).map((f) => {
          const s = fs.statSync(path.join(dir, f))
          return { filename: f, bytes: s.size, ctime: s.ctime.toISOString() }
        })
        return ok(json({ target: args.target, dir: relFromCwd(dir), total: files.length, items }))
      } catch { return ok(json({ target: args.target, total: 0, items: [] })) }
    }
    case "evidence_stat": {
      const p = path.join(evidenceDir(String(args.target)), String(args.filename))
      try {
        const buf = fs.readFileSync(p)
        const s = fs.statSync(p)
        return ok(json({
          filename: args.filename, path: relFromCwd(p),
          bytes: s.size, ctime: s.ctime.toISOString(),
          sha256: crypto.createHash("sha256").update(buf).digest("hex"),
        }))
      } catch (e: any) { return err(`stat failed: ${e?.message ?? e}`) }
    }
    case "evidence_delete": {
      const c = checkMutate(); if (!c.allowed) return err(c.reason ?? "denied")
      const p = path.join(evidenceDir(String(args.target)), String(args.filename))
      try { fs.unlinkSync(p); return ok(`Deleted ${relFromCwd(p)}`) }
      catch (e: any) { return err(`delete failed: ${e?.message ?? e}`) }
    }
    default: return err(`Unknown tool: ${name}`)
  }
}

// Skip stdio-server bootstrap when imported by tests. Bun sets no reliable
// entry-point marker across all versions; we cheap out with an env flag any
// test harness can toggle. Real MCP consumers never set this.
if (!process.env.OPENHACK_MCP_NO_MAIN) {
  runStdioMain({
    name: "openhack-capture-mcp",
    tools: TOOLS as any,
    handle,
    banner: () => `in ${ENGAGEMENT_DIR} · chromium=${chromiumBinary() ?? "(missing)"} · write_allowed=${!!process.env.OPENHACK_CAPTURE_MCP_ALLOW}`,
  })
}

export { TOOLS }
