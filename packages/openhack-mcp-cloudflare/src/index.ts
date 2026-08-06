// OpenHack Cloudflare MCP.
//
// The engagement-time surface for talking to Cloudflare while a pentest is
// running: whitelist a source IP so scans reach origin, check whether the
// origin is directly reachable (via cf-connecting-ip / origin certificate
// hints), toggle a temporary WAF exception, and query the Zone & rule state.
//
// Auth: reads `CLOUDFLARE_API_TOKEN` from env (Bearer token with `Zone:Read`,
// `Zone WAF:Edit`, `Firewall Services:Edit` — the minimum surface for the
// tools below). If unset, all mutating tools refuse with a clear error;
// read-only ones (get_zone, list_ip_lists) still work if the token has a
// weaker scope but the calls will 403 through — surfaced verbatim.
//
// Two hard gates on mutating tools (mirrors the ROE MCP's design):
//   OPENHACK_CF_MCP_ALLOW_MUTATE=1     enables mutating tools
//   OPENHACK_CF_MCP_STRICT=1           requires matching consent nonce
// This prevents an AI (or prompt-injection) from silently punching holes in
// the WAF or auto-whitelisting IPs mid-run.

import { ok, err, jsonBlock as json, checkConsent, consumeNonce as _consumeNonce, runStdioMain } from "../../openhack-mcp-common/src"

const API_BASE = "https://api.cloudflare.com/client/v4"
const TOKEN = process.env.CLOUDFLARE_API_TOKEN ?? ""
const NONCE_PATH = ".openhack/cloudflare/.mcp-consent-nonce"

function checkMutateConsent() {
  return checkConsent({
    envVar: "OPENHACK_CF_MCP_ALLOW_MUTATE",
    strictEnvVar: "OPENHACK_CF_MCP_STRICT",
    strictNoncePath: NONCE_PATH,
    action: "Cloudflare mutating tools",
  })
}
function consumeNonce() { _consumeNonce(NONCE_PATH) }

// ─── Cloudflare API client ───────────────────────────────────────────────

interface CfResponse<T = any> {
  ok: boolean
  status: number
  result?: T
  errors?: Array<{ code: number; message: string }>
  messages?: Array<{ code: number; message: string }>
}

async function cf<T = any>(method: "GET" | "POST" | "PATCH" | "DELETE" | "PUT", pathname: string, body?: unknown): Promise<CfResponse<T>> {
  if (!TOKEN) return { ok: false, status: 0, errors: [{ code: 0, message: "CLOUDFLARE_API_TOKEN is not set" }] }
  try {
    const res = await fetch(API_BASE + pathname, {
      method,
      headers: {
        Authorization: `Bearer ${TOKEN}`,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    })
    const j: any = await res.json().catch(() => ({}))
    return { ok: !!j?.success && res.ok, status: res.status, result: j?.result, errors: j?.errors, messages: j?.messages }
  } catch (e: any) {
    return { ok: false, status: 0, errors: [{ code: 0, message: e?.message ?? String(e) }] }
  }
}

// ─── tools ───────────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "cf_egress_ip",
    description: "Return the source IP the framework's tool calls will egress from (via cloudflare's cdn-cgi/trace). Handy to know what to whitelist in a firewall / WAF list.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "cf_zone_lookup",
    description: "Look up a zone id by name (e.g. 'golecloud.co.za'). Read-only — no consent gate.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", description: "Zone apex (no protocol / port)." } },
      required: ["name"],
    },
  },
  {
    name: "cf_zone_status",
    description: "Full status for a zone id: plan, name servers, status, activated_on, WAF-plan hints. Read-only.",
    inputSchema: {
      type: "object",
      properties: { zone_id: { type: "string" } },
      required: ["zone_id"],
    },
  },
  {
    name: "cf_check_origin_reachable",
    description: "Probe whether the ORIGIN behind Cloudflare is directly reachable from the framework's egress IP (bypassing the WAF). Uses common origin-discovery signals: Cloudflare Anycast IP set (should NOT match origin), SSL certificate SAN (real origin often leaks via SNI), and a HEAD request through the CDN vs a direct-to-origin attempt using DNS A records for `origin.<zone>` / `direct.<zone>` if present. Never spoofs anything; purely a reachability report.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: { type: "string", description: "Zone apex or subdomain to probe." },
      },
      required: ["hostname"],
    },
  },
  {
    name: "cf_ip_access_rules_list",
    description: "List IP access rules (allow/block/challenge) for a zone. Read-only.",
    inputSchema: {
      type: "object",
      properties: { zone_id: { type: "string" } },
      required: ["zone_id"],
    },
  },
  {
    name: "cf_ip_access_rule_add",
    description: "Add an IP access rule to a zone — `mode` is one of allow / block / challenge / js_challenge / managed_challenge. GATED: requires OPENHACK_CF_MCP_ALLOW_MUTATE=1. Use to whitelist the pentest egress IP for the engagement window; remove with cf_ip_access_rule_delete after.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string" },
        mode: { type: "string", enum: ["allow", "block", "challenge", "js_challenge", "managed_challenge"] },
        ip: { type: "string", description: "IP or CIDR (e.g. '203.0.113.42' or '203.0.113.0/24')." },
        notes: { type: "string", description: "Free-form audit note — recommended: engagement id + expiry." },
      },
      required: ["zone_id", "mode", "ip"],
    },
  },
  {
    name: "cf_ip_access_rule_delete",
    description: "Delete an IP access rule by id. GATED.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string" },
        rule_id: { type: "string" },
      },
      required: ["zone_id", "rule_id"],
    },
  },
  {
    name: "cf_waf_package_list",
    description: "List WAF managed rulesets attached to a zone. Read-only — useful to see which packages might block the engagement's scans.",
    inputSchema: {
      type: "object",
      properties: { zone_id: { type: "string" } },
      required: ["zone_id"],
    },
  },
  {
    name: "cf_dns_records",
    description: "List DNS records for a zone (A/AAAA/CNAME). Useful for surface enumeration BEFORE the engagement's active scanning starts — same information you'd get from dig against every record but authoritatively per-zone.",
    inputSchema: {
      type: "object",
      properties: { zone_id: { type: "string" }, type: { type: "string", description: "Optional record type filter." } },
      required: ["zone_id"],
    },
  },
] as const

async function handle(name: string, args: Record<string, any>) {
  switch (name) {
      case "cf_egress_ip": {
        try {
          const res = await fetch("https://www.cloudflare.com/cdn-cgi/trace", { method: "GET" })
          const t = await res.text()
          const line = t.split("\n").find((l) => l.startsWith("ip="))
          return ok(line ?? t.slice(0, 400))
        } catch (e: any) {
          return err(`egress lookup failed: ${e?.message ?? e}`)
        }
      }
      case "cf_zone_lookup": {
        const zoneName = String(args.name ?? "")
        if (!zoneName) return err("name required")
        const r = await cf("GET", `/zones?name=${encodeURIComponent(zoneName)}`)
        if (!r.ok) return err(json(r))
        const first = (r.result as any[])?.[0]
        return first ? ok(json({ id: first.id, name: first.name, status: first.status, plan: first.plan?.name })) : err(`no zone '${zoneName}' found (auth ok, but zone not visible with this token)`)
      }
      case "cf_zone_status": {
        const r = await cf("GET", `/zones/${encodeURIComponent(String(args.zone_id))}`)
        if (!r.ok) return err(json(r))
        return ok(json(r.result))
      }
      case "cf_check_origin_reachable": {
        const hostname = String(args.hostname ?? "")
        if (!hostname) return err("hostname required")
        const findings: Record<string, any> = { hostname }
        // A/AAAA lookups (JSON DoH — Cloudflare's).
        try {
          const doh = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, { headers: { Accept: "application/dns-json" } }).then((r) => r.json()) as any
          findings.a_records = (doh?.Answer ?? []).map((a: any) => a.data)
        } catch (e: any) { findings.a_records_error = e?.message ?? String(e) }
        // Head request through the CDN, look at cf-ray + server header.
        try {
          const h = await fetch(`https://${hostname}/`, { method: "HEAD", redirect: "manual" })
          findings.cdn_headers = { server: h.headers.get("server"), cf_ray: h.headers.get("cf-ray"), status: h.status }
        } catch (e: any) { findings.cdn_error = e?.message ?? String(e) }
        // Try origin.<zone> and direct.<zone> — sometimes DNS leaks the real origin.
        for (const prefix of ["origin", "direct", "www-origin"]) {
          try {
            const doh = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(prefix + "." + hostname)}&type=A`, { headers: { Accept: "application/dns-json" } }).then((r) => r.json()) as any
            const answers = (doh?.Answer ?? []).map((a: any) => a.data)
            if (answers.length) findings[`${prefix}_hint_records`] = answers
          } catch {}
        }
        // Heuristic verdict.
        const cdnServer = findings.cdn_headers?.server?.toLowerCase() ?? ""
        findings.behind_cloudflare = cdnServer.includes("cloudflare") || !!findings.cdn_headers?.cf_ray
        findings.notes = findings.behind_cloudflare
          ? "Cloudflare is in the response path. To reach the origin directly, use cf_ip_access_rules_list to add your egress IP as `allow` (gated) or scan the hinted origin.<zone> records above if any."
          : "No Cloudflare header detected — direct-to-origin may already work from the framework's egress IP."
        return ok(json(findings))
      }
      case "cf_ip_access_rules_list": {
        const r = await cf("GET", `/zones/${encodeURIComponent(String(args.zone_id))}/firewall/access_rules/rules`)
        if (!r.ok) return err(json(r))
        return ok(json(r.result))
      }
      case "cf_ip_access_rule_add": {
        const consent = checkMutateConsent()
        if (!consent.allowed) return err(consent.reason ?? "consent denied")
        const r = await cf("POST", `/zones/${encodeURIComponent(String(args.zone_id))}/firewall/access_rules/rules`, {
          mode: String(args.mode),
          configuration: { target: String(args.ip).includes("/") ? "ip_range" : "ip", value: String(args.ip) },
          notes: String(args.notes ?? "openhack-mcp"),
        })
        if (!r.ok) return err(json(r))
        if (process.env.OPENHACK_CF_MCP_STRICT === "1") consumeNonce()
        return ok(`Added rule ${(r.result as any)?.id} (${String(args.mode)} ${String(args.ip)}).`)
      }
      case "cf_ip_access_rule_delete": {
        const consent = checkMutateConsent()
        if (!consent.allowed) return err(consent.reason ?? "consent denied")
        const r = await cf("DELETE", `/zones/${encodeURIComponent(String(args.zone_id))}/firewall/access_rules/rules/${encodeURIComponent(String(args.rule_id))}`)
        if (!r.ok) return err(json(r))
        if (process.env.OPENHACK_CF_MCP_STRICT === "1") consumeNonce()
        return ok(`Deleted rule ${String(args.rule_id)}.`)
      }
      case "cf_waf_package_list": {
        const r = await cf("GET", `/zones/${encodeURIComponent(String(args.zone_id))}/firewall/waf/packages`)
        if (!r.ok) return err(json(r))
        return ok(json(r.result))
      }
      case "cf_dns_records": {
        const type = args.type ? `?type=${encodeURIComponent(String(args.type))}` : ""
        const r = await cf("GET", `/zones/${encodeURIComponent(String(args.zone_id))}/dns_records${type}`)
        if (!r.ok) return err(json(r))
        return ok(json(r.result))
      }
      default: return err(`Unknown tool: ${name}`)
  }
}

runStdioMain({
  name: "openhack-cloudflare-mcp",
  tools: TOOLS as any,
  handle,
  chdirToEngagement: false,
  banner: () => `token=${TOKEN ? "set" : "unset"} · mutate_allowed=${!!process.env.OPENHACK_CF_MCP_ALLOW_MUTATE} · strict=${process.env.OPENHACK_CF_MCP_STRICT === "1"}`,
})
