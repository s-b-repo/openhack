// OpenHack DNS-enumeration MCP.
//
// Passive-first DNS + subdomain discovery. Zero direct probing of the target;
// every source is a third-party API or a well-known public dataset:
//   • Certificate Transparency (crt.sh) — every issued cert covering the zone.
//   • DNS over HTTPS via Cloudflare's dns-query (A / AAAA / MX / TXT / NS / CNAME).
//   • Reverse-DNS lookups on discovered IPs.
//   • URLScan.io public dataset (opt-in via URLSCAN_API_KEY).
//
// No API keys required for the crt.sh + DoH path — the loop can run it for
// free against any domain. Everything is READ-ONLY; there's no mutation
// surface, so no consent gate is needed.

import { ok, err, jsonBlock as json, runStdioMain } from "../../openhack-mcp-common/src"

async function doh(name: string, type: string): Promise<string[]> {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
      headers: { Accept: "application/dns-json" },
    })
    const j: any = await r.json()
    return (j?.Answer ?? []).map((a: any) => a.data as string)
  } catch { return [] }
}

async function crtsh(domain: string): Promise<string[]> {
  try {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { headers: { Accept: "application/json" } })
    if (!r.ok) return []
    const rows: any[] = await r.json().catch(() => [])
    const names = new Set<string>()
    for (const row of rows) {
      const raw = String(row?.name_value ?? "")
      for (const n of raw.split(/\r?\n/)) {
        const clean = n.trim().toLowerCase().replace(/^\*\./, "")
        if (clean && clean.endsWith(domain.toLowerCase()) && /^[a-z0-9.-]+$/.test(clean)) names.add(clean)
      }
    }
    return [...names].sort()
  } catch { return [] }
}

async function urlscanDomain(domain: string): Promise<string[]> {
  const key = process.env.URLSCAN_API_KEY
  const headers: Record<string, string> = { Accept: "application/json" }
  if (key) headers["API-Key"] = key
  try {
    const r = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=100`, { headers })
    if (!r.ok) return []
    const j: any = await r.json()
    const hosts = new Set<string>()
    for (const res of j?.results ?? []) {
      const url = String(res?.task?.url ?? res?.page?.url ?? "")
      try { hosts.add(new URL(url).hostname.toLowerCase()) } catch {}
    }
    return [...hosts].filter((h) => h.endsWith(domain.toLowerCase())).sort()
  } catch { return [] }
}

const TOOLS = [
  {
    name: "dns_resolve",
    description: "DNS-over-HTTPS resolution for a name + record type (A / AAAA / MX / TXT / NS / CNAME). No caching.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        type: { type: "string", default: "A" },
      },
      required: ["name"],
    },
  },
  {
    name: "dns_full_record_sweep",
    description: "Resolve every common record type (A/AAAA/MX/TXT/NS/CNAME/CAA/SOA) for a name in one call.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string" } },
      required: ["name"],
    },
  },
  {
    name: "ct_subdomains",
    description: "Enumerate subdomains from Certificate Transparency logs (crt.sh). Returns every DNS name that any issued cert covered. Passive — zero probes against the target.",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Apex domain, e.g. golecloud.co.za." } },
      required: ["domain"],
    },
  },
  {
    name: "urlscan_subdomains",
    description: "Subdomains from the URLScan.io public dataset (may require URLSCAN_API_KEY env for higher rate limits). Passive.",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string" } },
      required: ["domain"],
    },
  },
  {
    name: "reverse_dns",
    description: "PTR record for an IP.",
    inputSchema: {
      type: "object",
      properties: { ip: { type: "string" } },
      required: ["ip"],
    },
  },
  {
    name: "passive_recon_bundle",
    description: "One-shot passive recon: CT subdomains + URLScan subdomains + full record sweep of the apex + reverse DNS of every A record found. Deduped, structured. Recommended entry point for the OSINT ActionNode.",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string" } },
      required: ["domain"],
    },
  },
] as const

export async function handle(name: string, args: Record<string, any>) {
  switch (name) {
      case "dns_resolve": {
        const type = String(args.type ?? "A")
        const rec = await doh(String(args.name), type)
        return ok(json({ name: args.name, type, records: rec }))
      }
      case "dns_full_record_sweep": {
        const target = String(args.name)
        const types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA"]
        const bundle: Record<string, string[]> = {}
        await Promise.all(types.map(async (t) => { bundle[t] = await doh(target, t) }))
        return ok(json({ name: target, records: bundle }))
      }
      case "ct_subdomains": {
        const domain = String(args.domain)
        const subs = await crtsh(domain)
        return ok(json({ domain, count: subs.length, subdomains: subs }))
      }
      case "urlscan_subdomains": {
        const domain = String(args.domain)
        const subs = await urlscanDomain(domain)
        return ok(json({ domain, count: subs.length, subdomains: subs, urlscan_key: !!process.env.URLSCAN_API_KEY }))
      }
      case "reverse_dns": {
        const ip = String(args.ip)
        // in-addr.arpa reverse.
        const parts = ip.split(".")
        if (parts.length !== 4) return err("reverse_dns currently only supports IPv4")
        const rev = parts.slice().reverse().join(".") + ".in-addr.arpa"
        const rec = await doh(rev, "PTR")
        return ok(json({ ip, ptr: rec }))
      }
      case "passive_recon_bundle": {
        const domain = String(args.domain)
        // Parallel: CT + URLScan + apex records.
        const [ct, us, apex] = await Promise.all([crtsh(domain), urlscanDomain(domain), (async () => {
          const b: Record<string, string[]> = {}
          const types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA"]
          await Promise.all(types.map(async (t) => { b[t] = await doh(domain, t) }))
          return b
        })()])
        const subdomains = Array.from(new Set([...ct, ...us])).sort()
        // Reverse DNS every A record found for the apex.
        const ptrs: Record<string, string[]> = {}
        for (const ip of apex.A ?? []) {
          const parts = ip.split(".")
          if (parts.length === 4) {
            const rev = parts.slice().reverse().join(".") + ".in-addr.arpa"
            ptrs[ip] = await doh(rev, "PTR")
          }
        }
        return ok(json({ domain, subdomains, subdomain_count: subdomains.length, apex_records: apex, apex_ptrs: ptrs, sources: { crt_sh: ct.length, urlscan: us.length } }))
      }
    default: return err(`Unknown tool: ${name}`)
  }
}

if (!process.env.OPENHACK_MCP_NO_MAIN) {
  runStdioMain({
    name: "openhack-dns-mcp",
    tools: TOOLS as any,
    handle,
    chdirToEngagement: false,
    banner: () => `urlscan_key=${!!process.env.URLSCAN_API_KEY}`,
  })
}
export { TOOLS }
