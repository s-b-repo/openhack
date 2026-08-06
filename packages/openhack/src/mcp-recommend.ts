/**
 * Recommend an opt-in MCP server when the task at hand matches its capability, so
 * the operator/agent enables the right tooling instead of working without it. The
 * bundled MCP catalog ships everything `enabled:false`; this maps a prompt or tool
 * output to the server that would help. Pure + testable.
 */
export namespace McpRecommend {
  export interface Capability {
    server: string
    enables: string
    triggers: RegExp
  }

  export const CATALOG: Capability[] = [
    { server: "hexstrike", enables: "150+ recon/scan tools (nmap, masscan, nuclei, nikto, dns)", triggers: /\b(port ?scan|nmap|masscan|recon|enumerat|nuclei|nikto|service (?:version|fingerprint)|subdomain)\b/i },
    { server: "pentestai", enables: "web-exploit probes (SQLi/XSS/auth/API)", triggers: /\b(sqli|sql ?injection|xss|cross.?site|api (?:test|abuse)|web exploit|probe|idor|ssrf)\b/i },
    { server: "rustsploit", enables: "exploitation + loot/credential modules", triggers: /\b(exploit|payload|loot|credential|reverse shell|privilege escalation|post.?exploit)\b/i },
    { server: "arcticfox", enables: "C2 agent management (deploy/status/queue)", triggers: /\b(c2|command.?and.?control|implant|beacon|agent deploy|dead.?drop)\b/i },
    { server: "camoufox", enables: "stealth browser — Cloudflare managed-challenge bypass, cf_clearance, authenticated browsing", triggers: /\b(cloudflare|\bwaf\b|managed challenge|turnstile|cf.?clearance|just a moment|logged.?in test|authenticated (?:browser|session)|headless browser|bot detection)\b/i },
    { server: "onlyoffice", enables: "docx/xlsx/pptx report generation", triggers: /\b(report|deliverable|\bdocx\b|\bxlsx\b|\bpptx\b|word doc|spreadsheet|presentation|executive summary)\b/i },
    { server: "sysreptor", enables: "SysReptor pentest report platform", triggers: /\bsysreptor\b/i },
    { server: "websearch", enables: "web search (Brave) for CVE/OSINT research", triggers: /\b(search the web|cve lookup|research (?:the|a) |osint|latest advisory)\b/i },
    { server: "fetch", enables: "fetch + convert a web page to markdown", triggers: /\b(fetch (?:the|a) url|scrape (?:the )?page|read (?:the )?page content)\b/i },
    { server: "git", enables: "git repository operations", triggers: /\b(git (?:log|diff|blame|clone)|commit history)\b/i },
  ]

  export interface Hit {
    server: string
    enables: string
  }

  /** Servers whose capability matches `text`, optionally excluding already-enabled ones. */
  export function recommend(text: string, opts?: { exclude?: Set<string> }): Hit[] {
    const out: Hit[] = []
    for (const c of CATALOG) {
      if (opts?.exclude?.has(c.server)) continue
      if (c.triggers.test(text)) out.push({ server: c.server, enables: c.enables })
    }
    return out
  }

  export function format(hits: Hit[]): string {
    if (!hits.length) return ""
    const lines = hits.map((h) => `  • ${h.server} — ${h.enables}`)
    return `[openhack] MCP suggestion — this task could use:\n${lines.join("\n")}\n  Enable with: openhack config set mcp.<server>.enabled true  (then install the server).`
  }
}
