import { existsSync, readFileSync, writeFileSync } from "node:fs"

export namespace Orchestrator {
  export interface RoutingRule {
    category: string
    primary: string
    fallback: string | null
    tools: string[]
  }

  export interface ToolScore {
    mcp: string
    tool: string
    score: number
    successes: number
    failures: number
    avgDurationMs: number
    lastUsed: string | null
  }

  export interface RouteResult {
    mcp: string
    tool: string
    category: string
    reason: string
    fallback?: string
  }

  const ROUTING_RULES: RoutingRule[] = [
    { category: "recon", primary: "hexstrike", fallback: "rustsploit", tools: ["nmap_scan", "rustscan_scan", "masscan_scan", "amass_enum", "subfinder_scan", "dnsenum_scan", "theharvester_search", "autorecon_scan", "httpx_scan"] },
    { category: "web_recon", primary: "pentestai", fallback: "hexstrike", tools: ["gobuster_scan", "feroxbuster_scan", "ffuf_scan", "dirsearch_scan", "katana_crawl", "hakrawler_crawl"] },
    { category: "web_exploit", primary: "pentestai", fallback: "hexstrike", tools: ["ptai_run_probe", "sqlmap_scan", "nuclei_scan", "dalfox_scan", "wpscan_scan", "nikto_scan", "xss_scan", "csrf_scan", "ssrf_scan"] },
    { category: "network_exploit", primary: "hexstrike", fallback: "rustsploit", tools: ["hydra_scan", "medusa_scan", "msfvenom_build", "responder_start", "netexec_scan", "crackmapexec_scan", "impacket_exec"] },
    { category: "auth_test", primary: "hexstrike", fallback: "pentestai", tools: ["hydra_scan", "john_hash", "hashcat_crack", "medusa_brute"] },
    { category: "binary_analysis", primary: "hexstrike", fallback: null, tools: ["ghidra_analyze", "radare2_analyze", "gdb_debug", "binwalk_extract", "checksec_scan", "strings_extract"] },
    { category: "cloud_scan", primary: "hexstrike", fallback: null, tools: ["prowler_assess", "scout_suite_audit", "trivy_scan", "kube_hunter_scan", "kube_bench_check"] },
    { category: "c2_ops", primary: "arcticfox", fallback: null, tools: ["arcticfox_agent_deploy", "arcticfox_heartbeat", "arcticfox_command_queue", "arcticfox_attack_template"] },
    { category: "post_exploit", primary: "arcticfox", fallback: "rustsploit", tools: ["arcticfox_persistence", "rustsploit_loot", "rustsploit_cred"] },
    { category: "reporting", primary: "sysreptor", fallback: null, tools: ["sr_project_create", "sr_finding_create", "sr_report_generate", "sr_evidence_upload"] },
    { category: "osint", primary: "hexstrike", fallback: "pentestai", tools: ["theharvester_search", "sherlock_search", "recon_ng_scan", "spiderfoot_scan"] },
    { category: "stealth_recon", primary: "rustsploit", fallback: "pentestai", tools: ["rustsploit_scan", "ptai_port_scan"] },
    { category: "wireless", primary: "hexstrike", fallback: null, tools: ["aircrack_ng_crack", "bettercap_wifi", "kismet_scan", "hcxdumptool_capture"] },
    { category: "mobile", primary: "hexstrike", fallback: "pentestai", tools: ["mobsf_analyze", "frida_inject", "apktool_decompile", "jadx_decompile"] },
    { category: "firmware_iot", primary: "hexstrike", fallback: null, tools: ["binwalk_extract", "firmwalker_scan", "mqtt_explore", "uart_scan"] },
    { category: "social_engineering", primary: "hexstrike", fallback: null, tools: ["gophish_campaign", "evilginx_setup", "set_toolkit"] },
    { category: "container", primary: "hexstrike", fallback: null, tools: ["docker_scan", "trivy_scan", "kube_hunter_scan", "falco_check"] },
    { category: "forensics", primary: "hexstrike", fallback: null, tools: ["volatility_scan", "volatility3_scan", "foremost_extract", "exiftool_read"] },
    { category: "api_security", primary: "pentestai", fallback: "hexstrike", tools: ["ptai_api_fuzz", "arjun_param", "graphql_scan", "swagger_audit"] },
    { category: "voip", primary: "hexstrike", fallback: null, tools: ["sipvicious_scan", "voip_vlan_scan"] },
  ]

  let toolScores: Map<string, ToolScore> = new Map()
  const SCORES_FILE = ".openhack/tool-scores.json"

  try {
    if (existsSync(SCORES_FILE)) {
      const saved = JSON.parse(readFileSync(SCORES_FILE, "utf-8"))
      toolScores = new Map(Object.entries(saved))
    }
  } catch {}

  // Persistence is coalesced — a burst of MCP tool.execute.after hooks would
  // otherwise trigger one writeFileSync per call. `dirty` flags a pending flush,
  // and `flushTimer` schedules exactly one write within `FLUSH_INTERVAL_MS`.
  // A process exit hook flushes the last batch so nothing is lost.
  const FLUSH_INTERVAL_MS = 500
  let dirty = false
  let flushTimer: ReturnType<typeof setTimeout> | null = null
  let exitHookInstalled = false

  function persistScoresNow(): void {
    try {
      const obj = Object.fromEntries(toolScores)
      writeFileSync(SCORES_FILE, JSON.stringify(obj, null, 2))
      dirty = false
    } catch {}
  }

  function persistScores(): void {
    dirty = true
    if (!exitHookInstalled) {
      try {
        process.on("beforeExit", () => { if (dirty) persistScoresNow() })
      } catch {}
      exitHookInstalled = true
    }
    if (flushTimer) return
    flushTimer = setTimeout(() => {
      flushTimer = null
      if (dirty) persistScoresNow()
    }, FLUSH_INTERVAL_MS)
    try { (flushTimer as any).unref?.() } catch {}
  }

  /** Test-only: force any pending flush to happen right now. */
  export function flushScoresForTest(): void {
    if (flushTimer) { clearTimeout(flushTimer); flushTimer = null }
    if (dirty) persistScoresNow()
  }

  function classifyIntent(command: string, toolName?: string): string {
    const lower = command.toLowerCase()

    if (lower.includes("c2") || lower.includes("arcticfox") || lower.includes("implant") || lower.includes("dead drop")) return "c2_ops"
    if (lower.includes("binary") || lower.includes("ghidra") || lower.includes("radare") || lower.includes("gdb") || lower.includes("disassemble") || lower.includes("binwalk") || lower.includes("checksec")) return "binary_analysis"
    if (lower.includes("cloud") || lower.includes("aws") || lower.includes("azure") || lower.includes("gcp") || lower.includes("kubernetes") || lower.includes("helm")) return "cloud_scan"
    if (lower.includes("password") || lower.includes("auth") || lower.includes("credential") || lower.includes("hash") || lower.includes("login") || lower.includes("hydra") || lower.includes("john") || lower.includes("hashcat")) return "auth_test"
    if (lower.includes("privilege escalation") || lower.includes("lateral movement") || lower.includes("harvest") || lower.includes("exfiltrat") || lower.includes("persist")) return "post_exploit"
    if (lower.includes("report") || lower.includes("finding") || lower.includes("sysreptor") || lower.includes("export to pdf") || lower.includes("document")) return "reporting"

    if (lower.includes("sqli") || lower.includes("sql injection") || lower.includes("xss") || lower.includes("csrf") || lower.includes("ssrf") || lower.includes("rce") || lower.includes("command injection") || lower.includes("exploit")) {
      if (lower.includes("web") || lower.includes("url") || lower.includes("http") || lower.includes("api")) return "web_exploit"
      return "network_exploit"
    }

    if (lower.includes("scan") || lower.includes("nmap") || lower.includes("port") || lower.includes("discover") || lower.includes("enum") || lower.includes("dns") || lower.includes("subdomain") || lower.includes("fingerprint") || lower.includes("recon") || lower.includes("osint")) {
      if (lower.includes("stealth") || lower.includes("quiet") || lower.includes("covert")) return "stealth_recon"
      if (lower.includes("web") || lower.includes("http") || lower.includes("dir") || lower.includes("gobuster") || lower.includes("ffuf")) return "web_recon"
      return "recon"
    }

    if (lower.includes("wireless") || lower.includes("wifi") || lower.includes("wpa") || lower.includes("aircrack")) return "wireless"
    if (lower.includes("mobile") || lower.includes("android") || lower.includes("ios") || lower.includes("apk") || lower.includes("frida")) return "mobile"
    if (lower.includes("firmware") || lower.includes("iot") || lower.includes("embedded") || lower.includes("uart")) return "firmware_iot"
    if (lower.includes("phish") || lower.includes("social") || lower.includes("gophish") || lower.includes("evilginx")) return "social_engineering"
    if (lower.includes("docker") || lower.includes("container")) return "container"
    if (lower.includes("forensic") || lower.includes("memory") || lower.includes("volatility")) return "forensics"

    return "generic"
  }

  export function route(command: string, preferredMCP?: string): RouteResult {
    const category = classifyIntent(command)

    const rule = ROUTING_RULES.find((r) => r.category === category)
    if (!rule) {
      return { mcp: "builtin", tool: "bash", category: "generic", reason: "No routing rule found — using bash directly" }
    }

    const primary = preferredMCP || rule.primary

    const primaryScore = getToolScore(primary, rule.tools[0])
    if (primaryScore && primaryScore.score > 0) {
      return {
        mcp: primary,
        tool: rule.tools[0],
        category,
        reason: `Routed to ${primary} (primary for ${category}, score: ${primaryScore.score})`,
        fallback: rule.fallback || undefined,
      }
    }

    return {
      mcp: primary,
      tool: rule.tools[0],
      category,
      reason: `Routed to ${primary} (primary for ${category})`,
      fallback: rule.fallback || undefined,
    }
  }

  function getToolScore(mcp: string, tool: string): ToolScore | null {
    return toolScores.get(`${mcp}:${tool}`) || null
  }

  export function recordResult(mcp: string, tool: string, success: boolean, durationMs: number): void {
    const key = `${mcp}:${tool}`
    const existing = toolScores.get(key) || { mcp, tool, score: 50, successes: 0, failures: 0, avgDurationMs: 0, lastUsed: null }

    if (success) {
      existing.successes++
      existing.score = Math.min(100, existing.score + 2)
    } else {
      existing.failures++
      existing.score = Math.max(0, existing.score - 5)
    }

    existing.avgDurationMs = (existing.avgDurationMs * (existing.successes + existing.failures - 1) + durationMs) / (existing.successes + existing.failures)
    existing.lastUsed = new Date().toISOString()
    toolScores.set(key, existing)
    persistScores()
  }

  export function getRoutingTable(): { rules: RoutingRule[]; scores: ToolScore[] } {
    return { rules: ROUTING_RULES, scores: Array.from(toolScores.values()) }
  }

  export function suggestTool(category: string): string | null {
    const rule = ROUTING_RULES.find((r) => r.category === category)
    if (!rule) return null

    let bestScore = -1
    let bestTool = rule.tools[0]

    for (const tool of rule.tools) {
      const ps = getToolScore(rule.primary, tool)
      if (ps && ps.score > bestScore) {
        bestScore = ps.score
        bestTool = tool
      }
      if (rule.fallback) {
        const fs = getToolScore(rule.fallback, tool)
        if (fs && fs.score > bestScore) {
          bestScore = fs.score
          bestTool = tool
        }
      }
    }

    return bestTool
  }
}
