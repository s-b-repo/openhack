import { ConfigStore } from "./config-store"

/**
 * Presets for the pentest tools shipped by default on Kali — a named base-args
 * recipe per common scenario, so an operator or agent runs the right invocation
 * without re-deriving flags. Built-ins are overridable/extendable via the
 * `tool_presets` key in `.openhack/openhack.jsonc` (so presets are, like everything
 * else, shell-configurable). Each preset also declares its own timeout, aligned
 * with the smart command-timeout policy (long scanners are not auto-killed).
 */
export namespace Presets {
  export interface Preset {
    id: string
    tool: string
    /** Base arguments; the target/URL is appended after these. */
    args: string
    timeout_ms?: number
    description: string
    /** How the target should look (hint for the operator/agent). */
    target_hint?: string
  }

  export const BUILTIN: Preset[] = [
    { id: "nmap-quick", tool: "nmap", args: "-sV -T4 -Pn --top-ports 1000", timeout_ms: 600_000, description: "Quick service/version scan (top 1000 TCP)", target_hint: "host or CIDR" },
    { id: "nmap-full", tool: "nmap", args: "-sV -sC -A -p- -T4 --max-retries 2", timeout_ms: 3_600_000, description: "Full aggressive all-port scan", target_hint: "host or CIDR" },
    { id: "nmap-udp", tool: "nmap", args: "-sU -T4 --top-ports 100 -Pn", timeout_ms: 1_800_000, description: "Top-100 UDP scan", target_hint: "host" },
    { id: "rustscan-full", tool: "rustscan", args: "-b 4500 --range 1-65535 -- -sV", timeout_ms: 1_800_000, description: "Fast full-port sweep piped to nmap -sV", target_hint: "-a host" },
    { id: "ffuf-common", tool: "ffuf", args: "-w /usr/share/wordlists/dirb/common.txt -t 50 -mc 200,204,301,302,307,401,403 -u", timeout_ms: 900_000, description: "Content discovery (common.txt)", target_hint: "URL with FUZZ, e.g. https://t/FUZZ" },
    { id: "gobuster-common", tool: "gobuster", args: "dir -w /usr/share/wordlists/dirb/common.txt -t 50 -q -u", timeout_ms: 900_000, description: "Directory brute-force (common.txt)", target_hint: "URL" },
    { id: "feroxbuster-deep", tool: "feroxbuster", args: "-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 --depth 2 -u", timeout_ms: 1_800_000, description: "Recursive content discovery", target_hint: "URL" },
    { id: "nuclei-critical", tool: "nuclei", args: "-severity critical,high -rl 20 -et dos -u", timeout_ms: 1_800_000, description: "Critical/high template scan", target_hint: "URL" },
    { id: "nuclei-wordpress", tool: "nuclei", args: "-tags wordpress,exposure -rl 15 -et dos -u", timeout_ms: 1_800_000, description: "WordPress + exposure templates", target_hint: "URL" },
    { id: "sqlmap-auto", tool: "sqlmap", args: "--batch --random-agent --level 3 --risk 2 -u", timeout_ms: 1_800_000, description: "Automated SQLi test", target_hint: "URL with a param (?id=1)" },
    { id: "wpscan-enum", tool: "wpscan", args: "--enumerate vp,vt,u --random-user-agent --url", timeout_ms: 1_800_000, description: "WordPress vuln + user enumeration (needs --api-token for CVEs)", target_hint: "URL" },
    { id: "nikto-quick", tool: "nikto", args: "-Tuning 123bde -h", timeout_ms: 1_800_000, description: "Web server misconfig scan", target_hint: "URL/host" },
    { id: "whatweb", tool: "whatweb", args: "-a 3", timeout_ms: 120_000, description: "Aggressive tech fingerprint", target_hint: "URL" },
    { id: "subfinder", tool: "subfinder", args: "-silent -d", timeout_ms: 600_000, description: "Passive subdomain enumeration", target_hint: "apex domain" },
    { id: "amass-passive", tool: "amass", args: "enum -passive -d", timeout_ms: 1_800_000, description: "Passive attack-surface mapping", target_hint: "apex domain" },
    { id: "httpx-probe", tool: "httpx", args: "-silent -td -sc -title -l", timeout_ms: 600_000, description: "Probe a host list (status/title/tech)", target_hint: "path to hosts file" },
  ]

  function userPresets(): Preset[] {
    const raw = ConfigStore.get("tool_presets")
    if (!raw || typeof raw !== "object") return []
    return Object.entries(raw).map(([id, v]: [string, any]) => ({ id, tool: v.tool, args: v.args ?? "", timeout_ms: v.timeout_ms, description: v.description ?? "", target_hint: v.target_hint }))
  }

  /** Built-ins with user `tool_presets` merged/overriding by id. */
  export function all(): Preset[] {
    const map = new Map<string, Preset>()
    for (const p of BUILTIN) map.set(p.id, p)
    for (const p of userPresets()) if (p.tool) map.set(p.id, p)
    return [...map.values()]
  }

  export function get(id: string): Preset | undefined {
    return all().find((p) => p.id === id)
  }

  /** Build the full command line for a preset. Target/URL is appended after the args. */
  export function expand(preset: Preset, target?: string): string {
    return `${preset.tool} ${preset.args}${target ? " " + target : ""}`.trim()
  }
}
