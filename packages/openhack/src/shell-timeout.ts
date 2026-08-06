/**
 * Smart per-command timeout policy. Short-lived commands (curl, dig, one-shot
 * fetches/lookups) should ALWAYS be bounded so a hung request can't stall a run;
 * long-running scanners (nmap, nuclei, ffuf, sqlmap, …) must NOT be auto-killed.
 *
 * Applied in the OpenHack plugin's `tool.execute.before` (sets the shell tool's
 * `timeout` arg when the caller didn't specify one). An explicit `timeout` always
 * wins. Pure + dependency-free so it's trivially unit-testable.
 */
export namespace ShellTimeout {
  export interface Policy {
    /** ms for short-lived commands (default 45s). */
    short_ms?: number
    /** ms for long-running scanners (default 1h). */
    long_ms?: number
    /** per-tool overrides, e.g. { "sqlmap": 7200000 }. */
    overrides?: Record<string, number>
    /** extra tool names to treat as short-lived / long-running. */
    short_tools?: string[]
    long_tools?: string[]
  }

  // Bounded, one-shot fetches/lookups — safe to hard-timeout.
  const SHORT = new Set([
    "curl", "wget", "dig", "host", "nslookup", "whatweb", "ping", "traceroute",
    "openssl", "whois", "nc", "ncat", "socat", "head", "tail", "cat", "jq", "httpie", "http",
  ])
  // Scanners / brute-forcers / long crawls — never auto-kill.
  const LONG = new Set([
    "nmap", "masscan", "rustscan", "nuclei", "ffuf", "gobuster", "feroxbuster", "dirb",
    "dirsearch", "wfuzz", "katana", "sqlmap", "hydra", "medusa", "patator", "wpscan",
    "amass", "subfinder", "assetfinder", "hashcat", "john", "nikto", "enum4linux",
    "crackmapexec", "nxc", "responder", "aircrack-ng", "bettercap", "msfconsole", "zap",
    "sslscan", "testssl.sh", "recon-ng", "theharvester", "gau", "waybackurls", "arjun",
  ])
  // Wrapper prefixes to skip so `sudo nmap …` / `timeout 60 curl …` classify by the real tool.
  const WRAPPERS = new Set(["sudo", "env", "time", "timeout", "nice", "ionice", "stdbuf", "nohup", "doas", "unbuffer"])

  export const DEFAULT_SHORT_MS = 45_000
  export const DEFAULT_LONG_MS = 60 * 60 * 1000

  /** First real tool of each pipeline/list segment (skips wrappers + VAR=val prefixes + paths). */
  export function tools(command: string): string[] {
    const segs = command.split(/(?:\|\||&&|[;\n|&])/)
    const out: string[] = []
    for (const seg of segs) {
      const words = seg.trim().split(/\s+/).filter(Boolean)
      let i = 0
      // skip VAR=val assignments and wrapper commands + their trivial args
      while (i < words.length) {
        const w = words[i]
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { i++; continue }
        if (WRAPPERS.has(w.includes("/") ? w.split("/").pop()! : w)) {
          i++
          // skip a wrapper's own numeric/flag args (e.g. `timeout 60`, `nice -n 5`)
          while (i < words.length && /^-|^\d/.test(words[i])) i++
          continue
        }
        break
      }
      if (i < words.length) {
        let t = words[i]
        if (t.includes("/")) t = t.split("/").pop()!
        if (t) out.push(t.toLowerCase())
      }
    }
    return out
  }

  /**
   * Decide the timeout (ms) for a command when the caller gave none. Priority:
   * per-tool override > any long-running tool present (exempt) > all short-lived
   * (strict) > provided default.
   */
  export function classify(command: string, defaultMs: number, policy?: Policy): { ms: number; reason: string } {
    const shortMs = policy?.short_ms ?? DEFAULT_SHORT_MS
    const longMs = policy?.long_ms ?? DEFAULT_LONG_MS
    const shortSet = policy?.short_tools ? new Set([...SHORT, ...policy.short_tools]) : SHORT
    const longSet = policy?.long_tools ? new Set([...LONG, ...policy.long_tools]) : LONG
    const ts = tools(command)
    if (ts.length === 0) return { ms: defaultMs, reason: "default" }
    for (const t of ts) {
      if (policy?.overrides && policy.overrides[t] != null) return { ms: policy.overrides[t], reason: `override:${t}` }
    }
    const longHit = ts.find((t) => longSet.has(t))
    if (longHit) return { ms: longMs, reason: `long-running:${longHit}` }
    if (ts.every((t) => shortSet.has(t))) return { ms: shortMs, reason: "short-lived" }
    return { ms: defaultMs, reason: "default" }
  }
}
