import * as fs from "fs"
import * as path from "path"

export namespace Scope {
  export interface ScopeConfig {
    enabled: boolean
    targets: string[]
    exclusions: string[]
    max_port_range: string
    allowed_tools: string[]
    disallowed_tools: string[]
    require_confirmation_for: string[]
  }

  export interface ScopeCheck {
    passed: boolean
    reason?: string
    matchedTarget?: string
  }

  let cachedConfig: ScopeConfig | null = null

  export function load(config?: ScopeConfig): ScopeConfig {
    if (config) {
      cachedConfig = config
      return config
    }
    if (cachedConfig) return cachedConfig

    const configPath = ".openhack/scope.json"
    if (fs.existsSync(configPath)) {
      try {
        cachedConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"))
        return cachedConfig!
      } catch {}
    }

    return {
      enabled: false,
      targets: [],
      exclusions: [],
      max_port_range: "1-65535",
      allowed_tools: [],
      disallowed_tools: [],
      require_confirmation_for: [],
    }
  }

  export function save(config: ScopeConfig): void {
    const dir = ".openhack"
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.join(dir, "scope.json"), JSON.stringify(config, null, 2))
    cachedConfig = config
  }

  function ipInCIDR(ip: string, cidr: string): boolean {
    try {
      const [range, bitsStr] = cidr.split("/")
      const bits = Math.min(32, Math.max(0, parseInt(bitsStr)))
      if (!bits && bits !== 0) return false
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
      const ipNum = ip.split(".").reduce((acc, oct) => ((acc << 8) >>> 0) + parseInt(oct), 0) >>> 0
      const rangeNum = range.split(".").reduce((acc, oct) => ((acc << 8) >>> 0) + parseInt(oct), 0) >>> 0
      return (ipNum & mask) >>> 0 === (rangeNum & mask) >>> 0
    } catch {
      return false
    }
  }

  function wildcardMatch(pattern: string, target: string): boolean {
    const regex = new RegExp(
      "^" + pattern.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$",
      "i",
    )
    return regex.test(target)
  }

  function extractIPs(command: string): string[] {
    const ipPattern = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
    return command.match(ipPattern) || []
  }

  function extractHosts(command: string): string[] {
    const hostPattern = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g
    const matches = command.match(hostPattern) || []
    return matches.filter((h) => !h.endsWith(".js") && !h.endsWith(".ts") && !h.endsWith(".py") && !h.endsWith(".json") && h.length > 4 && h.includes("."))
  }

  /** Reduce a URL/authority-style value (http://host:port/path, user@host) to its bare host. */
  function hostOf(value: string): string {
    let v = value.trim()
    const scheme = v.indexOf("://")
    if (scheme >= 0) v = v.slice(scheme + 3)
    v = v.split("/")[0].split("?")[0]
    if (v.includes("@")) v = v.split("@").pop() as string
    // Strip a trailing :port (but leave bare IPv6 / :: forms alone).
    if (v.includes(":") && !v.includes("::")) v = v.split(":")[0]
    return v
  }

  function isLocalhost(target: string): boolean {
    const localhosts = ["127.0.0.1", "::1", "localhost", "0.0.0.0"]
    return localhosts.includes(target)
  }

  export function isExcluded(target: string, config: ScopeConfig): boolean {
    for (const exclusion of config.exclusions) {
      if (wildcardMatch(exclusion, target)) return true
      if (exclusion.includes("/") && ipInCIDR(target, exclusion)) return true
    }
    return false
  }

  export function isInScope(target: string, config: ScopeConfig): ScopeCheck {
    if (!config.enabled) return { passed: true }

    if (isLocalhost(target)) return { passed: true }

    if (isExcluded(target, config)) {
      return { passed: false, reason: `Target ${target} is explicitly excluded from scope` }
    }

    for (const scopeTarget of config.targets) {
      if (wildcardMatch(scopeTarget, target) || target === scopeTarget) {
        return { passed: true, matchedTarget: scopeTarget }
      }
      if (scopeTarget.includes("/") && ipInCIDR(target, scopeTarget)) {
        return { passed: true, matchedTarget: scopeTarget }
      }
    }

    return { passed: false, reason: `Target ${target} is not in engagement scope. Scope: ${config.targets.join(", ")}` }
  }

  export function checkCommand(command: string, config?: ScopeConfig): ScopeCheck {
    const cfg = config || load()

    if (!cfg.enabled) return { passed: true }

    const ips = extractIPs(command)
    const hosts = extractHosts(command)
    const allTargets = [...ips, ...hosts]

    if (allTargets.length === 0) return { passed: true }

    for (const target of allTargets) {
      const result = isInScope(target, cfg)
      if (!result.passed) return result
    }

    return { passed: true }
  }

  export function checkToolCall(toolName: string, args: Record<string, unknown>, config?: ScopeConfig): ScopeCheck {
    const cfg = config || load()

    if (!cfg.enabled) return { passed: true }

    if (cfg.disallowed_tools.includes(toolName)) {
      return { passed: false, reason: `Tool '${toolName}' is disallowed in current scope` }
    }

    if (cfg.allowed_tools.length > 0 && !cfg.allowed_tools.includes(toolName) && !cfg.allowed_tools.includes("*")) {
      return { passed: false, reason: `Tool '${toolName}' is not in the allowed tools list` }
    }

    const targetFields = ["target", "host", "url", "domain", "ip", "hostname", "address", "endpoint"]
    for (const field of targetFields) {
      const value = args[field]
      if (typeof value === "string" && value.length > 2) {
        const check = isInScope(hostOf(value), cfg)
        if (!check.passed) return check
      }
    }

    return { passed: true }
  }

  export function generateScopePrompt(config: ScopeConfig): string {
    if (!config.enabled || config.targets.length === 0) {
      return ""
    }

    return `
## Engagement Scope
- **Targets**: ${config.targets.join(", ")}
- **Exclusions**: ${config.exclusions.length > 0 ? config.exclusions.join(", ") : "None"}
- **Port Range**: ${config.max_port_range}
- **Allowed Tools**: ${config.allowed_tools.length > 0 ? config.allowed_tools.join(", ") : "All"}
- **Disallowed Tools**: ${config.disallowed_tools.length > 0 ? config.disallowed_tools.join(", ") : "None"}

CRITICAL: All tool calls are validated against this scope. Out-of-scope targets will be BLOCKED.
`
  }
}
