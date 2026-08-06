/**
 * Shared IPv4 / hostname matching helpers used by both the engagement Scope and
 * the Rules of Engagement. Consolidates what used to be three divergent copies
 * of the IP/host regexes and match logic (scope.ts, roe.ts, and the old inline
 * block in shell.ts) so scope and ROE decide "is this target in bounds?"
 * identically — including real CIDR range matching, which ROE previously lacked.
 */
export namespace Net {
  /** True if IPv4 `ip` falls inside `cidr` (e.g. "10.0.0.0/24"). Non-IPv4 input → false. */
  export function ipInCIDR(ip: string, cidr: string): boolean {
    try {
      const [range, bitsStr] = cidr.split("/")
      const bits = Math.min(32, Math.max(0, parseInt(bitsStr, 10)))
      if (Number.isNaN(bits)) return false
      const toNum = (v: string) => {
        const octets = v.split(".")
        if (octets.length !== 4) return null
        let acc = 0
        for (const oct of octets) {
          const n = parseInt(oct, 10)
          if (Number.isNaN(n) || n < 0 || n > 255) return null
          acc = ((acc << 8) >>> 0) + n
        }
        return acc >>> 0
      }
      const ipNum = toNum(ip)
      const rangeNum = toNum(range)
      if (ipNum === null || rangeNum === null) return false
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
      return ((ipNum & mask) >>> 0) === ((rangeNum & mask) >>> 0)
    } catch {
      return false
    }
  }

  /** Glob-style match where `*` is a wildcard and dots are literal, case-insensitive. */
  export function wildcardMatch(pattern: string, value: string): boolean {
    const regex = new RegExp("^" + pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i")
    return regex.test(value)
  }

  /**
   * Match a single target against one scope/ROE pattern. Handles exact match,
   * CIDR ranges (pattern contains "/"), and wildcards.
   */
  export function matchTarget(pattern: string, target: string): boolean {
    if (pattern === "*") return true
    if (pattern === target) return true
    if (pattern.includes("/")) return ipInCIDR(target, pattern)
    return wildcardMatch(pattern, target)
  }

  /** Reduce a URL/authority value (scheme://user@host:port/path?q) to its bare host. */
  export function hostOf(value: string): string {
    let v = value.trim()
    const scheme = v.indexOf("://")
    if (scheme >= 0) v = v.slice(scheme + 3)
    v = v.split("/")[0].split("?")[0]
    if (v.includes("@")) v = v.split("@").pop() as string
    if (v.includes(":") && !v.includes("::")) v = v.split(":")[0]
    return v
  }

  const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
  const HOST_RE = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g
  // Bare filenames that the host regex would otherwise pick up as domains.
  const NON_HOST_SUFFIX = /\.(js|ts|jsx|tsx|py|json|md|txt|sh|go|rs|rb|yml|yaml|toml|cfg|conf|log|csv|xml|html?)$/i

  export function extractIPs(text: string): string[] {
    return text.match(IP_RE) ?? []
  }

  export function extractHosts(text: string): string[] {
    return (text.match(HOST_RE) ?? []).filter((h) => h.length > 4 && h.includes(".") && !NON_HOST_SUFFIX.test(h))
  }

  /** All IP and hostname targets referenced in `text`, de-duplicated. */
  export function extractTargets(text: string): string[] {
    return [...new Set([...extractIPs(text), ...extractHosts(text)])]
  }

  /** The first target referenced in `text`, IPs taking priority, or null. */
  export function firstTarget(text: string): string | null {
    return extractIPs(text)[0] ?? extractHosts(text)[0] ?? null
  }
}
