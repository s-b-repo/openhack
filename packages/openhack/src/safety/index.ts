import { Audit } from "../audit"
import { DESTRUCTIVE_PATTERNS, WARNING_PATTERNS } from "../hooks/shell-hook"

export namespace Safety {
  export interface BlockedCommand {
    command: string
    reason: string
    pattern: string
  }

  export interface SafetyConfig {
    enabled: boolean
    whitelist: string[]
    require_confirmation: string[]
    profiles: Record<string, SafetyProfile>
  }

  export interface SafetyProfile {
    deny: string[]
    allow: string[]
  }

  export interface MiddlewareResult {
    blocked: boolean
    reason?: string
    middleware: "safety" | "scope" | "resources" | "hallucination"
    shouldRecover?: boolean
  }

  // Block/warning patterns are defined once in ../hooks/shell-hook so every
  // enforcement path (this middleware and the interactive shell tool) agrees.

  export function inspect(command: string, config?: SafetyConfig): BlockedCommand | null {
    if (config && !config.enabled) return null

    const trimmed = command.trim()

    if (config?.whitelist?.some((w) => trimmed.includes(w))) {
      return null
    }

    for (const { pattern, reason } of DESTRUCTIVE_PATTERNS) {
      if (pattern.test(trimmed)) {
        return { command: trimmed, reason, pattern: pattern.source }
      }
    }

    return null
  }

  export function check(command: string, agent: string, config?: SafetyConfig): MiddlewareResult {
    if (config && !config.enabled) return { blocked: false, middleware: "safety" }

    const trimmed = command.trim()

    if (config?.whitelist?.some((w) => trimmed.includes(w))) {
      return { blocked: false, middleware: "safety" }
    }

    if (config?.profiles?.[agent]) {
      const profile = config.profiles[agent]
      if (profile.allow.some((a) => trimmed.includes(a))) {
        return { blocked: false, middleware: "safety" }
      }
    }

    for (const { pattern, reason } of DESTRUCTIVE_PATTERNS) {
      if (pattern.test(trimmed)) {
        Audit.safetyBlock(trimmed, reason, agent)
        return { blocked: true, reason: `SAFETY BLOCKED: ${reason}`, middleware: "safety" }
      }
    }

    const warnings = getWarnings(trimmed)
    if (warnings.length > 0) {
      return {
        blocked: false,
        reason: `WARNING: ${warnings.map((w) => w.reason).join("; ")}`,
        middleware: "safety",
      }
    }

    return { blocked: false, middleware: "safety" }
  }

  export function getWarnings(command: string): Array<{ reason: string }> {
    return WARNING_PATTERNS.filter(({ pattern }) => pattern.test(command.trim())).map(({ reason }) => ({ reason }))
  }

  export function isSafe(): boolean {
    try {
      const fs = require("node:fs")
      const configPath = ".openhack/openhack.jsonc"
      if (fs.existsSync(configPath)) {
        const config = JSON.parse(fs.readFileSync(configPath, "utf-8"))
        return config.safety?.enabled !== false
      }
      return true
    } catch {
      return true
    }
  }

  export function toggle(): boolean {
    try {
      const fs = require("node:fs")
      const configPath = ".openhack/openhack.jsonc"
      let config: any = { safety: { enabled: true } }
      if (fs.existsSync(configPath)) {
        config = JSON.parse(fs.readFileSync(configPath, "utf-8"))
      }
      const current = config.safety?.enabled !== false
      config.safety = { ...(config.safety || {}), enabled: !current }
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2))
      return !current
    } catch {
      return false
    }
  }

  export function getBlockedMessage(blocked: BlockedCommand): string {
    return `SAFETY HARNESS BLOCKED: ${blocked.reason}
Command: ${blocked.command}
Matched pattern: ${blocked.pattern}

This command has been blocked by the OpenHack safety harness.
Use /danger to bypass for current session.
`
  }
}
