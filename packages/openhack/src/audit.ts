import * as fs from "fs"
import * as path from "path"

export namespace Audit {
  interface AuditEntry {
    id: string
    timestamp: string
    sessionId: string
    workflowId?: string
    agent: string
    actionType:
      | "tool_call"
      | "finding_create"
      | "finding_update"
      | "safety_block"
      | "scope_block"
      | "hallucination"
      | "recovery"
      | "config_change"
      | "session_start"
      | "session_end"
      | "assessment_complete"
      | "cleanup"
    toolName?: string
    toolArgs?: Record<string, unknown>
    toolResultSummary?: string
    findingId?: string
    target?: string
    safetyCheckResult?: "pass" | "block" | "warn"
    scopeCheckResult?: "pass" | "block"
    durationMs: number
    tokenUsage?: { input: number; output: number; cost: number }
  }

  const LOG_DIR = ".openhack/logs"
  let activeSession: string | null = null
  let logFile: string | null = null
  let buffer: AuditEntry[] = []
  let flushInterval: ReturnType<typeof setInterval> | null = null

  export function sessionStart(sessionId: string): void {
    activeSession = sessionId
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR, { recursive: true })
    }
    logFile = path.join(LOG_DIR, `${sessionId}.jsonl`)

    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId,
      agent: "system",
      actionType: "session_start",
      durationMs: 0,
    })

    flushInterval = setInterval(flush, 5000)
  }

  export function sessionEnd(): void {
    if (!activeSession) return

    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: activeSession,
      agent: "system",
      actionType: "session_end",
      durationMs: 0,
    })

    flush()
    if (flushInterval) clearInterval(flushInterval)
    activeSession = null
    logFile = null
  }

  export function log(entry: AuditEntry): void {
    if (!activeSession) return
    entry.sessionId = activeSession
    buffer.push(entry)
    if (buffer.length >= 10) flush()
  }

  function flush(): void {
    if (!logFile || buffer.length === 0) return
    const lines = buffer.map((e) => JSON.stringify(e)).join("\n") + "\n"
    fs.appendFileSync(logFile, lines, "utf-8")
    buffer = []
  }

  export function toolCall(
    toolName: string,
    args: Record<string, unknown>,
    durationMs: number,
    agent: string,
    resultSummary?: string,
    tokenUsage?: { input: number; output: number; cost: number },
  ): void {
    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: activeSession!,
      agent,
      actionType: "tool_call",
      toolName,
      toolArgs: sanitizeArgs(args),
      toolResultSummary: resultSummary,
      durationMs,
      tokenUsage,
    })
  }

  export function safetyBlock(command: string, reason: string, agent: string): void {
    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: activeSession!,
      agent,
      actionType: "safety_block",
      toolName: "bash",
      toolArgs: { command },
      toolResultSummary: reason,
      safetyCheckResult: "block",
      durationMs: 0,
    })
  }

  export function scopeBlock(command: string, reason: string, agent: string): void {
    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: activeSession!,
      agent,
      actionType: "scope_block",
      toolName: "bash",
      toolArgs: { command },
      toolResultSummary: reason,
      scopeCheckResult: "block",
      durationMs: 0,
    })
  }

  export function hallucination(command: string, reason: string, agent: string, count: number): void {
    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: activeSession!,
      agent,
      actionType: "hallucination",
      toolName: "bash",
      toolArgs: { command },
      toolResultSummary: `${reason} (hallucination #${count})`,
      durationMs: 0,
    })
  }

  export function recovery(agent: string, recoveryNumber: number): void {
    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: activeSession!,
      agent,
      actionType: "recovery",
      toolResultSummary: `Auto-recovery #${recoveryNumber} triggered`,
      durationMs: 0,
    })
  }

  export function assessmentComplete(): void {
    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: activeSession!,
      agent: "system",
      actionType: "assessment_complete",
      durationMs: 0,
    })
  }

  export function cleanup(agent: string, itemsRemoved: number, itemsFailed: number): void {
    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: activeSession!,
      agent,
      actionType: "cleanup",
      toolResultSummary: `${itemsRemoved} items removed, ${itemsFailed} failed`,
      durationMs: 0,
    })
  }

  export function findingCreate(findingId: string, agent: string): void {
    log({
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: activeSession!,
      agent,
      actionType: "finding_create",
      findingId,
      durationMs: 0,
    })
  }

  export function exportSession(sessionId: string, format: "json" | "csv" | "md"): string {
    const logPath = path.join(LOG_DIR, `${sessionId}.jsonl`)
    if (!fs.existsSync(logPath)) return ""

    const entries = fs
      .readFileSync(logPath, "utf-8")
      .trim()
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l))

    if (format === "json") {
      return JSON.stringify(entries, null, 2)
    }

    if (format === "csv") {
      const headers = ["timestamp", "agent", "actionType", "toolName", "target", "durationMs", "safetyCheckResult", "scopeCheckResult"]
      let csv = headers.join(",") + "\n"
      for (const e of entries) {
        csv += headers.map((h) => JSON.stringify(e[h] || "")).join(",") + "\n"
      }
      return csv
    }

    let md = "# Audit Log\n\n"
    md += `**Session**: ${sessionId}\n`
    md += `**Entries**: ${entries.length}\n\n`
    md += `| Time | Agent | Action | Tool | Duration | Safety | Scope |\n`
    md += `|------|-------|--------|------|----------|--------|-------|\n`
    for (const e of entries) {
      md += `| ${e.timestamp} | ${e.agent} | ${e.actionType} | ${e.toolName || "-"} | ${e.durationMs}ms | ${e.safetyCheckResult || "-"} | ${e.scopeCheckResult || "-"} |\n`
    }
    return md
  }

  function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {}
    const sensitive = ["password", "passwd", "token", "api_key", "secret", "key", "auth", "credential", "cookie"]

    for (const [key, value] of Object.entries(args)) {
      const isSensitive = sensitive.some((s) => key.toLowerCase().includes(s))
      if (typeof value === "string" && isSensitive) {
        sanitized[key] = "[REDACTED]"
      } else if (typeof value === "string" && value.length > 500) {
        sanitized[key] = value.slice(0, 500) + "..."
      } else {
        sanitized[key] = value
      }
    }

    return sanitized
  }

  function generateId(): string {
    return `audit-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
  }

  export function getActiveSession(): string | null {
    return activeSession
  }
}
