import * as fs from "node:fs"
import * as path from "node:path"
import { Safety } from "./safety"
import { Scope } from "./scope"
import { ResourceManager } from "./resources"
import { HallucinationGuard } from "./hallucination"
import { Audit } from "./audit"
import { Findings } from "./findings"
import { Secrets } from "./secrets"

export namespace MiddlewareChain {
  export type Middleware = "safety" | "scope" | "resources" | "hallucination"

  export interface MiddlewareResult {
    blocked: boolean
    reason?: string
    middleware: Middleware
    shouldRecover?: boolean
  }

  export interface ToolCallContext {
    toolName: string
    args: Record<string, unknown>
    agent: string
    sessionId: string
    workflowId?: string
  }

  export interface ChainConfig {
    safety: Safety.SafetyConfig
    scope: Scope.ScopeConfig
    hallucinationGuard: HallucinationGuard.Guard
    target: string
  }

  export function preflight(command: string, agent: string, config: ChainConfig): MiddlewareResult {
    // [1] Safety Harness — HARD BLOCK on destructive patterns
    const safetyResult = Safety.check(command, agent, config.safety)
    if (safetyResult.blocked) {
      return {
        blocked: true,
        reason: safetyResult.reason,
        middleware: "safety",
      }
    }

    // [2] Scope Enforcer — HARD BLOCK on out-of-scope targets
    const scopeResult = Scope.checkCommand(command, config.scope)
    if (!scopeResult.passed) {
      Audit.scopeBlock(command, scopeResult.reason || "Out of scope", agent)
      return {
        blocked: true,
        reason: `SCOPE BLOCKED: ${scopeResult.reason}`,
        middleware: "scope",
      }
    }

    // [3] Hallucination Guard — SOFT BLOCK, counts toward threshold
    const hallucinationResult = config.hallucinationGuard.check(command)
    if (hallucinationResult.blocked) {
      Audit.hallucination(
        command,
        hallucinationResult.reason || "Hallucination detected",
        agent,
        config.hallucinationGuard.counter,
      )
      return {
        blocked: true,
        reason: hallucinationResult.reason,
        middleware: "hallucination",
        shouldRecover: hallucinationResult.shouldRecover,
      }
    }

    if (hallucinationResult.reason) {
      Audit.hallucination(
        command,
        hallucinationResult.reason,
        agent,
        config.hallucinationGuard.counter,
      )
    }

    return { blocked: false, middleware: "hallucination" }
  }

  export function preflightToolCall(ctx: ToolCallContext, config: ChainConfig): MiddlewareResult {
    // [2] Scope enforcer for MCP tool calls
    const scopeResult = Scope.checkToolCall(ctx.toolName, ctx.args, config.scope)
    if (!scopeResult.passed) {
      Audit.scopeBlock(
        `${ctx.toolName}(${JSON.stringify(ctx.args).slice(0, 200)})`,
        scopeResult.reason || "Out of scope",
        ctx.agent,
      )
      return {
        blocked: true,
        reason: `SCOPE BLOCKED: ${scopeResult.reason}`,
        middleware: "scope",
      }
    }

    // [3] Acquire resource lock if applicable
    for (const field of ["target", "host", "ip"]) {
      const value = ctx.args[field]
      if (typeof value === "string" && value.length > 2) {
        if (!ResourceManager.isAvailable("target", value)) {
          Audit.toolCall(
            ctx.toolName,
            ctx.args,
            0,
            ctx.agent,
            `Resource conflict: target ${value} already in use`,
          )
          return {
            blocked: true,
            reason: `RESOURCE BLOCKED: Target ${value} is already being scanned by another agent`,
            middleware: "resources",
          }
        }
        break
      }
    }

    return { blocked: false, middleware: "resources" }
  }

  export function postflight(
    toolName: string,
    args: Record<string, unknown>,
    agent: string,
    sessionId: string,
    durationMs: number,
    resultSummary?: string,
    tokenUsage?: { input: number; output: number; cost: number },
  ): void {
    // Sanitize output before logging
    const sanitizedSummary = resultSummary ? Secrets.sanitizeOutput(resultSummary) : undefined
    Audit.toolCall(toolName, args, durationMs, agent, sanitizedSummary, tokenUsage)
  }

  export function checkFindingDetection(
    output: string,
    target: string,
    agent: string,
    sessionId: string,
  ): boolean {
    const findingIndicators = [
      "vulnerability",
      "CVE-",
      "SQL injection",
      "XSS",
      "cross-site",
      "open port",
      "exposed",
      "misconfiguration",
      "weak password",
      "default credentials",
      "CVSS",
      "finding",
      "exploit successful",
      "shell obtained",
      "access granted",
      "authenticated as",
    ]

    const lower = output.toLowerCase()
    return findingIndicators.some((indicator) => lower.includes(indicator.toLowerCase()))
  }

  // Cheap sentinel: any of a few high-signal words that must appear in the FIRST
  // 4 KB of a huge output before we spend O(N) regex scans on the rest. A 200 KB
  // ceiling bounds the worst-case cost of the follow-on full scan.
  const HUGE_THRESHOLD = 200 * 1024
  const SENTINEL_RE = /\b(vulnerab|cve-|cvss|injection|xss|misconfig|shell obtained|access granted|open port|exposed|weak password|default credentials|finding)/i

  export function autoSaveFindingIfDetected(
    output: string,
    target: string,
    agent: string,
    sessionId: string,
  ): string | null {
    // Hot-path guard: on very large outputs (a full dump from a scanner or a
    // download), only pay the full regex scan cost when the leading window
    // already looks findings-y. This eliminates the pathological case where
    // every scanner result gets re-scanned end-to-end on the tool.execute.after
    // hook of every MCP tool call.
    if (output.length > HUGE_THRESHOLD && !SENTINEL_RE.test(output.slice(0, 4096))) return null

    if (checkFindingDetection(output, target, agent, sessionId)) {
      const store = Findings.load(target, sessionId)
      const title = extractFindingTitle(output)
      const severity = extractSeverity(output)
      const description = output.slice(0, 1000)

      // Capture the raw tool output as an on-disk evidence artifact so this
      // uncertain finding carries proof for later evidence-backed verification.
      // Evidence write is fire-and-forget: an evidence file failing to land
      // must not block the finding record itself (the finding stays uncertain
      // and the operator can regenerate the artifact from the session log).
      const id = Findings.generateId()
      const evidenceFiles: string[] = []
      try {
        const evidenceDir = path.join(".openhack", "findings", "evidence")
        fs.mkdirSync(evidenceDir, { recursive: true })
        const evidencePath = path.join(evidenceDir, `${id}.txt`)
        // Async, unawaited — the finding record below still points at the path
        // and the file will land before the operator opens it.
        fs.promises
          .writeFile(evidencePath, output, { encoding: "utf-8", mode: 0o600 })
          .catch(() => {})
        evidenceFiles.push(evidencePath)
      } catch {
        // best-effort: a finding without a captured artifact simply stays uncertain
      }

      const finding: Findings.Finding = {
        id,
        timestamp: new Date().toISOString(),
        target,
        title: title || "Auto-detected finding",
        description,
        severity,
        status: "uncertain",
        source_agent: agent,
        source_session: sessionId,
        evidence_files: evidenceFiles,
        manual_verify_required: true,
        audit_trail: [],
        promotionChain: [],
        challengedByCouncils: [],
        hash: "",
        hmac: "",
        tags: [],
      }

      Findings.add(store, finding, sessionId)
      Audit.findingCreate(finding.id, agent)
      return finding.id
    }
    return null
  }

  function extractFindingTitle(output: string): string | null {
    const patterns = [
      /found\s+(.+?)(?:\.|$)/i,
      /discovered\s+(.+?)(?:\.|$)/i,
      /detected\s+(.+?)(?:\.|$)/i,
      /vulnerable to\s+(.+?)(?:\.|$)/i,
    ]
    for (const pattern of patterns) {
      const match = output.match(pattern)
      if (match) return match[1].trim().slice(0, 100)
    }
    return null
  }

  function extractSeverity(output: string): "critical" | "high" | "medium" | "low" | "info" {
    const lower = output.toLowerCase()
    if (lower.includes("critical") || lower.includes("rce") || lower.includes("remote code execution")) return "critical"
    if (lower.includes("high") || lower.includes("sqli") || lower.includes("sql injection") || lower.includes("authentication bypass")) return "high"
    if (lower.includes("medium") || lower.includes("xss") || lower.includes("csrf")) return "medium"
    if (lower.includes("low") || lower.includes("info") || lower.includes("informational")) return "low"
    return "info"
  }

  export function assessmentComplete(
    target: string,
    sessionId: string,
    agent: string,
  ): { cleanedUp: boolean; itemsRemoved: number; itemsFailed: number } {
    Audit.assessmentComplete()
    Audit.sessionEnd()

    const resourcesRemoved = ResourceManager.releaseAllForSession(sessionId)
    const orphanCount = ResourceManager.getOrphanCount()

    if (orphanCount > 0) {
      ResourceManager.forceCleanup()
    }

    return {
      cleanedUp: orphanCount === 0,
      itemsRemoved: resourcesRemoved,
      itemsFailed: orphanCount,
    }
  }
}

export default MiddlewareChain
