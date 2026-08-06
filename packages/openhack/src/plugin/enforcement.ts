import { Safety } from "../safety"
import { Scope } from "../scope"
import { ROE } from "../roe"
import { inspectShellCommand } from "../hooks/shell-hook"

/**
 * Pure enforcement decision for a single tool call. Composes the OpenHack
 * safety harness, engagement scope, and Rules of Engagement into one verdict so
 * the plugin's `tool.execute.before` hook can block with a single throw.
 *
 * Shell commands (`bash`) are checked for destructive patterns, in-scope
 * targets, and ROE authorization of the invoked binary. Every other tool is
 * checked against the engagement scope (allowed/disallowed tools + any
 * target-bearing argument).
 */
export interface Decision {
  blocked: boolean
  reason?: string
  kind?: "safety" | "scope" | "roe"
}

const SHELL_TOOLS = new Set(["bash"])

export function evaluateToolCall(tool: string, args: Record<string, unknown>): Decision {
  const scopeCfg = Scope.load()

  if (SHELL_TOOLS.has(tool)) {
    const command = typeof args["command"] === "string" ? (args["command"] as string) : ""
    if (!command) return { blocked: false }

    // Safety harness — respects the /danger toggle via Safety.isSafe(), and uses
    // the normalized inspector so obfuscated destructive commands are caught.
    if (Safety.isSafe()) {
      const insp = inspectShellCommand(command)
      if (insp.blocked) return { blocked: true, reason: insp.reason, kind: "safety" }
    }

    // Engagement scope — targets referenced in the command must be in scope.
    const sc = Scope.checkCommand(command, scopeCfg)
    if (!sc.passed) return { blocked: true, reason: sc.reason, kind: "scope" }

    // Rules of Engagement — the invoked binary and target must be authorized.
    const roeDecision = ROE.enforce(ROE.load(), ROE.extractTarget(command), ROE.extractTool(command))
    if (roeDecision.blocked) return { blocked: true, reason: roeDecision.reason, kind: "roe" }

    return { blocked: false }
  }

  // Non-shell tools: scope enforcement on tool name + target-bearing args.
  const sc = Scope.checkToolCall(tool, args, scopeCfg)
  if (!sc.passed) return { blocked: true, reason: sc.reason, kind: "scope" }
  return { blocked: false }
}
