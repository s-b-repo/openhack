// OpenHack Findings-store MCP.
//
// Read + curate the findings store at `.openhack/findings/<target>.json`
// (HMAC-signed by the openhack framework). Every write goes through the
// same `Findings.add / markVerified / markFalsePositive` API so evidence
// gates, hash dedup, and audit trails are preserved.
//
// Read tools are ungated. Mark / add / delete tools are env-gated by
// `OPENHACK_FINDINGS_MCP_ALLOW_MUTATE=1` — an AI shouldn't be able to
// silently promote its own uncertain findings to verified, or delete
// evidence, without operator consent for that shell session.

import * as fs from "node:fs"
import * as path from "node:path"
import { Findings } from "../../openhack/src/findings"
import { ok, err, jsonBlock as json, checkConsent, resolveEngagementDir, runStdioMain } from "../../openhack-mcp-common/src"

const ENGAGEMENT_DIR = resolveEngagementDir()

function checkMutate() {
  return checkConsent({ envVar: "OPENHACK_FINDINGS_MCP_ALLOW_MUTATE", action: "Findings mutating tools" })
}

function summariseFinding(f: Findings.Finding): Record<string, any> {
  return {
    id: f.id, hash: f.hash, title: f.title, severity: f.severity, status: f.status,
    target: f.target, affected_component: f.affected_component, cwe: f.cwe, cvss_score: f.cvss_score,
    source_agent: f.source_agent, timestamp: f.timestamp,
    evidence_files: f.evidence_files, manual_verify_required: f.manual_verify_required,
    tags: f.tags,
    promotionChain_len: f.promotionChain?.length ?? 0,
    challengedByCouncils_len: f.challengedByCouncils?.length ?? 0,
  }
}

const TOOLS = [
  {
    name: "findings_list_targets",
    description: "List every target with a findings store on disk. Read-only.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "findings_summary",
    description: "Summary for one target: total count, per-severity, per-status, HMAC integrity check.",
    inputSchema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] },
  },
  {
    name: "findings_list",
    description: "List every finding for a target (compact form). Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        severity_min: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
        status: { type: "string", enum: ["verified", "uncertain", "false_positive"] },
        limit: { type: "number" },
      },
      required: ["target"],
    },
  },
  {
    name: "findings_get",
    description: "Fetch the full finding record by id (includes description, audit_trail, promotionChain).",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string" }, id: { type: "string" } },
      required: ["target", "id"],
    },
  },
  {
    name: "findings_uncertain",
    description: "Every finding still flagged manual_verify_required. Read-only.",
    inputSchema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] },
  },
  {
    name: "findings_verified",
    description: "Every verified finding. Read-only.",
    inputSchema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] },
  },
  {
    name: "findings_report_markdown",
    description: "Format the target's findings as the same markdown block `openhack findings --target X` emits. Read-only.",
    inputSchema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] },
  },
  {
    name: "findings_integrity_check",
    description: "Verify HMAC on every finding for a target. Returns the list of tamper-detected records (if any).",
    inputSchema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] },
  },
  {
    name: "findings_mark_verified",
    description: "Mark a finding as verified — REQUIRES a reproducible PoC + at least one on-disk evidence file (enforced by Findings.markVerified). GATED: needs OPENHACK_FINDINGS_MCP_ALLOW_MUTATE=1.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        id: { type: "string" },
        oracle: { type: "string", description: "Name of the verifying entity (e.g. 'operator', 'council-r2')." },
        poc: { type: "string", description: "Reproducible proof-of-concept command / request / step." },
        evidence_files: { type: "array", items: { type: "string" }, description: "On-disk paths that already exist." },
      },
      required: ["target", "id", "oracle", "poc", "evidence_files"],
    },
  },
  {
    name: "findings_mark_false_positive",
    description: "Mark a finding as false positive with a reason. GATED.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        id: { type: "string" },
        reason: { type: "string" },
      },
      required: ["target", "id", "reason"],
    },
  },
  {
    name: "findings_export_json",
    description: "Full findings store as JSON, suitable for piping into an external report or a SysReptor upload. Read-only.",
    inputSchema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] },
  },
] as const

async function handle(name: string, args: Record<string, any>) {
  switch (name) {
      case "findings_list_targets": {
        const dir = path.join(ENGAGEMENT_DIR, ".openhack", "findings")
        try {
          const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json") && !f.startsWith("."))
          return ok(json({ targets: files.map((f) => f.slice(0, -5)).sort() }))
        } catch { return ok(json({ targets: [] })) }
      }
      case "findings_summary": {
        const store = Findings.load(String(args.target))
        return ok(json({
          target: store.target,
          total: store.totalCount,
          by_severity: store.bySeverity,
          by_status: store.byStatus,
          last_updated: store.lastUpdated,
          integrity_violations: Findings.getIntegrityViolations(store).length,
        }))
      }
      case "findings_list": {
        const store = Findings.load(String(args.target))
        const sevOrder: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
        const minRank = args.severity_min ? sevOrder[String(args.severity_min)] ?? 0 : 0
        let found = store.findings
          .filter((f) => (sevOrder[f.severity] ?? 0) >= minRank)
          .filter((f) => !args.status || f.status === args.status)
          .map(summariseFinding)
        if (args.limit) found = found.slice(0, Number(args.limit))
        return ok(json({ target: args.target, count: found.length, findings: found }))
      }
      case "findings_get": {
        const store = Findings.load(String(args.target))
        const f = store.findings.find((x) => x.id === String(args.id))
        return f ? ok(json(f)) : err(`no finding ${args.id} in ${args.target}`)
      }
      case "findings_uncertain": {
        const store = Findings.load(String(args.target))
        return ok(json(Findings.getUncertain(store).map(summariseFinding)))
      }
      case "findings_verified": {
        const store = Findings.load(String(args.target))
        return ok(json(Findings.getVerified(store).map(summariseFinding)))
      }
      case "findings_report_markdown": {
        const store = Findings.load(String(args.target))
        return ok(Findings.formatFindingsSummary(store))
      }
      case "findings_integrity_check": {
        const store = Findings.load(String(args.target))
        const violations = Findings.getIntegrityViolations(store)
        return ok(json({ target: args.target, ok: violations.length === 0, tampered: violations.map(summariseFinding) }))
      }
      case "findings_mark_verified": {
        const c = checkMutate()
        if (!c.allowed) return err(c.reason ?? "denied")
        const store = Findings.load(String(args.target))
        const after = Findings.markVerified(store, String(args.id), String(args.oracle), {
          poc: String(args.poc),
          evidenceFiles: (args.evidence_files ?? []).map(String),
        })
        const f = after.findings.find((x) => x.id === String(args.id))
        return f ? ok(`Marked ${f.id}: ${f.status} (was ${f.status}). Evidence gate: ${f.status === "verified" ? "passed" : "rejected"}.\n\n${json(summariseFinding(f))}`) : err(`no finding ${args.id}`)
      }
      case "findings_mark_false_positive": {
        const c = checkMutate()
        if (!c.allowed) return err(c.reason ?? "denied")
        const store = Findings.load(String(args.target))
        Findings.markFalsePositive(store, String(args.id), String(args.reason))
        return ok(`Marked ${args.id} as false_positive.`)
      }
      case "findings_export_json": {
        const store = Findings.load(String(args.target))
        return ok(json(store))
      }
      default: return err(`Unknown tool: ${name}`)
  }
}

runStdioMain({
  name: "openhack-findings-mcp",
  tools: TOOLS as any,
  handle,
  banner: () => `in ${ENGAGEMENT_DIR} · mutate_allowed=${!!process.env.OPENHACK_FINDINGS_MCP_ALLOW_MUTATE}`,
})
