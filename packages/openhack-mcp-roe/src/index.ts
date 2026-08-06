// OpenHack ROE-control MCP.
//
// Exposes the Rules-of-Engagement (`.openhack/roe/active.roe.json`) as MCP
// tools so the loop's agents (and any operator-side MCP client) can:
//
//   • READ  — inspect the active ROE without changing anything
//   • DRAFT — create / edit an unsigned draft (safe; signature checks still
//             block any tool call whose target/tool isn't in a SIGNED ROE)
//   • SIGN / REVOKE — the two operations that actually change what's
//     authorized. These are hard-gated: the operator must set an env var
//     BEFORE the MCP starts, otherwise the tool call refuses with an
//     explanatory error. This keeps the AI from self-authorizing by
//     accident (or by prompt-injection).
//
// Engagement dir is read from `OPENHACK_ENGAGEMENT_DIR` (default: current
// cwd of the MCP process). Every tool call rebases into that dir before
// touching `.openhack/`. All ROE operations use the openhack package's own
// `ROE` namespace so the HMAC-signing / signature-verification story stays
// identical to the CLI.

import { Server } from "@modelcontextprotocol/sdk/server/index.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
} from "@modelcontextprotocol/sdk/types.js"
import * as path from "node:path"
import * as fs from "node:fs"
import { ROE } from "../../openhack/src/roe"

// ─── engagement dir ─────────────────────────────────────────────────────
// Every tool call rebases into ENGAGEMENT_DIR before invoking the ROE module,
// so the MCP works whether spawned inside a repo or against a standalone
// `.openhack/` on disk.
const ENGAGEMENT_DIR = process.env.OPENHACK_ENGAGEMENT_DIR
  ? path.resolve(process.env.OPENHACK_ENGAGEMENT_DIR)
  : process.cwd()

let installedCwd = false
function ensureCwd(): void {
  if (installedCwd) return
  try { fs.mkdirSync(ENGAGEMENT_DIR, { recursive: true }) } catch {}
  try { process.chdir(ENGAGEMENT_DIR) } catch {}
  installedCwd = true
}

// ─── consent gates for sign / revoke ────────────────────────────────────
// The two operations that meaningfully change what's authorized require an
// env-var opt-in that the operator sets BEFORE launching the MCP:
//
//   OPENHACK_ROE_MCP_ALLOW_SIGN=1         allows roe_sign_current
//   OPENHACK_ROE_MCP_ALLOW_REVOKE=1       allows roe_revoke
//
// Optional strict mode:
//
//   OPENHACK_ROE_MCP_STRICT=1             the env var above must equal the
//     content of `.openhack/roe/.mcp-consent-nonce` (which the operator
//     creates), and the nonce file is deleted on successful use.

function readConsentNonce(): string | null {
  try {
    return fs.readFileSync(path.join(".openhack", "roe", ".mcp-consent-nonce"), "utf-8").trim()
  } catch { return null }
}
function consumeConsentNonce(): void {
  try { fs.rmSync(path.join(".openhack", "roe", ".mcp-consent-nonce")) } catch {}
}

interface ConsentDecision { allowed: boolean; reason?: string }

function checkSignConsent(): ConsentDecision {
  const env = process.env.OPENHACK_ROE_MCP_ALLOW_SIGN
  if (!env) {
    return {
      allowed: false,
      reason:
        "roe_sign_current is disabled: set OPENHACK_ROE_MCP_ALLOW_SIGN=1 in the MCP's environment (or a matching nonce if OPENHACK_ROE_MCP_STRICT=1), then restart the MCP.",
    }
  }
  if (process.env.OPENHACK_ROE_MCP_STRICT === "1") {
    const nonce = readConsentNonce()
    if (!nonce) {
      return {
        allowed: false,
        reason:
          "strict mode: no consent nonce found. Operator: `echo <nonce> > .openhack/roe/.mcp-consent-nonce` and set OPENHACK_ROE_MCP_ALLOW_SIGN=<same nonce>.",
      }
    }
    if (env !== nonce) {
      return { allowed: false, reason: "strict mode: env OPENHACK_ROE_MCP_ALLOW_SIGN does not match the nonce file." }
    }
  }
  return { allowed: true }
}

function checkRevokeConsent(): ConsentDecision {
  const env = process.env.OPENHACK_ROE_MCP_ALLOW_REVOKE
  if (!env) {
    return {
      allowed: false,
      reason:
        "roe_revoke is disabled: set OPENHACK_ROE_MCP_ALLOW_REVOKE=1 in the MCP's environment, then restart the MCP.",
    }
  }
  if (process.env.OPENHACK_ROE_MCP_STRICT === "1") {
    const nonce = readConsentNonce()
    if (!nonce) return { allowed: false, reason: "strict mode: no consent nonce found." }
    if (env !== nonce) return { allowed: false, reason: "strict mode: env OPENHACK_ROE_MCP_ALLOW_REVOKE does not match the nonce file." }
  }
  return { allowed: true }
}

// ─── tool shapes ────────────────────────────────────────────────────────

function ok(text: string) { return { content: [{ type: "text", text }] } as const }
function err(text: string) { return { content: [{ type: "text", text }], isError: true } as const }

function jsonBlock(v: unknown): string {
  return "```json\n" + JSON.stringify(v, null, 2) + "\n```"
}

// ─── server ─────────────────────────────────────────────────────────────

const server = new Server(
  { name: "openhack-roe", version: "0.1.0" },
  { capabilities: { tools: {} } },
)

const TOOLS = [
  // ---- READ ----
  {
    name: "roe_status",
    description:
      "Return the active ROE's structured status: id, company, targets, authorized_tools, exclusions, signature validity, expiry, days remaining, current status enum. Read-only.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "roe_validate",
    description:
      "Check whether a (target, tool) pair is authorized under the active signed ROE. Returns `{ blocked: boolean, reason?: string }` — this is the same decision the runtime plugin makes.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Hostname / IP / CIDR the tool would touch." },
        tool: { type: "string", description: "Tool binary/name (e.g. 'nmap', 'sqlmap', 'nuclei')." },
      },
      required: ["target", "tool"],
    },
  },
  {
    name: "roe_list_authorized_tools",
    description: "Return the authorized_tools array from the active ROE (or [] if no ROE).",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "roe_time_remaining_minutes",
    description: "Minutes until the active ROE expires; negative when expired; null if no ROE.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "roe_summary_markdown",
    description: "Human-readable Markdown status line — safe to paste into a report or log.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "roe_get",
    description:
      "Return the full active ROE document as JSON (draft or signed). Redacts the signature so the raw HMAC isn't echoed into logs.",
    inputSchema: { type: "object", properties: {} },
  },

  // ---- DRAFT (mutates unsigned only) ----
  {
    name: "roe_create_draft",
    description:
      "Create a fresh unsigned ROE template. Overwrites any prior draft. To take effect, the operator must eventually call roe_sign_current (which is env-gated).",
    inputSchema: {
      type: "object",
      properties: {
        company: { type: "string" },
        client: { type: "string" },
      },
    },
  },
  {
    name: "roe_set_targets",
    description: "Replace the draft's `targets` array (targets outside this list are blocked).",
    inputSchema: {
      type: "object",
      properties: { targets: { type: "array", items: { type: "string" }, minItems: 1 } },
      required: ["targets"],
    },
  },
  {
    name: "roe_set_authorized_tools",
    description:
      "Replace the draft's `authorized_tools` list. Use ['*'] to allow all. This is the tool-authorization axis of the runtime enforcement.",
    inputSchema: {
      type: "object",
      properties: { tools: { type: "array", items: { type: "string" }, minItems: 1 } },
      required: ["tools"],
    },
  },
  {
    name: "roe_set_exclusions",
    description: "Replace the draft's `exclusions` array (targets EXPLICITLY blocked even if they match `targets`).",
    inputSchema: {
      type: "object",
      properties: { exclusions: { type: "array", items: { type: "string" } } },
      required: ["exclusions"],
    },
  },
  {
    name: "roe_set_expiry_days",
    description:
      "Set the draft's expiry to N days from now (max 30). This bounds the entire engagement window; the runtime blocks all tool calls after expiry.",
    inputSchema: {
      type: "object",
      properties: { days: { type: "number", minimum: 1, maximum: 30 } },
      required: ["days"],
    },
  },
  {
    name: "roe_set_notes",
    description: "Set the draft's free-form `notes` field (surfaced in reports).",
    inputSchema: { type: "object", properties: { notes: { type: "string" } }, required: ["notes"] },
  },
  {
    name: "roe_diff",
    description:
      "Show the human-readable diff between the current draft (or a proposed patch) and the currently-signed ROE. Read-only.",
    inputSchema: { type: "object", properties: {} },
  },

  // ---- AI MODELS ----
  {
    name: "roe_list_authorized_models",
    description:
      "Return `authorized_models` from the active ROE. `[]` = every model allowed (no ROE model restriction). Read-only.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "roe_set_authorized_models",
    description:
      "Replace the draft's `authorized_models` list — the LLM models authorized for the engagement. Supports exact ids ('deepseek/deepseek-v4') and wildcards ('anthropic/*'). Use ['*'] to allow every model. Mutates the draft only; takes effect on the next roe_sign_current.",
    inputSchema: {
      type: "object",
      properties: {
        models: {
          type: "array",
          items: { type: "string" },
          description: "Model ids or wildcard patterns.",
          minItems: 1,
        },
      },
      required: ["models"],
    },
  },
  {
    name: "roe_validate_model",
    description:
      "Check whether a specific model id is authorized under the active ROE. Returns `{ blocked, reason? }` — same shape as roe_validate for tools.",
    inputSchema: {
      type: "object",
      properties: { model: { type: "string", description: "e.g. 'deepseek/deepseek-v4'" } },
      required: ["model"],
    },
  },
  {
    name: "roe_add_authorized_model",
    description:
      "Append a single model (or wildcard pattern) to the draft's `authorized_models` list, deduped. Convenience for iterative editing without replacing the whole list.",
    inputSchema: {
      type: "object",
      properties: { model: { type: "string" } },
      required: ["model"],
    },
  },
  {
    name: "roe_remove_authorized_model",
    description: "Remove a model (or pattern) from the draft's `authorized_models`.",
    inputSchema: {
      type: "object",
      properties: { model: { type: "string" } },
      required: ["model"],
    },
  },

  // ---- SIGN / REVOKE (env-gated) ----
  {
    name: "roe_sign_current",
    description:
      "Sign the current draft, activating it as the authorization document the runtime enforces. GATED: fails unless OPENHACK_ROE_MCP_ALLOW_SIGN is set in the MCP's environment. In strict mode, must additionally match a nonce file the operator drops.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "roe_revoke",
    description:
      "Revoke the active signed ROE (sets status=revoked, expires_at=now). GATED: fails unless OPENHACK_ROE_MCP_ALLOW_REVOKE is set in the MCP's environment.",
    inputSchema: { type: "object", properties: {} },
  },
] as const

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
}))

// ─── tool dispatch ──────────────────────────────────────────────────────

function redactSignature<T extends { signature?: string }>(doc: T): T {
  if (!doc.signature) return doc
  return { ...doc, signature: `[${doc.signature.slice(0, 8)}… ${doc.signature.length} chars]` } as T
}

function loadOrCreateDraft(): ROE.ROEDocument {
  // If a doc exists — signed, expired, revoked, or already-draft — reuse it
  // in place so field values (targets, exclusions, personnel, dates, notes)
  // survive the edit. `saveDraft` below then demotes it to draft and drops
  // the signature. The old behaviour of "spin up a fresh template when the
  // existing doc isn't already a draft" silently wiped targets on any
  // post-sign edit, which is exactly the kind of thing tamper-detection is
  // supposed to prevent, not cause.
  const existing = ROE.load()
  if (existing) return existing
  const fresh = ROE.createTemplate()
  ROE.save(fresh)
  return fresh
}

function saveDraft(doc: ROE.ROEDocument): void {
  // Any mutation on a draft clears prior signature bits so a stale signature
  // never survives an edit.
  doc.status = "draft"
  doc.signature = undefined
  doc.signer_key = undefined
  doc.signed_at = undefined
  ROE.save(doc)
}

server.setRequestHandler(CallToolRequestSchema, async (req: CallToolRequest) => {
  ensureCwd()
  const name = req.params.name
  const args = (req.params.arguments ?? {}) as Record<string, any>
  try {
    switch (name) {
      case "roe_status": {
        const doc = ROE.load()
        if (!doc) return ok("No ROE loaded.")
        return ok(jsonBlock({
          id: doc.id,
          company: doc.company,
          client: doc.client,
          status: doc.status,
          targets: doc.targets,
          authorized_tools: doc.authorized_tools,
          exclusions: doc.exclusions,
          signature_valid: doc.status === "signed" ? ROE.verifySignature(doc) : null,
          expires_at: doc.expires_at,
          date_start: doc.date_start,
          date_end: doc.date_end,
          days_remaining: Math.floor((new Date(doc.expires_at).getTime() - Date.now()) / 86400_000),
        }))
      }
      case "roe_validate": {
        const target = String(args.target ?? "")
        const tool = String(args.tool ?? "")
        if (!target || !tool) return err("roe_validate requires 'target' and 'tool'.")
        const d = ROE.enforce(ROE.load(), target, tool)
        return ok(jsonBlock({ blocked: d.blocked, reason: d.reason }))
      }
      case "roe_list_authorized_tools": {
        const doc = ROE.load()
        return ok(jsonBlock(doc?.authorized_tools ?? []))
      }
      case "roe_time_remaining_minutes": {
        const doc = ROE.load()
        if (!doc) return ok("null")
        return ok(String(Math.floor((new Date(doc.expires_at).getTime() - Date.now()) / 60_000)))
      }
      case "roe_summary_markdown": {
        const doc = ROE.load()
        return ok(ROE.getStatusString(doc))
      }
      case "roe_get": {
        const doc = ROE.load()
        if (!doc) return ok("null")
        return ok(jsonBlock(redactSignature(doc)))
      }

      // ---- draft edits ----
      case "roe_create_draft": {
        const doc = ROE.createTemplate(args.company, args.client)
        saveDraft(doc)
        return ok(`Created draft ROE ${doc.id} (targets=[${doc.targets.join(", ")}], expires_at=${doc.expires_at}).`)
      }
      case "roe_set_targets": {
        const doc = loadOrCreateDraft()
        if (!Array.isArray(args.targets) || args.targets.length === 0) return err("targets must be a non-empty array.")
        doc.targets = args.targets.map(String)
        saveDraft(doc)
        return ok(`targets=[${doc.targets.join(", ")}]`)
      }
      case "roe_set_authorized_tools": {
        const doc = loadOrCreateDraft()
        if (!Array.isArray(args.tools) || args.tools.length === 0) return err("tools must be a non-empty array.")
        doc.authorized_tools = args.tools.map(String)
        saveDraft(doc)
        return ok(`authorized_tools=[${doc.authorized_tools.join(", ")}]`)
      }
      case "roe_set_exclusions": {
        const doc = loadOrCreateDraft()
        if (!Array.isArray(args.exclusions)) return err("exclusions must be an array.")
        doc.exclusions = args.exclusions.map(String)
        saveDraft(doc)
        return ok(`exclusions=[${doc.exclusions.join(", ")}]`)
      }
      case "roe_set_expiry_days": {
        const doc = loadOrCreateDraft()
        const days = Number(args.days)
        if (!Number.isFinite(days) || days <= 0 || days > 30) return err("days must be a number between 1 and 30.")
        const end = new Date(Date.now() + days * 86400_000)
        doc.date_end = end.toISOString().slice(0, 10)
        doc.expires_at = end.toISOString()
        saveDraft(doc)
        return ok(`expires_at=${doc.expires_at}`)
      }
      case "roe_set_notes": {
        const doc = loadOrCreateDraft()
        doc.notes = String(args.notes ?? "")
        saveDraft(doc)
        return ok(`notes set (${doc.notes.length} chars)`)
      }
      case "roe_diff": {
        const draft = ROE.load()
        if (!draft) return ok("No ROE loaded.")
        // Best-effort diff: emit both the draft (redacted) and a note about
        // what would change on sign.
        return ok([
          "Current active ROE (may be draft or signed):",
          jsonBlock(redactSignature(draft)),
          draft.status === "draft"
            ? "Signing will produce an HMAC over `{id, company, client, targets, exclusions, authorized_tools, restricted_tools, date_start, date_end, expires_at, authorized_personnel}` and set status='signed'."
            : "Already signed. Edit a fresh draft with roe_create_draft to propose changes.",
        ].join("\n\n"))
      }

      // ---- ai models ----
      case "roe_list_authorized_models": {
        const doc = ROE.load()
        return ok(jsonBlock(doc?.authorized_models ?? []))
      }
      case "roe_set_authorized_models": {
        const doc = loadOrCreateDraft()
        if (!Array.isArray(args.models) || args.models.length === 0) return err("models must be a non-empty array.")
        doc.authorized_models = args.models.map(String)
        saveDraft(doc)
        return ok(`authorized_models=[${doc.authorized_models.join(", ")}]`)
      }
      case "roe_validate_model": {
        const model = String(args.model ?? "")
        if (!model) return err("roe_validate_model requires 'model'.")
        const d = ROE.enforceModel(ROE.load(), model)
        return ok(jsonBlock({ blocked: d.blocked, reason: d.reason }))
      }
      case "roe_add_authorized_model": {
        const doc = loadOrCreateDraft()
        const model = String(args.model ?? "")
        if (!model) return err("model must be a non-empty string.")
        const set = new Set(doc.authorized_models ?? [])
        set.add(model)
        doc.authorized_models = [...set]
        saveDraft(doc)
        return ok(`authorized_models=[${doc.authorized_models.join(", ")}]`)
      }
      case "roe_remove_authorized_model": {
        const doc = loadOrCreateDraft()
        const model = String(args.model ?? "")
        const before = doc.authorized_models ?? []
        doc.authorized_models = before.filter((m) => m !== model)
        saveDraft(doc)
        return ok(`authorized_models=[${doc.authorized_models.join(", ")}]`)
      }

      // ---- sign / revoke (gated) ----
      case "roe_sign_current": {
        const consent = checkSignConsent()
        if (!consent.allowed) return err(consent.reason ?? "sign denied")
        const doc = ROE.load()
        if (!doc) return err("No ROE draft to sign. Call roe_create_draft first.")
        if (doc.status === "signed" && ROE.verifySignature(doc))
          return ok(`ROE ${doc.id} is already signed and valid.`)
        ROE.sign(doc)
        if (process.env.OPENHACK_ROE_MCP_STRICT === "1") consumeConsentNonce()
        return ok(`Signed ROE ${doc.id} (expires ${doc.expires_at}). authorized_tools=[${doc.authorized_tools.join(", ")}].`)
      }
      case "roe_revoke": {
        const consent = checkRevokeConsent()
        if (!consent.allowed) return err(consent.reason ?? "revoke denied")
        const doc = ROE.load()
        if (!doc) return err("No active ROE to revoke.")
        ROE.revoke(doc)
        if (process.env.OPENHACK_ROE_MCP_STRICT === "1") consumeConsentNonce()
        return ok(`Revoked ROE ${doc.id}.`)
      }

      default:
        return err(`Unknown tool: ${name}`)
    }
  } catch (e: any) {
    return err(`Tool '${name}' failed: ${e?.message ?? e}`)
  }
})

async function main(): Promise<void> {
  ensureCwd()
  const transport = new StdioServerTransport()
  await server.connect(transport)
  // Ready — stdio pipes are hooked up. Log a startup line to stderr so the
  // parent process sees the MCP is live (the SDK reserves stdout for the RPC
  // channel).
  process.stderr.write(`[openhack-roe-mcp] ready in ${ENGAGEMENT_DIR} · sign_allowed=${!!process.env.OPENHACK_ROE_MCP_ALLOW_SIGN} · revoke_allowed=${!!process.env.OPENHACK_ROE_MCP_ALLOW_REVOKE} · strict=${process.env.OPENHACK_ROE_MCP_STRICT === "1"}\n`)
}

main().catch((e) => {
  process.stderr.write(`[openhack-roe-mcp] fatal: ${e?.stack ?? e}\n`)
  process.exit(1)
})
