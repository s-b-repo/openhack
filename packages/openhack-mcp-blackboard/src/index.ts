// OpenHack inter-manager blackboard MCP.
//
// Exposes the phase-manager blackboard (`.openhack/blackboard/<target>.json`,
// HMAC-signed by the framework) so an IN-SESSION worker agent — not just the
// loop's phase-managers — can read peer directives and (when the operator
// consents) post its own. Everything goes through the same `Blackboard` API so
// HMAC signing, the atomic-mkdir lock, and message provenance are preserved.
//
// Read tools (inbox / list) are ungated. Mutating tools (post / mark_consumed)
// are env-gated by OPENHACK_BLACKBOARD_MCP_ALLOW_POST=1 — an AI shouldn't be
// able to inject cross-manager directives without operator consent for that
// shell session.

import { Blackboard } from "../../openhack/src/blackboard"
import { ok, err, jsonBlock as json, checkConsent, resolveEngagementDir, runStdioMain } from "../../openhack-mcp-common/src"

const ENGAGEMENT_DIR = resolveEngagementDir()

const PHASES = ["recon", "enumeration", "exploitation", "post-exploitation", "c2", "main"] as const
const KINDS = ["directive", "hint", "request", "ack"] as const

function checkPost() {
  return checkConsent({ envVar: "OPENHACK_BLACKBOARD_MCP_ALLOW_POST", action: "Blackboard mutating tools (post / mark_consumed)" })
}

function isPhase(v: any): v is Blackboard.Phase {
  return typeof v === "string" && (PHASES as readonly string[]).includes(v)
}
function isKind(v: any): v is Blackboard.Kind {
  return typeof v === "string" && (KINDS as readonly string[]).includes(v)
}

const TOOLS = [
  {
    name: "blackboard_inbox",
    description:
      "Messages addressed to a phase (or broadcast to 'all'), excluding that phase's own posts. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        phase: { type: "string", enum: PHASES as unknown as string[], description: "The reading phase-manager." },
        include_all: { type: "boolean", description: "Include broadcasts to 'all' (default true)." },
        only_open: { type: "boolean", description: "Hide already-consumed messages (default true)." },
      },
      required: ["target", "phase"],
    },
  },
  {
    name: "blackboard_list",
    description: "Every message on a target's blackboard (compact). Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        only_open: { type: "boolean", description: "Only show open (unconsumed) messages (default false)." },
      },
      required: ["target"],
    },
  },
  {
    name: "blackboard_post",
    description:
      "Post a peer directive/hint/request from one phase to another (or 'all'). GATED: needs OPENHACK_BLACKBOARD_MCP_ALLOW_POST=1.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        from: { type: "string", enum: PHASES as unknown as string[] },
        to: { type: "string", description: "A phase id, or 'all' for a broadcast." },
        kind: { type: "string", enum: KINDS as unknown as string[] },
        text: { type: "string" },
        refs: { type: "array", items: { type: "string" }, description: "Optional finding/node ids this message references." },
        round: { type: "number", description: "Loop round number (default 0)." },
      },
      required: ["target", "from", "to", "kind", "text"],
    },
  },
  {
    name: "blackboard_mark_consumed",
    description: "Mark message ids consumed by a reader. GATED: needs OPENHACK_BLACKBOARD_MCP_ALLOW_POST=1.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        ids: { type: "array", items: { type: "string" } },
        by: { type: "string", description: "Who consumed them (a phase/agent label)." },
      },
      required: ["target", "ids", "by"],
    },
  },
] as const

async function handle(name: string, args: Record<string, any>) {
  switch (name) {
    case "blackboard_inbox": {
      if (!isPhase(args.phase)) return err(`invalid phase: ${args.phase}. one of ${PHASES.join(", ")}`)
      const msgs = Blackboard.inbox(String(args.target), args.phase, {
        includeAll: args.include_all !== false,
        onlyOpen: args.only_open !== false,
      })
      return ok(json({ target: args.target, phase: args.phase, count: msgs.length, messages: msgs }))
    }
    case "blackboard_list": {
      const store = Blackboard.load(String(args.target))
      const msgs = args.only_open ? store.messages.filter((m) => m.status === "open") : store.messages
      return ok(json({ target: store.target, count: msgs.length, messages: msgs }))
    }
    case "blackboard_post": {
      const c = checkPost()
      if (!c.allowed) return err(c.reason ?? "denied")
      if (!isPhase(args.from)) return err(`invalid from: ${args.from}`)
      if (!(args.to === "all" || isPhase(args.to))) return err(`invalid to: ${args.to}`)
      if (!isKind(args.kind)) return err(`invalid kind: ${args.kind}`)
      const text = String(args.text ?? "").trim()
      if (!text) return err("text is required")
      const m = Blackboard.post(String(args.target), {
        round: Number(args.round) || 0,
        from: args.from,
        to: args.to,
        kind: args.kind,
        text,
        refs: Array.isArray(args.refs) ? args.refs.map(String) : [],
      })
      return ok(`Posted ${m.id} (${m.from} → ${m.to} [${m.kind}]).\n\n${json(m)}`)
    }
    case "blackboard_mark_consumed": {
      const c = checkPost()
      if (!c.allowed) return err(c.reason ?? "denied")
      const ids = (args.ids ?? []).map(String)
      Blackboard.markConsumed(String(args.target), ids, String(args.by ?? "unknown"))
      return ok(`Marked ${ids.length} message(s) consumed by ${args.by}.`)
    }
    default:
      return err(`Unknown tool: ${name}`)
  }
}

runStdioMain({
  name: "openhack-blackboard-mcp",
  tools: TOOLS as any,
  handle,
  banner: () => `in ${ENGAGEMENT_DIR} · post_allowed=${!!process.env.OPENHACK_BLACKBOARD_MCP_ALLOW_POST}`,
})
