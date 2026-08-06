import * as fs from "node:fs"
import { Scope } from "../scope"
import { ROE } from "../roe"
import { Secrets } from "../secrets"
import { Audit } from "../audit"
import { MiddlewareChain } from "../middleware"
import { MOERouter } from "../moe-router"
import { Orchestrator } from "../orchestrator"
import { Codeguard } from "../codeguard"
import { ShellTimeout } from "../shell-timeout"
import { ConfigStore } from "../config-store"
import { McpRecommend } from "../mcp-recommend"
import { evaluateToolCall } from "./enforcement"

// MoE experts route to these agent types only — the subagent names actually
// defined in packages/core/src/plugin/agent.ts. (MoE's "defense"/"c2" targets
// have no agent definition, so routing to them would break task dispatch.)
const ROUTABLE_AGENTS = new Set(["recon", "exploit", "post-exploit", "report"])
const MCP_PREFIXES = new Set(["hexstrike", "ptai", "pentestai", "rustsploit", "arcticfox", "sysreptor"])
// Tools whose written content the code-quality guardrail inspects.
const FILE_TOOLS = new Set(["write", "edit", "apply_patch"])

// The guided iteration ("hru") loop: the agent is expected to keep correcting
// toward the goal + quality bar rather than working around a block.
const HRU_LOOP_GUIDANCE = `## Guided iteration
Work in a goal-directed loop: when a write is blocked or a check fails, read the guidance, fix the root cause, and retry until BOTH the objective and the quality bar are met. Do not disable checks, work around the guardrail, or stop at the first attempt — converge on a correct, robust solution.`

// Per-agent objective focus, injected into the specialist's system prompt now that
// the plugin can resolve the session's agent. Prioritizes real, authorized pentest
// objectives (access, PII, pivot) while never permitting destructive/DoS actions —
// the safety harness and ROE/scope still block those independently.
const OBJECTIVE_HINTS: Record<string, string> = {
  recon:
    "## Objective focus\nYou are the recon specialist. Thoroughly map the authorized attack surface (hosts, services, versions, endpoints, tech) so the access and pivot steps can build on it. Be complete — do not stop short.",
  exploit:
    "## Objective focus\nYou are the exploitation specialist. Prioritize gaining authorized, in-scope internal access: weak/default creds, auth/authz bypass, injection, SSRF-to-internal, exposed admin/API surfaces. Prove access non-destructively and chain it forward. Never perform DoS or destructive/irreversible actions.",
  "post-exploit":
    "## Objective focus\nYou are the post-exploitation specialist. Prioritize PII/sensitive-data exposure, lateral pivoting, and privilege escalation. Sample and evidence exposure (never mass-exfiltrate), keep every action reversible, and never damage or disrupt systems.",
}

// The agent cannot type slash commands (those expand what the operator types),
// but it can perform every workflow itself with its tools. Injected during an
// active engagement so automode/assessment sessions run the flows proactively.
const WORKFLOWS_GUIDANCE = `## OpenHack workflows you can run yourself
The **entire OpenHack surface is available from the shell** (your \`bash\` tool) — use it proactively:
- **CLI features**: \`openhack config|checklist|coverage|preset|mcp-recommend|scope|roe|findings|finding-verify|moe|orch\`. E.g. check coverage gaps (\`openhack coverage --target <t> --gaps\`), expand a tool preset (\`openhack preset --name nmap-quick --target <t>\`), record/verify findings.
- **Macros from the shell**: \`openhack cmd --name <macro> [--args "…"]\` runs any slash-command macro; \`openhack council [--target <t>]\` and \`openhack triage [--path …]\` are direct wrappers. (\`openhack cmd --list\` shows them.)
- **Auto mode** (full team by default — plan → parallel multi-instance subagents → MoE → council every phase → chaining → report): \`openhack automode --target <t> --loop\` (flags: --instances/--plan/--council/--parallel/--coverage-target).
You can also drive these directly with the \`task\` tool: dispatch specialized objectives to specialists (recon-depth→recon, internal-access→exploit, pii/pivot/privesc→post-exploit), feed findings forward, fan out council reviewers (subagent_type: council) to validate + find missing vectors, and record every confirmed finding under .openhack/findings/ with evidence — chaining them into end-to-end attack paths.
ROE/scope are enforced automatically — stay in scope. Prioritize authorized internal access / PII exposure / pivoting / privesc; never perform DoS or destructive actions.`

// Compact identity+doctrine re-injected into the compaction context so the model
// keeps its role and rules after long-session compaction (DeepSeek drift mitigation).
const ANCHOR = `## OpenHack anchor (retain across compaction)
You are OpenHack, the lead of an autonomous, authorized penetration-testing team. Keep pursuing the engagement objective — recon → internal access → PII/pivot/privesc → chain findings into attack paths → council QA review → report — dispatching specialist subagents via the task tool and feeding findings forward. Prioritize demonstrating impact through ACCESS and evidence; NEVER perform DoS or destructive/irreversible actions (the runtime blocks these and enforces ROE/scope regardless). Do not lose this role or these rules.`

// Structural shapes of the OpenCode plugin hooks we use. Declared locally so the
// openhack package stays free of a build-time dependency on @opencode-ai/plugin;
// the object returned by OpenHackPlugin is checked against the real Hooks type at
// its registration site in packages/opencode/src/plugin/index.ts.
interface BeforeInput {
  tool: string
  sessionID: string
  callID: string
}
interface AfterInput extends BeforeInput {
  args: any
}

const AGENT = "assessment"

// ─── hot-path caches ──────────────────────────────────────────────────────
// These three helpers are called from every tool.execute.before / .after hook,
// on every tool call — including every MCP tool call during an engagement.
// The raw impls all did sync disk IO or a full JSON parse on each invocation;
// the caches below make each of them O(1) inside a short window (~2 s), refreshed
// whenever the underlying file's mtime changes so live edits still take effect.
const HOT_TTL_MS = 2_000
let cachedOpenhackEnabled: { at: number; value: boolean } | null = null
let cachedCodeguardEnabled: { at: number; mtimeMs: number; value: boolean } | null = null
const CODEGUARD_FILE = ".openhack/openhack.jsonc"

/** True when this project opts into OpenHack (has a `.openhack/` directory). */
function openhackEnabled(): boolean {
  const now = Date.now()
  if (cachedOpenhackEnabled && now - cachedOpenhackEnabled.at < HOT_TTL_MS) return cachedOpenhackEnabled.value
  let value = false
  try { value = fs.existsSync(".openhack") } catch {}
  cachedOpenhackEnabled = { at: now, value }
  return value
}

/** Whether an engagement is actively configured (scope enabled or a signed ROE). */
function engagementActive(): boolean {
  try {
    if (Scope.load().enabled) return true
    const roe = ROE.load()
    return !!roe && roe.status === "signed"
  } catch {
    return false
  }
}

/** Whether the code-quality guardrail is enabled (default on; disable via config). */
function codeguardEnabled(): boolean {
  const now = Date.now()
  let mtimeMs = 0
  try { mtimeMs = fs.statSync(CODEGUARD_FILE).mtimeMs } catch {}
  if (cachedCodeguardEnabled && now - cachedCodeguardEnabled.at < HOT_TTL_MS && cachedCodeguardEnabled.mtimeMs === mtimeMs) {
    return cachedCodeguardEnabled.value
  }
  let value = true
  try {
    const cfg = JSON.parse(fs.readFileSync(CODEGUARD_FILE, "utf-8"))
    value = cfg.codeguard?.enabled !== false
  } catch {}
  cachedCodeguardEnabled = { at: now, mtimeMs, value }
  return value
}

/**
 * The OpenHack runtime plugin. When a `.openhack/` directory is present it wires
 * the security core into the real session: every tool call is enforced against
 * the safety harness / scope / ROE (blocking with a thrown error), tool output is
 * scrubbed of secrets and scanned for findings, and the engagement scope + ROE
 * status are injected into the system prompt. Absent `.openhack/`, it registers
 * no hooks so vanilla OpenCode behavior is preserved.
 */
export async function OpenHackPlugin(_input: any) {
  if (!openhackEnabled()) return {}

  // Warn-level code-quality notes stashed in the before-hook and surfaced on the
  // matching tool result in the after-hook (keyed by callID).
  const pendingWarnings = new Map<string, string>()

  // Real agent name per session, captured from chat.message (which fires before
  // system.transform and the tool hooks, and — unlike them — carries the agent).
  // Lets audit/findings record the actual specialist and lets system.transform
  // scope guidance per agent, instead of the old fixed "assessment" placeholder.
  const sessionAgents = new Map<string, string>()
  function agentFor(sessionID: string | undefined): string {
    return (sessionID && sessionAgents.get(sessionID)) || AGENT
  }

  // MCP servers already suggested this run (keyed "sessionID:server") — suggest each
  // relevant opt-in MCP at most once so recommendations inform without spamming.
  const suggestedMcp = new Set<string>()
  function mcpSuggestion(sessionID: string | undefined, text: string): string | undefined {
    try {
      const enabled = new Set<string>()
      const mcp = ConfigStore.get("mcp") as Record<string, any> | undefined
      if (mcp) for (const [name, v] of Object.entries(mcp)) if (v && v.enabled === true) enabled.add(name)
      const hits = McpRecommend.recommend(text, { exclude: enabled }).filter((h) => !suggestedMcp.has(`${sessionID}:${h.server}`))
      if (!hits.length) return undefined
      const first = hits[0]
      suggestedMcp.add(`${sessionID}:${first.server}`)
      return McpRecommend.format([first])
    } catch {
      return undefined
    }
  }

  let auditedSession: string | null = null
  function ensureAudit(sessionID: string) {
    try {
      if (auditedSession === sessionID) return
      if (Audit.getActiveSession() && Audit.getActiveSession() !== sessionID) Audit.sessionEnd()
      Audit.sessionStart(sessionID)
      auditedSession = sessionID
    } catch {}
  }

  return {
    "chat.message": async (input: { sessionID: string; agent?: string }, _output: any) => {
      if (input.agent) sessionAgents.set(input.sessionID, input.agent)
    },

    "tool.execute.before": async (input: BeforeInput, output: { args: any }) => {
      const args = (output.args ?? {}) as Record<string, unknown>

      // Smart command timeout: bound short-lived commands (curl/dig/one-shot fetches)
      // so a hung request can't stall a run, but never auto-kill long scanners
      // (nmap/nuclei/ffuf/sqlmap/…). An explicit `timeout` always wins.
      if (input.tool === "bash" && args["timeout"] == null && typeof args["command"] === "string") {
        try {
          const policy = ConfigStore.get("shell.timeout_policy") as ShellTimeout.Policy | undefined
          const { ms } = ShellTimeout.classify(String(args["command"]), 2 * 60 * 1000, policy)
          args["timeout"] = ms
        } catch {}
      }

      const decision = evaluateToolCall(input.tool, args)
      if (!decision.blocked) {
        // MoE routing: refine a generic subagent dispatch to the specialist the
        // prompt best matches during an engagement. Never overrides an explicit
        // choice and only routes to agents that exist — refines, never breaks.
        if (input.tool === "task" && engagementActive()) {
          try {
            const st = String(args["subagent_type"] ?? "").toLowerCase()
            if (!st || st === "general" || st === "build") {
              const { expert } = MOERouter.route(String(args["prompt"] ?? args["description"] ?? ""))
              if (ROUTABLE_AGENTS.has(expert.targetAgent)) args["subagent_type"] = expert.targetAgent
            }
          } catch {}
        }

        // Code-quality guardrail: inspect the code the agent is about to write and
        // hard-block high-confidence anti-patterns with actionable guidance so the
        // agent fixes and retries (the guided "hru" loop). Softer issues are stashed
        // as non-blocking notes surfaced on the tool result.
        if (codeguardEnabled() && FILE_TOOLS.has(input.tool)) {
          const extracted = Codeguard.extractContent(input.tool, args)
          if (extracted) {
            const violations = Codeguard.inspect(extracted.filePath, extracted.text)
            const blocking = violations.filter((v) => v.severity === "block")
            if (blocking.length) {
              ensureAudit(input.sessionID)
              try {
                Audit.toolCall(input.tool, { filePath: extracted.filePath }, 0, agentFor(input.sessionID), `CODE-QUALITY BLOCK: ${blocking.map((v) => v.ruleId).join(", ")}`)
              } catch {}
              throw new Error(Codeguard.formatBlock(extracted.filePath, blocking))
            }
            const warns = violations.filter((v) => v.severity === "warn")
            if (warns.length) pendingWarnings.set(input.callID, Codeguard.formatWarnings(extracted.filePath, warns))
          }
        }
        return
      }

      ensureAudit(input.sessionID)
      try {
        if (decision.kind === "safety")
          Audit.safetyBlock(String(args["command"] ?? ""), decision.reason ?? "blocked", agentFor(input.sessionID))
        else if (decision.kind === "scope")
          Audit.scopeBlock(JSON.stringify(args).slice(0, 200), decision.reason ?? "blocked", agentFor(input.sessionID))
      } catch {}

      const label =
        decision.kind === "safety"
          ? "SAFETY HARNESS BLOCKED"
          : decision.kind === "scope"
            ? "SCOPE BLOCKED"
            : "ROE VIOLATION"
      throw new Error(`${label}: ${decision.reason ?? "blocked by OpenHack policy"}`)
    },

    "tool.execute.after": async (input: AfterInput, output: { title: string; output: string; metadata: any }) => {
      if (typeof output.output === "string") {
        try {
          output.output = Secrets.sanitizeOutput(output.output)
        } catch {}
      }
      // Surface any non-blocking code-quality notes stashed for this tool call.
      const note = pendingWarnings.get(input.callID)
      if (note) {
        pendingWarnings.delete(input.callID)
        if (typeof output.output === "string") output.output = `${output.output}\n\n${note}`
      }
      if (engagementActive() && typeof output.output === "string") {
        try {
          const target = Scope.load().targets[0] ?? "assessment"
          ensureAudit(input.sessionID)
          MiddlewareChain.autoSaveFindingIfDetected(output.output, target, agentFor(input.sessionID), input.sessionID)
        } catch {}
        // Recommend an opt-in MCP when the work matches its capability (once per server).
        const suggestion = mcpSuggestion(input.sessionID, output.output.slice(0, 2000))
        if (suggestion) output.output = `${output.output}\n\n${suggestion}`
      }
      try {
        ensureAudit(input.sessionID)
        Audit.toolCall(
          input.tool,
          (input.args ?? {}) as Record<string, unknown>,
          0,
          agentFor(input.sessionID),
          typeof output.output === "string" ? output.output.slice(0, 200) : undefined,
        )
      } catch {}
      // Orchestrator learning: record MCP pentest-tool outcomes so its routing
      // scores (.openhack/tool-scores.json) adapt to what actually works.
      try {
        const prefix = input.tool.split("_")[0]
        if (MCP_PREFIXES.has(prefix)) {
          const text = typeof output.output === "string" ? output.output : ""
          const success = !/\b(error|failed|not found|refused|timed out|unreachable)\b/i.test(text)
          Orchestrator.recordResult(prefix, input.tool.slice(prefix.length + 1) || input.tool, success, 0)
        }
      } catch {}
      // Tool-call repair nudge: help DeepSeek self-correct a failed/malformed call
      // instead of looping on it. One concise line, appended at most once.
      try {
        if (typeof output.output === "string" && !output.output.includes("[openhack-repair]")) {
          if (/\b(invalid arguments?|unknown tool|could not parse|malformed|no such (?:file|tool)|Traceback|Exception:|Error:)\b/i.test(output.output)) {
            output.output +=
              "\n\n[openhack-repair] This tool call did not succeed. Diagnose the cause (wrong arguments, wrong tool, or bad path), fix it, and retry a corrected call — do not repeat the same failing call."
          }
        }
      } catch {}
    },

    "experimental.chat.system.transform": async (input: { sessionID?: string; model: any }, output: { system: string[] }) => {
      try {
        // Emit STABLE blocks first and DYNAMIC blocks (scope/ROE, which change as the
        // engagement progresses) last, so a stable prompt prefix maximizes DeepSeek's
        // automatic prefix-cache hits across turns.
        const stable: string[] = []
        const dynamic: string[] = []
        if (codeguardEnabled()) {
          stable.push(Codeguard.SYSTEM_GUIDANCE)
          stable.push(HRU_LOOP_GUIDANCE)
        }
        if (engagementActive()) stable.push(WORKFLOWS_GUIDANCE)
        const hint = OBJECTIVE_HINTS[agentFor(input.sessionID)]
        if (hint) stable.push(hint)
        const scopePrompt = Scope.generateScopePrompt(Scope.load())
        if (scopePrompt.trim()) dynamic.push(scopePrompt.trim())
        const roe = ROE.load()
        if (roe)
          dynamic.push(
            `## Rules of Engagement\n${ROE.getStatusString(roe)}\n\n` +
              "Every tool call is enforced against this ROE and the engagement scope. " +
              "Out-of-scope targets, unauthorized tools, and destructive commands are blocked automatically.",
          )
        const parts = [...stable, ...dynamic]
        if (parts.length) output.system.push(parts.join("\n\n"))
      } catch {}
    },

    // DeepSeek tool-call drift is worst at higher temperatures — keep tool-heavy
    // specialists deterministic and give review/brainstorm roles a little more room.
    // No-op for non-DeepSeek providers.
    "chat.params": async (
      input: { sessionID: string; agent: string; model: any },
      output: { temperature: number; topP: number; topK: number; maxOutputTokens: number | undefined; options: Record<string, any> },
    ) => {
      try {
        // Robust to the model object's exact shape (Provider.Model uses api.id, not modelID).
        const isDeepseek = JSON.stringify(input.model ?? {}).toLowerCase().includes("deepseek")
        if (!isDeepseek) return
        const brainstorm = new Set(["general", "plan", "planner"])
        output.temperature = brainstorm.has(input.agent) ? 0.5 : 0.2
      } catch {}
    },

    // Re-anchor identity + doctrine into the compaction context so DeepSeek retains
    // its role and rules after compaction — exactly when long-context drift bites.
    "experimental.session.compacting": async (_input: { sessionID: string }, output: { context: string[]; prompt?: string }) => {
      try {
        if (engagementActive()) output.context.push(ANCHOR)
      } catch {}
    },

    dispose: async () => {
      try {
        Audit.sessionEnd()
      } catch {}
    },
  }
}
