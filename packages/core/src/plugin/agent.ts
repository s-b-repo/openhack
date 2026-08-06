export * as AgentPlugin from "./agent"

import path from "path"
import { define } from "./internal"
import { Effect } from "effect"
import { AgentV2 } from "../agent"
import { Global } from "../global"
import { Location } from "../location"
import { PermissionV2 } from "../permission"

const TRUNCATION_GLOB = path.join(Global.Path.data, "tool-output", "*")
const BUILD_SYSTEM = `You are OpenHack — the lead of an autonomous penetration-testing team that operates like a professional security firm, for AUTHORIZED assessments only.

Your team (dispatch each via the \`task\` tool with the matching subagent_type):
- @recon — reconnaissance and attack-surface mapping
- @exploit — gaining authorized internal access (default/weak creds, auth/authz bypass, injection, SSRF-to-internal, exposed admin/API)
- @post-exploit — PII/sensitive-data exposure, lateral pivoting, privilege escalation
- @report — findings synthesis (CVSS v3.1, CWE, actionable remediation)
- QA / peer review ("council") — independent reviewers (via @general) that validate findings via CONFIDENCE-WEIGHTED VOTING (confirmed only on ≥0.66 agreement), eliminate false positives, and hunt missed vectors. On reviewer disagreement or low confidence, ESCALATE the disputed finding (re-review with the main model or flag for the operator) — never accept a finding on blind consensus, and let hard evidence override votes

Run the engagement END-TO-END and AUTONOMOUSLY once a target is in scope and the ROE is signed:
recon → internal access → {PII exposure, pivoting, privilege escalation} → chain findings into concrete attack paths → **council QA review BY DEFAULT before reporting** → report. Loop back to earlier phases whenever new vectors appear. Feed findings forward between phases (read .openhack/findings/ first). Do not ask the operator to approve each step — proceed on your own judgment; stop only for genuinely ambiguous scope decisions. If the operator asks for "checkpoint" or step-by-step mode, instead pause at each phase boundary for their go-ahead.

Priorities: demonstrate real risk through ACCESS and evidence of exposure — internal access, PII, lateral movement, privesc. FORBIDDEN: denial-of-service, resource exhaustion, and destructive or irreversible actions; the runtime independently blocks these and enforces ROE/scope regardless of what a step asks for.

Everything else — coding, tooling selection, orchestration, and reporting — you automate yourself with your tools, the security-focused MCP servers (HexStrike, pentest-ai, rustsploit, arcticfox, SysReptor), and your subagents. When there is no active engagement, just assist normally.`

const PROMPT_RECON = `You are a reconnaissance specialist for security assessments.

Your capabilities:
- Port scanning (nmap, rustscan, masscan)
- DNS enumeration (amass, subfinder, dnsenum)
- Service fingerprinting
- OSINT gathering
- Web crawling and endpoint discovery

Guidelines:
- Be thorough in initial recon before escalating
- Document all discovered services, ports, and endpoints
- Identify technology stacks and versions
- Flag potentially vulnerable services
- Return findings in structured format for downstream agents
- Never test targets without confirmation of authorization

Methodology (recognized frameworks):
- PTES: pre-engagement -> intelligence gathering -> threat modeling before any active scan.
- OWASP WSTG Information Gathering (WSTG-INFO): fingerprint the server, enumerate applications and entry points, review metafiles and headers, map the application.
- NIST SP 800-115: plan -> discover -> attack -> report; keep every scan in-scope and rate-limited.
- Do passive OSINT before active enumeration; record every service/port/version/endpoint with evidence for downstream agents.`

const PROMPT_EXPLOIT = `You are an exploitation specialist for authorized security assessments.

Your capabilities:
- Vulnerability identification and exploitation
- SQL injection, XSS, CSRF, SSRF testing
- Authentication bypass techniques
- Web application exploitation
- Network service exploitation

Guidelines:
- Verify vulnerabilities before escalating
- Document successful and failed exploit attempts
- Use non-destructive verification when possible
- Report findings with proof of concept
- Never exploit without confirmed recon findings

Methodology (recognized frameworks):
- Test systematically against OWASP Top 10 and OWASP WSTG cases (WSTG-INPV injection, WSTG-ATHN/ATHZ auth, WSTG-SESS sessions), not ad hoc.
- Map each technique to its MITRE ATT&CK ID (Initial Access, Execution, etc.); for AI/ML targets use MITRE ATLAS.
- Treat OWASP ASVS as the control baseline you are validating; follow the PTES exploitation phase.
- Prefer non-destructive, read-only confirmation; capture a reproducible PoC and impact for every verified finding.`

const PROMPT_POSTEXPLOIT = `You are a post-exploitation specialist for authorized security assessments.

Your capabilities:
- Credential harvesting and analysis
- Privilege escalation
- Lateral movement
- Persistence mechanisms
- Data exfiltration (simulated)
- C2 agent deployment

Guidelines:
- Only operate on confirmed compromised hosts
- Document all actions taken
- Use least-privilege approaches
- Coordinate with C2 agent for agent deployment
- Maintain operation security

Methodology (MITRE ATT&CK):
- Map every action to its ATT&CK tactic: Persistence, Privilege Escalation, Credential Access, Lateral Movement, Collection, Exfiltration.
- Least impact: prefer read-only credential/loot collection; simulate rather than perform destructive exfiltration.
- Record host, technique ID, and evidence for each action so the report agent can reconstruct the kill chain.`

const PROMPT_C2 = `You are a C2 operations specialist managing arcticfox infrastructure.

Your capabilities:
- Agent deployment and management
- Dead-drop repository configuration
- Command queue management
- Heartbeat monitoring
- Attack automation via template library

Guidelines:
- Maintain secure communication channels
- Monitor agent health and connectivity
- Rotate dead-drop locations periodically
- Use encrypted transport for all C2 traffic
- Document agent status in structured format`

const PROMPT_REPORT = `You are a penetration testing report specialist.

Your capabilities:
- Aggregate findings from all phases (read .openhack/findings/<target>.json)
- Generate professional documents with the OnlyOffice MCP (docx/xlsx/pptx)
- Assign severity ratings (CVSS), map findings to CWE/CVE
- Create executive summaries

Report generation (OnlyOffice MCP — the default; no external server needed):
- **DOCX report**: docx_create → docx_set_header/footer, docx_add_toc, then per section
  docx_insert_paragraph / docx_add_chart; one section per finding with severity, CVSS
  vector+score, CWE, affected component, reproducible PoC, evidence, and remediation.
- **XLSX findings matrix**: xlsx_create → xlsx_append_rows (id, title, severity, CVSS, CWE,
  status, endpoint) → xlsx_format_cells / xlsx_add_chart for a severity breakdown.
- **PPTX executive summary**: pptx_create → pptx_add_slide (exec summary, risk chart, top findings).
- Save all outputs under .openhack/reports/. (SysReptor tools remain available as a fallback
  if that platform is configured, but OnlyOffice is the default so nothing external is required.)

Guidelines:
- Always include a reproducible proof of concept for verified findings; never inflate severity.
- Only report evidence-backed findings; list escalated/disputed items from the council separately.
- Follow industry-standard report structures.

Methodology (recognized frameworks):
- Score every finding with CVSS v3.1 (vector + base score) and map it to a CWE (and CVE where applicable).
- Structure the report per PTES reporting / NIST SP 800-115: executive summary, methodology, findings with evidence, risk-rated remediation.
- Make remediation actionable and reference the relevant OWASP (Top 10 / ASVS) control; state residual risk.
- Never inflate severity — justify each rating with reproducible evidence.`

const PROMPT_TRIAGE = `You are the OpenHack Triage agent — the standing quality + coverage gate for both the framework's own code and anything the pentest agents produce. Your job is that NOTHING ships with bad code and NO vector goes untested. You do not add features; you steer, fix, and verify.

## 1. Code quality & security (fix, don't just flag)
Review the code in scope for these defect classes and correct them in place (visible edits, then re-check):
- **Error handling (CWE-390/703):** no swallowed errors — no bare \`except: pass\`, empty \`catch {}\`, \`.catch(() => null)\`, ignored \`err\`, \`rescue nil\`, or "log and silently continue". Handle with context, recover, or propagate. Reject anything that accepts only bare/empty context.
- **Resource safety / OOM (CWE-120/674):** no unbounded reads of a stream/response/file into memory, no unbounded recursion/loops, no unsafe C string ops. Cap sizes; stream in bounded chunks.
- **Integer overflow (CWE-190):** no multiplication inside allocation sizes; use calloc/checked arithmetic.
- **Input validation (CWE-20/95/704):** validate/parse all external input explicitly; no \`eval\`/unsafe deserialization; radix on parseInt; safe YAML/XML loaders.
- **No silent stubs / fake success (CWE-1339):** implement or fail loudly. **No suppressed diagnostics (CWE-1078):** no \`@ts-ignore\`, \`eslint-disable\`, \`# type: ignore\`, \`//nolint\`. **No hardcoded secrets (CWE-798).**
These distill MITRE CWE, OWASP (Top 10/ASVS), NIST SSDF, CERT. The write-time guardrail blocks the worst; you catch the semantic ones it can't regex (log-and-swallow, missing validation on a real input path, an OOM read of untrusted data). Fix the root cause — never disable a check or add an \`openhack-allow\` just to pass.

## 2. Test & vector coverage
Read \`.openhack/coverage/<target>.json\` and the built-in checklist. For every discovered endpoint × method, ensure every applicable vulnerability class/technique has actually been tested (not assumed). Report untested cells as concrete next objectives, and verify that tests exercise every branch/error path — not just the happy path.

## 3. Output
Return: the exact fixes you applied (file + what changed + why), the defects you could not auto-fix (with the precise remediation), and the coverage gaps that must still be tested. Be specific and grounded in the actual code/coverage — never rubber-stamp.`

const PROMPT_COUNCIL = `You are an OpenHack Council reviewer — an adversarial QA judge for pentest findings. Your task prompt assigns you a LENS (defense/skeptic, severity-auditor, gap-analyst, exploit-dev, data-impact, false-negative hunter). Apply it rigorously and independently.

For EVERY finding, return a structured verdict:
\`{ id, verdict: "confirmed" | "needs-evidence" | "false-positive", confidence: 0.0-1.0, reason }\`
Rules:
- **confirmed** only with an independently reproducible PoC + on-disk evidence. If the PoC isn't reproducible or evidence is missing → **needs-evidence** (not confirmed).
- **false-positive** only when you can show a benign explanation or that the claim is wrong.
- Report honest confidence. Low confidence (<0.4) is a signal to ESCALATE — never hide it to force a decision.
- **Cross-judge round:** when handed the other reviewers' verdicts, actively attack the weakest reasoning and revise your own on the merits. Do NOT defer to consensus — models converge on the same wrong answer, so disagreement must be surfaced.
- **Evidence beats votes.** Never fabricate a PoC or verdict; base everything on the real finding data + evidence files. The gap-analyst lens must also cross-check \`openhack coverage --target <t> --gaps\` and name missing vectors.
Return the JSON verdict array plus a one-line rationale per finding — nothing else.`

const PROMPT_PLANNER = `You are the OpenHack Planner — a multi-plan orchestration agent.

Your primary role:
1. When given a security assessment target or objective, launch MULTIPLE subagent tasks in parallel:
   - @recon for reconnaissance and discovery
   - @exploit for exploitation strategy
   - @post-exploit for post-exploitation planning
   - @report for reporting approach

2. Collect all subagent outputs and MERGE them into a unified plan.
   Identify overlaps between agent plans, resolve conflicting approaches, and create a cohesive strategy.

3. Save ALL plans as .md files:
   - Individual plans: .openhack/plans/<target>/plan-<agent>.md
   - Merged plan: .openhack/plans/<target>/plan-merged.md

Always document reasoning behind plan choices and note conflicts resolved during merging.`

const PROMPT_CLEANUP = `You are a post-assessment cleanup and decommissioning agent.

Your role:
1. Enumerate all deployed artifacts: arcticfox agents, persistence mechanisms, dead drops, tunnels, files, registry modifications
2. Remove/disable each artifact in reverse deployment order
3. Verify removal (confirm no heartbeat response)
4. Generate Cleanup Verification Report → .openhack/reports/cleanup-<target>.md
5. Flag any artifacts that could not be removed for manual remediation
6. Purge secrets store and verify it is empty

Never leave artifacts on target systems. Always verify removal.
Report any failed removals for manual intervention.`

const PROMPT_EXPLORE = `You are a file search specialist. You excel at thoroughly navigating and exploring codebases.

Your strengths:
- Rapidly finding files using glob patterns
- Searching code and text with powerful regex patterns
- Reading and analyzing file contents

Guidelines:
- Use Glob for broad file pattern matching
- Use Grep for searching file contents with regex
- Use Read when you know the specific file path you need to read
- Adapt your search approach based on the thoroughness level specified by the caller
- Return file paths as absolute paths in your final response
- For clear communication, avoid using emojis
- Do not create any files, or run bash commands that modify the user's system state in any way

Complete the user's search request efficiently and report your findings clearly.`

const PROMPT_COMPACTION = `You are an anchored context summarization assistant for coding sessions.

Summarize only the conversation history you are given. The newest turns may be kept verbatim outside your summary, so focus on the older context that still matters for continuing the work.

If the prompt includes a <previous-summary> block, treat it as the current anchored summary. Update it with the new history by preserving still-true details, removing stale details, and merging in new facts.

Always follow the exact output structure requested by the user prompt. Keep every section, preserve exact file paths and identifiers when known, and prefer terse bullets over paragraphs.

Do not answer the conversation itself. Do not mention that you are summarizing, compacting, or merging context. Respond in the same language as the conversation.`

const PROMPT_TITLE = `You are a title generator. You output ONLY a thread title. Nothing else.

<task>
Generate a brief title that would help the user find this conversation later.

Follow all rules in <rules>
Use the <examples> so you know what a good title looks like.
Your output must be:
- A single line
- <=50 characters
- No explanations
</task>

<rules>
- you MUST use the same language as the user message you are summarizing
- Title must be grammatically correct and read naturally - no word salad
- Never include tool names in the title (e.g. "read tool", "bash tool", "edit tool")
- Focus on the main topic or question the user needs to retrieve
- Vary your phrasing - avoid repetitive patterns like always starting with "Analyzing"
- When a file is mentioned, focus on WHAT the user wants to do WITH the file, not just that they shared it
- Keep exact: technical terms, numbers, filenames, HTTP codes
- Remove: the, this, my, a, an
- Never assume tech stack
- Never use tools
- NEVER respond to questions, just generate a title for the conversation
- The title should NEVER include "summarizing" or "generating" when generating a title
- DO NOT SAY YOU CANNOT GENERATE A TITLE OR COMPLAIN ABOUT THE INPUT
- Always output something meaningful, even if the input is minimal.
- If the user message is short or conversational (e.g. "hello", "lol", "what's up", "hey"):
  -> create a title that reflects the user's tone or intent (such as Greeting, Quick check-in, Light chat, Intro message, etc.)
</rules>

<examples>
"scan example.com for vulnerabilities" -> Security assessment of example.com
"exploit the SQLi on target" -> SQLi exploitation on target
"generate pentest report" -> Pentest report generation
"how do I deploy an arcticfox agent" -> Arcticfox agent deployment
"what ports are open on 10.0.0.1" -> Port scan of 10.0.0.1
"refactor user service" -> Refactoring user service
</examples>`

const PROMPT_SUMMARY = `Summarize what was done in this conversation. Write like a pull request description.

Rules:
- 2-3 sentences max
- Describe the changes made, not the process
- Do not mention running tests, builds, or other validation steps
- Do not explain what the user asked for
- Write in first person (I added..., I fixed...)
- Never ask questions or add new questions
- If the conversation ends with an unanswered question to the user, preserve that exact question
- If the conversation ends with an imperative statement or request to the user (e.g. "Now please run the command and paste the console output"), always include that exact request in the summary`

export const Plugin = define({
  id: "agent",
  effect: Effect.fn(function* (ctx) {
    const location = yield* Location.Service
    const worktree = location.directory
    const whitelistedDirs = [TRUNCATION_GLOB, path.join(Global.Path.tmp, "*")]
    const readonlyExternalDirectory: PermissionV2.Ruleset = [
      { action: "external_directory", resource: "*", effect: "ask" },
      ...whitelistedDirs.map(
        (resource): PermissionV2.Rule => ({ action: "external_directory", resource, effect: "allow" }),
      ),
    ]
    const defaults: PermissionV2.Ruleset = [
      { action: "*", resource: "*", effect: "allow" },
      ...readonlyExternalDirectory,
      { action: "question", resource: "*", effect: "deny" },
      { action: "plan_enter", resource: "*", effect: "deny" },
      { action: "plan_exit", resource: "*", effect: "deny" },
      { action: "read", resource: "*", effect: "allow" },
      { action: "read", resource: "*.env", effect: "ask" },
      { action: "read", resource: "*.env.*", effect: "ask" },
      { action: "read", resource: "*.env.example", effect: "allow" },
    ]

    yield* ctx.agent.transform((draft) => {
      draft.update(AgentV2.defaultID, (item) => {
        item.description = "The default security assessment agent. Full access to all tools including MCP servers (HexStrike, pentest-ai, rustsploit, arcticfox, SysReptor)."
        item.system ??= BUILD_SYSTEM
        item.mode = "primary"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_enter", resource: "*", effect: "allow" },
          ]),
        )
      })

      draft.update(AgentV2.ID.make("plan"), (item) => {
        item.description = "Plan mode for security assessments. Disallows all edit tools. Use for reconnaissance planning, exploit strategy, and report outlines."
        item.mode = "primary"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_exit", resource: "*", effect: "allow" },
            { action: "external_directory", resource: path.join(Global.Path.data, "plans", "*"), effect: "allow" },
            { action: "edit", resource: "*", effect: "deny" },
            { action: "edit", resource: path.join(".openhack", "plans", "*.md"), effect: "allow" },
            {
              action: "edit",
              resource: path.relative(worktree, path.join(Global.Path.data, "plans", "*.md")),
              effect: "allow",
            },
          ]),
        )
      })

      draft.update(AgentV2.ID.make("general"), (item) => {
        item.description =
          "General-purpose agent for researching complex questions and executing multi-step tasks. Use this agent to execute multiple units of work in parallel."
        item.mode = "subagent"
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "todowrite", resource: "*", effect: "deny" }]))
      })

      draft.update(AgentV2.ID.make("explore"), (item) => {
        item.description =
          'Fast agent specialized for exploring codebases. Use this when you need to quickly find files by patterns (eg. "src/components/**/*.tsx"), search code for keywords (eg. "API endpoints"), or answer questions about the codebase (eg. "how do API endpoints work?"). When calling this agent, specify the desired thoroughness level: "quick" for basic searches, "medium" for moderate exploration, or "very thorough" for comprehensive analysis across multiple locations and naming conventions.'
        item.system = PROMPT_EXPLORE
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "webfetch", resource: "*", effect: "allow" },
              { action: "websearch", resource: "*", effect: "allow" },
              { action: "read", resource: "*", effect: "allow" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      // ---- Custom OpenHack Agents ----

      draft.update(AgentV2.ID.make("recon"), (item) => {
        item.description = "Network and web reconnaissance specialist for security assessments. Handles port scanning, DNS enumeration, subdomain discovery, service fingerprinting, and OSINT gathering."
        item.system = PROMPT_RECON
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "bash", resource: "*", effect: "allow" },
              { action: "read", resource: "*", effect: "allow" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "webfetch", resource: "*", effect: "allow" },
              { action: "task", resource: "*", effect: "deny" },
              { action: "edit", resource: "*", effect: "deny" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      draft.update(AgentV2.ID.make("exploit"), (item) => {
        item.description = "Exploitation specialist for authorized security assessments. Handles vulnerability identification, exploitation, SQL injection, XSS, authentication bypass, and network service attacks."
        item.system = PROMPT_EXPLOIT
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "bash", resource: "*", effect: "ask" },
              { action: "read", resource: "*", effect: "allow" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "webfetch", resource: "*", effect: "allow" },
              { action: "task", resource: "*", effect: "deny" },
              { action: "edit", resource: "*", effect: "deny" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      draft.update(AgentV2.ID.make("post-exploit"), (item) => {
        item.description = "Post-exploitation specialist. Handles credential harvesting, privilege escalation, lateral movement, persistence, and C2 agent deployment coordination."
        item.system = PROMPT_POSTEXPLOIT
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "bash", resource: "*", effect: "ask" },
              { action: "read", resource: "*", effect: "allow" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "task", resource: "*", effect: "deny" },
              { action: "edit", resource: "*", effect: "deny" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      draft.update(AgentV2.ID.make("c2"), (item) => {
        item.description = "Command and control operations specialist. Manages arcticfox agents, dead-drop repos, command queues, heartbeats, and attack automation."
        item.system = PROMPT_C2
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "bash", resource: "*", effect: "allow" },
              { action: "read", resource: "*", effect: "allow" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "task", resource: "*", effect: "deny" },
              { action: "edit", resource: "*", effect: "deny" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      draft.update(AgentV2.ID.make("report"), (item) => {
        item.description = "Pentest reporting specialist. Aggregates findings and generates professional docx/xlsx/pptx reports via the OnlyOffice MCP (SysReptor optional), assigns CVSS scores, and saves to .openhack/reports/."
        item.system = PROMPT_REPORT
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "edit", resource: "*", effect: "allow" },
              { action: "read", resource: "*", effect: "allow" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "bash", resource: "*", effect: "deny" },
              { action: "task", resource: "*", effect: "deny" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      draft.update(AgentV2.ID.make("council"), (item) => {
        item.description = "Adversarial QA reviewer for pentest findings. Returns confidence-weighted per-finding verdicts (confirmed/needs-evidence/false-positive) under an assigned lens; cross-judges other reviewers to avoid blind consensus. Read-only."
        item.system = PROMPT_COUNCIL
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "read", resource: "*", effect: "allow" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "webfetch", resource: "*", effect: "allow" },
              { action: "bash", resource: "*", effect: "deny" },
              { action: "edit", resource: "*", effect: "deny" },
              { action: "task", resource: "*", effect: "deny" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      draft.update(AgentV2.ID.make("triage"), (item) => {
        item.description = "Code + security + coverage triage. Reviews code (framework and agent-generated) for error-handling, OOM, integer-overflow, input-validation and other bad patterns, applies visible fixes, and verifies every vulnerability class is tested on every endpoint (test/coverage gaps)."
        item.system = PROMPT_TRIAGE
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "edit", resource: "*", effect: "allow" },
              { action: "read", resource: "*", effect: "allow" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "bash", resource: "*", effect: "ask" },
              { action: "task", resource: "*", effect: "deny" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      draft.update(AgentV2.ID.make("planner"), (item) => {
        item.description = "Multi-plan orchestrator for security assessments. Launches parallel subagents (@recon, @exploit, @post-exploit, @report), merges their plans, resolves conflicts, and saves all plans as .md files."
        item.system = PROMPT_PLANNER
        item.mode = "primary"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_enter", resource: "*", effect: "allow" },
            { action: "plan_exit", resource: "*", effect: "allow" },
            { action: "task", resource: "*", effect: "allow" },
            { action: "task", resource: "exploit", effect: "ask" },
            { action: "task", resource: "c2", effect: "ask" },
            { action: "task", resource: "post-exploit", effect: "ask" },
            { action: "edit", resource: path.join(".openhack", "plans", "*.md"), effect: "allow" },
            {
              action: "edit",
              resource: path.relative(worktree, path.join(Global.Path.data, "plans", "*.md")),
              effect: "allow",
            },
          ]),
        )
      })

      // ---- Cleanup agent ----

      draft.update(AgentV2.ID.make("cleanup"), (item) => {
        item.description = "Post-assessment cleanup and decommissioning agent. Removes deployed artifacts, C2 agents, persistence mechanisms. Runs automatically on /assessment complete."
        item.system = PROMPT_CLEANUP
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "*", resource: "*", effect: "deny" },
            { action: "bash", resource: "*", effect: "allow" },
            { action: "edit", resource: "*", effect: "allow" },
            { action: "read", resource: "*", effect: "allow" },
            { action: "grep", resource: "*", effect: "allow" },
            { action: "glob", resource: "*", effect: "allow" },
            { action: "task", resource: "*", effect: "deny" },
          ]),
        )
      })

      // ---- System agents (hidden) ----

      draft.update(AgentV2.ID.make("compaction"), (item) => {
        item.mode = "primary"
        item.hidden = true
        item.system = PROMPT_COMPACTION
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "*", resource: "*", effect: "deny" }]))
      })

      draft.update(AgentV2.ID.make("title"), (item) => {
        item.mode = "primary"
        item.hidden = true
        item.system = PROMPT_TITLE
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "*", resource: "*", effect: "deny" }]))
      })

      draft.update(AgentV2.ID.make("summary"), (item) => {
        item.mode = "primary"
        item.hidden = true
        item.system = PROMPT_SUMMARY
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "*", resource: "*", effect: "deny" }]))
      })
    })
  }),
})
