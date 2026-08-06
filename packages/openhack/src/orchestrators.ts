import { Automode } from "./automode"

/**
 * Pentest objective orchestrators. Each dispatches a specialized, goal-directed
 * instruction to the specialist subagent best suited to it, so an assessment is
 * driven toward the objectives that actually demonstrate risk — internal access,
 * sensitive-data exposure, pivoting, privilege escalation — rather than stalling
 * out of timidity.
 *
 * The instructions deliberately remove *hesitation* about legitimate, authorized,
 * in-scope testing while keeping hard prohibitions on anything destructive. They
 * do NOT grant new permissions: the runtime safety harness (destructive-command
 * blocking) and ROE/scope enforcement still apply to every tool call regardless
 * of what an objective asks for.
 */
export namespace Orchestrators {
  export interface Orchestrator {
    id: string
    name: string
    /**
     * Which specialist subagent runs it. Widened from the original 5-value
     * union to accept every agent defined in `.openhack/agents/*.md` — the
     * loop-graph hybrid promotes osint / defense / c2 / cleanup to first-class
     * objectives alongside the original recon / exploit / post-exploit /
     * report / general set.
     */
    subagentType: string
    /**
     * Optional slash-command macro to dispatch instead of the agent path.
     * When set, `runInstance` fires `run --command <name>` so the
     * `.opencode/command/<name>.md` protocol is the single source of truth.
     * Used for orchestrators that reuse an existing macro (council / triage
     * / cleanup) — the doctrine still lives in `withDoctrine()` on the
     * `instruction` field, but macro dispatch renders the actual protocol.
     */
    command?: string
    /** 1 = earliest; lower priority numbers run first. */
    priority: number
    objective: string
    instruction: (target: string) => string
  }

  /**
   * Shared rules of engagement embedded in every objective. This is the
   * "prioritize pentesting, but never destructive" doctrine: pursue access and
   * evidence exposure aggressively within authorization; never impact availability.
   */
  export const DOCTRINE = `Rules of engagement for this objective:
- Authorized, in-scope work only — everything is gated by the active ROE and engagement scope; the runtime independently blocks out-of-scope targets and destructive commands.
- Prioritize impact through ACCESS, not disruption. Pursue the objective thoroughly and do not skip legitimate authorized testing out of caution.
- FORBIDDEN: denial-of-service, resource exhaustion, data destruction, or any irreversible or availability-impacting action. Demonstrate risk by gaining access and evidencing exposure — never by breaking things.
- Build on prior work: first read the current findings in .openhack/findings/ and continue from them; do not repeat completed steps.
- Record every finding with evidence, and note chaining opportunities (how it combines with other findings into a higher-impact attack path) for downstream orchestrators.`

  function withDoctrine(target: string, body: string): string {
    return `Target: ${target}\n\n${body}\n\n${DOCTRINE}`
  }

  export const ORCHESTRATORS: Orchestrator[] = [
    {
      id: "recon-depth",
      name: "Recon depth",
      subagentType: "recon",
      priority: 1,
      objective: "Thorough authorized attack-surface mapping",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: map the full authorized attack surface of ${t}.
- Enumerate hosts, open ports, services and exact versions, virtual hosts, and web endpoints/APIs.
- Fingerprint technology stacks and flag anything outdated, misconfigured, or exposed that is unlikely to be intended.
- Produce a structured inventory the access and pivot orchestrators can act on.`,
        ),
    },
    {
      id: "internal-access",
      name: "Internal access",
      subagentType: "exploit",
      priority: 2,
      objective: "Gain an authorized foothold / internal access",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: obtain a foothold and reach internal systems on ${t}.
- Test exposed services and web apps for default/weak credentials, authentication and authorization bypass, injection (SQL/command/template), SSRF that reaches internal services, and exposed admin/management/API surfaces.
- Confirm access with a minimal, non-destructive proof (e.g. read a benign internal resource) and capture a reproducible PoC.
- Report each confirmed access path with its impact and how it could be chained further.`,
        ),
    },
    {
      id: "pii-exposure",
      name: "PII / sensitive-data exposure",
      subagentType: "post-exploit",
      priority: 3,
      objective: "Detect exposed PII and sensitive data",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: identify exposed sensitive data reachable on ${t}.
- Look for open databases/backups/object storage, exposed .git/.env/config, directory listings, verbose errors, and API responses that leak PII or secrets.
- SAMPLE and evidence the exposure (a redacted snippet plus counts) — do NOT mass-download or exfiltrate data; demonstrate exposure, not extraction.
- Classify the data (PII, credentials, financial, health) and rate the exposure severity.`,
        ),
    },
    {
      id: "pivoting",
      name: "Pivoting / lateral movement",
      subagentType: "post-exploit",
      priority: 3,
      objective: "Lateral movement from an established foothold",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: from any foothold gained on ${t}, expand reachability.
- Map the internal network reachable from the foothold; identify additional hosts, services, and trust relationships.
- Test credential reuse and captured secrets against other in-scope systems.
- Chain findings into a path toward higher-value assets. Keep every action reversible and non-disruptive.`,
        ),
    },
    {
      id: "privesc",
      name: "Privilege escalation",
      subagentType: "post-exploit",
      priority: 3,
      objective: "Privilege-escalation paths",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: identify privilege-escalation paths on compromised in-scope hosts of ${t}.
- Enumerate local/domain misconfigurations: sudo rules, SUID/capabilities, writable services/paths, secrets in config, over-privileged tokens/roles, and vulnerable service/kernel versions.
- Demonstrate escalation with the least-impact method and document it; do not disable security controls or damage the host.`,
        ),
    },
    {
      id: "chaining-planning",
      name: "Chaining & gap analysis",
      subagentType: "general",
      priority: 4,
      objective: "Chain findings into attack paths and find missing vectors",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: review ALL current findings for ${t} and think adversarially.
- For EACH confirmed finding ask the finding-forward questions: (1) what can I COMBINE it with (chain into a bigger impact)? (2) what did I MISS around it? (3) "if this is true, what ELSE must be true / reachable?" Turn the answers into concrete next objectives.
- Chain individual findings into end-to-end attack paths (entry -> access -> escalation -> impact) with likelihood and impact.
- Identify MISSING vectors against the checklist: cross-check \`openhack coverage --target ${t} --gaps\` (single-cell gaps), \`openhack combos --target ${t} --gaps\` (method-tuple / payload-family / chain-pair combinations), and \`openhack checklist\` — every vulnerability class on every discovered endpoint × method should be tested with every payload family that applies. Output the untested cells and combinations as a prioritized list of next objectives.
- This plan feeds the next orchestration round and the final report.`,
        ),
    },
    {
      id: "combination-gaps",
      name: "Combinatorial-coverage gap sweep",
      subagentType: "general",
      priority: 4,
      objective: "Close every method-tuple / payload-family / chain-pair the checklist still reports open",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: run \`openhack combos --target ${t} --gaps --per-finding\` and close its output mathematically.

For each section the tool prints:
1. **Method-tuple gaps** — send a minimal non-destructive request with each missing method (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD) on every listed endpoint; if a new method is accepted, RE-RUN the applicable checklist against that method.
2. **Payload-family gaps** — for each (endpoint × method × class) cell that has been engaged but missing families, send ONE representative payload from each missing family (see \`packages/openhack/knowledge/payloadsallthethings-index.json\` for the upstream directory pointer, and HackTricks URLs are shown alongside each cell in \`--report\`).
3. **Chain-pair gaps** — for each vulnerable A-cell whose B-side is untested, exercise B using the primitive gained from A. Record the resulting finding's \`promotionChain\` back to A's finding id.
4. **Per-finding combinations** — for each recorded finding, close the surrounding neighbourhood the tool lists (same-endpoint / chain-class / same-class-other-endpoints).

Update the coverage store after each attempt (\`Coverage.mark\` supports a \`payloadFamilies\` array) so the next round's \`openhack combos\` output shrinks. Terminate when the "combos open" count reaches 0. Stay in scope; never destructive.`,
        ),
    },
    // ── loop-graph hybrid — additional agent roles ─────────────────────────
    // These four orchestrators promote osint / defense / c2 / cleanup from
    // "on-disk agent files that the loop never dispatched" to first-class
    // objectives with declared priority. Two of them reuse existing slash-
    // command macros so the protocol is one source of truth.
    {
      id: "osint-passive",
      name: "OSINT — passive discovery",
      subagentType: "osint",
      priority: 0,
      objective: "Enumerate the authorized attack surface with only passive intel (no direct scans)",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: passively enumerate ${t}'s attack surface. Zero direct probing of the target.
- Certificate transparency logs (crt.sh, censys); subdomain enumeration via passive DNS + threat-intel sources.
- OSINT for company / employees / email format: LinkedIn, GitHub (leaked commits, config/env in public repos), archive.org, breach databases.
- Historical WHOIS + PDNS to spot infrastructure the current DNS doesn't advertise.
- Feed every discovered host into \`.openhack/scope.json\` (advisory — the operator confirms scope changes).
- STOP before any active scan — that's the recon orchestrator's job.`,
        ),
    },
    {
      id: "defense-review",
      name: "Blue-team adversarial review",
      subagentType: "defense",
      priority: 3,
      objective: "Adversarially score existing findings from the defender's perspective",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: read every finding for ${t} and adversarially score each one.
- For each finding: ask "would this pass an independent PoC test?", "is severity over/under-rated?", "what's the benign explanation?", "how would a defender detect this attack?".
- Mark low-confidence or unreproducible findings as manual_verify_required.
- Note detection opportunities the operator should mention in the report.
- This is the counterweight to the exploit specialist's optimism; use it before the council orchestrator escalates disputes.`,
        ),
    },
    {
      id: "c2-handoff",
      name: "C2 handoff planning",
      subagentType: "c2",
      priority: 3,
      objective: "Plan C2 handoff for verified footholds (opt-in via --objectives c2-handoff)",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: for each verified foothold on ${t}, plan a controlled C2 handoff.
- Enumerate handoff options via the arcticfox MCP (agent deploy, dead-drop, queue).
- Pick the LEAST invasive option that demonstrates operational capability without persistence beyond the engagement window.
- Document the exact commands / callback URLs used, so cleanup can undo them.
- If arcticfox is not enabled or authorized, describe the handoff plan in prose only — do NOT execute.`,
        ),
    },
    {
      id: "cleanup-artifacts",
      name: "Post-assessment cleanup",
      subagentType: "cleanup",
      command: "cleanup",
      priority: 99,
      objective: "Decommission every deployed artifact in reverse-deploy order",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: run the /cleanup macro protocol against ${t}. Reverse-deploy order; verify each removal; report leftovers.`,
        ),
    },
    {
      id: "report",
      name: "Report synthesis",
      subagentType: "report",
      priority: 5,
      objective: "Synthesize findings into a report",
      instruction: (t) =>
        withDoctrine(
          t,
          `Objective: synthesize all findings for ${t} into a professional report.
- Score each finding with CVSS v3.1 (vector + base score), map it to a CWE (and CVE where applicable), and give actionable, prioritized remediation.
- Include an executive summary, the confirmed attack paths from the chaining step, evidence, and residual risk. Save the report under .openhack/reports/.`,
        ),
    },
  ]

  export function get(id: string): Orchestrator | undefined {
    return ORCHESTRATORS.find((o) => o.id === id)
  }

  /** Ordered dispatch plan (orchestrator ids), earliest priority first. */
  export function plan(): string[] {
    return [...ORCHESTRATORS].sort((a, b) => a.priority - b.priority).map((o) => o.id)
  }

  /** Build an ordered Automode batch of specialized objective tasks for a target. */
  export function buildBatch(target: string, ids?: string[]): Automode.TaskSpec[] {
    const selected = ids && ids.length ? ORCHESTRATORS.filter((o) => ids.includes(o.id)) : ORCHESTRATORS
    return [...selected]
      .sort((a, b) => a.priority - b.priority)
      .map((o) => ({
        id: o.id,
        prompt: o.instruction(target),
        agent: o.subagentType,
        priority: o.priority,
        // Loop-graph hybrid: when an orchestrator declares a `command`, the
        // TaskSpec carries it forward and `runInstance` dispatches via macro
        // rather than the agent path.
        ...(o.command ? { command: o.command } : {}),
      }))
  }
}
