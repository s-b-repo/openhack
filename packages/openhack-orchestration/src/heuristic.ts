import type {
  ActionNode,
  Controller,
  ControllerInput,
  CoverageGap,
  Edge,
  FindingLike,
  GraphUpdate,
  NodeUnion,
  Severity,
} from "./types"
import { emptyUpdate } from "./types"
import { AttackGraph } from "./graph"
import { Scores } from "./scores"

/**
 * Deterministic, LLM-free controller. Purpose:
 *
 *   1. Graceful degrade — used verbatim when the LLM controller times out /
 *      throws / returns a schema-invalid object. Same input → same output.
 *   2. Mock driver for the perf harness — the bench script runs with this
 *      controller so runs are reproducible and cost nothing.
 *   3. First-round warm start — before the LLM has any signal to work from,
 *      this fills the frontier from coverage gaps + existing findings.
 *
 * Emission rules (in priority order — the frontier sort inverts priority):
 *
 *   - For each *unverified* high/critical finding → one `verify-finding`
 *     ActionNode dispatched to `general` (priority 2, score 6).
 *   - For each *verified* critical finding → one `chain-finding` ActionNode
 *     to `post-exploit` (priority 3, score 5).
 *   - For up to N coverage gaps → one `test-gap` ActionNode per cell, routed
 *     to `recon` or `exploit` based on the vuln class name (priority 3-4).
 *
 * The controller caps its own output at ~2×frontier_k so it doesn't flood
 * the graph on a fresh engagement with hundreds of endpoints.
 */
export namespace HeuristicController {
  const MAX_ACTIONS_PER_ROUND = 12

  export function make(): Controller {
    return async (input: ControllerInput): Promise<GraphUpdate> => run(input)
  }

  /** Direct entry-point, exported so tests can call without wrapping. */
  export function run(input: ControllerInput): GraphUpdate {
    const { round, findings, coverageGaps, currentFrontierIds, target } = input
    const alreadyQueued = new Set(currentFrontierIds)
    const addNodes: NodeUnion[] = []
    const addEdges: Edge[] = []

    // --- 1) Verify unverified high/critical findings ---
    const toVerify = findings
      .filter((f) => (f.severity === "critical" || f.severity === "high") && f.status !== "verified" && f.status !== "false_positive")
      .slice(0, 6)
    for (const f of toVerify) {
      const id = AttackGraph.newActionId()
      if (alreadyQueued.has(id)) continue
      const action: ActionNode = {
        id,
        objective: `verify-finding-${f.hash.slice(0, 8)}`,
        agent: "general",
        prompt: verifyPrompt(target, f),
        priority: 2,
        score: severityWeight(f.severity) + 3, // 6 for critical, 5 for high
        expectedGain: 3,
        requires: [`finding:${f.hash}`],
        produces: [],
        spawnedRound: round,
        status: "queued",
      }
      addNodes.push(action)
      addEdges.push(AttackGraph.edge(action.id, `finding:${f.hash}`, "requires", round))
    }

    // --- 2) Chain verified critical findings forward ---
    const toChain = findings.filter((f) => f.severity === "critical" && f.status === "verified").slice(0, 4)
    for (const f of toChain) {
      const id = AttackGraph.newActionId()
      const action: ActionNode = {
        id,
        objective: `chain-finding-${f.hash.slice(0, 8)}`,
        agent: "post-exploit",
        prompt: chainPrompt(target, f),
        priority: 3,
        score: 5,
        expectedGain: 4,
        requires: [`finding:${f.hash}`],
        produces: [],
        spawnedRound: round,
        status: "queued",
      }
      addNodes.push(action)
      addEdges.push(AttackGraph.edge(action.id, `finding:${f.hash}`, "requires", round))
    }

    // --- 3) Fill remaining budget from coverage gaps ---
    // Reserve some budget for step 4 (combinatorial gaps) when they're present,
    // otherwise a big coverage-gap round would starve the combo axis every time.
    const comboReserve = input.combinationGaps ? 4 : 0
    const remaining = MAX_ACTIONS_PER_ROUND - addNodes.length - comboReserve
    const gapSlice = coverageGaps.slice(0, Math.max(0, remaining))
    for (const g of gapSlice) {
      const id = AttackGraph.newActionId()
      const epId = AttackGraph.endpointId(g.endpoint, g.method)
      // MoE-routed when the caller supplies it; otherwise fall back to the
      // classify-by-classname regex. This lets `.openhack/moe-stats.json`
      // adapt routing to what actually worked, instead of a static heuristic.
      const gapPromptForRouting = `Test ${g.className} on ${g.method} ${g.endpoint}`
      const agent = input.routeAgent
        ? routeAgentWithFallback(input.routeAgent, gapPromptForRouting, classifyGapAgent(g))
        : classifyGapAgent(g)
      const action: ActionNode = {
        id,
        objective: `test-gap-${g.method}-${sanitize(g.classId)}`,
        agent,
        prompt: gapPrompt(target, g),
        priority: gapPriority(g),
        score: gapScore(g),
        expectedGain: 2,
        classId: g.classId,
        endpointKey: `${g.method.toUpperCase()} ${g.endpoint}`,
        requires: [epId],
        produces: [],
        spawnedRound: round,
        status: "queued",
      }
      addNodes.push(action)
      addEdges.push(AttackGraph.edge(action.id, epId, "requires", round))
    }

    // --- 4) Combinatorial-coverage gaps (methods / payload families / chains) ---
    // Only emit until the round budget is exhausted; the loop driver's frontier(k)
    // will pick the top-k across steps 1-4 by score.
    let comboCount = 0
    if (input.combinationGaps && addNodes.length < MAX_ACTIONS_PER_ROUND) {
      const budget = () => MAX_ACTIONS_PER_ROUND - addNodes.length

      // 4a — method-tuple gaps (`GET was tested, was POST, was DELETE?`)
      for (const mg of input.combinationGaps.methods.slice(0, budget())) {
        if (budget() <= 0) break
        for (const m of mg.missingMethods.slice(0, 2)) { // cap 2 methods/endpoint per round
          if (budget() <= 0) break
          const epId = AttackGraph.endpointId(mg.endpoint, m)
          const id = AttackGraph.newActionId()
          const action: ActionNode = {
            id,
            objective: `test-method-${m}-${sanitize(mg.endpoint)}`,
            agent: "recon",
            prompt: methodComboPrompt(target, mg.endpoint, m, mg.testedMethods),
            priority: 4,
            score: 2,
            expectedGain: 1,
            endpointKey: `${m} ${mg.endpoint}`,
            requires: [epId],
            produces: [],
            spawnedRound: round,
            status: "queued",
          }
          addNodes.push(action)
          addEdges.push(AttackGraph.edge(action.id, epId, "requires", round))
          comboCount++
        }
      }

      // 4b — payload-family gaps (each engaged cell × missing families)
      for (const pg of input.combinationGaps.payloads.slice(0, budget())) {
        if (budget() <= 0) break
        const epId = AttackGraph.endpointId(pg.endpoint, pg.method)
        const id = AttackGraph.newActionId()
        // Score by knowledge weight: high=6, medium=4, low=2. Bumps high-impact
        // payload combos (SQLi time-blind, cmdi inline-unix, SSRF cloud-metadata)
        // above informational ones (open-redirect params, verbose errors) in the
        // frontier's top-k ordering.
        const w = pg.weight ?? "medium"
        const wScore = w === "high" ? 6 : w === "medium" ? 4 : 2
        const wPri = w === "high" ? 2 : w === "medium" ? 3 : 4
        const payloadAgent = input.routeAgent
          ? routeAgentWithFallback(input.routeAgent, `Test ${pg.className} payload families on ${pg.method} ${pg.endpoint}`, "exploit")
          : "exploit"
        const action: ActionNode = {
          id,
          objective: `test-payload-${sanitize(pg.classId)}-${sanitize(pg.endpoint)}`,
          agent: payloadAgent,
          prompt: payloadFamilyPrompt(target, pg),
          priority: wPri,
          score: wScore,
          expectedGain: w === "high" ? 3 : 2,
          classId: pg.classId,
          endpointKey: `${pg.method} ${pg.endpoint}`,
          requires: [epId],
          produces: [],
          spawnedRound: round,
          status: "queued",
        }
        addNodes.push(action)
        addEdges.push(AttackGraph.edge(action.id, epId, "requires", round))
        comboCount++
      }

      // 4c — chain-pair gaps (vulnerable A cell → not-yet-vulnerable B cell)
      for (const cg of input.combinationGaps.chains.slice(0, budget())) {
        if (budget() <= 0) break
        const epA = AttackGraph.endpointId(cg.endpointA, cg.methodA)
        const epB = AttackGraph.endpointId(cg.endpointB, cg.methodB)
        const id = AttackGraph.newActionId()
        // Chain gaps carry the max of A/B class weights — a chain between two
        // high-weight classes deserves the highest score in the frontier.
        const w = cg.weight ?? "medium"
        const wScore = w === "high" ? 7 : w === "medium" ? 5 : 3
        const wPri = w === "high" ? 2 : w === "medium" ? 3 : 4
        const action: ActionNode = {
          id,
          objective: `chain-${sanitize(cg.classA)}-with-${sanitize(cg.classB)}`,
          agent: "post-exploit",
          prompt: chainComboPrompt(target, cg),
          priority: wPri,
          score: wScore, // high-weight chains dominate frontier top-k
          expectedGain: w === "high" ? 5 : 4,
          endpointKey: `${cg.methodB} ${cg.endpointB}`,
          requires: [epA, epB],
          produces: [],
          spawnedRound: round,
          status: "queued",
        }
        addNodes.push(action)
        addEdges.push(AttackGraph.edge(action.id, epA, "requires", round))
        addEdges.push(AttackGraph.edge(action.id, epB, "requires", round))
        // Reflect the combination itself into the graph as a first-class edge
        // (attrs.classPair stashed on the endpoint asset via attrs).
        addEdges.push({ from: epA, to: epB, kind: "combines-with", addedInRound: round, source: "controller" })
        comboCount++
      }
    }

    // --- 5) Loop-graph hybrid nodes (council, triage, osint, cleanup) ---
    // Promote the review / QA / passive-discovery / decommission roles to
    // first-class ActionNodes so the graph controller can score, prune, and
    // dispatch them like any other node. Each is guarded so the branch stays
    // inert when combinationGaps is null (bench mode / no-graph runs).
    let hybridCount = 0
    // Council — after any round that produced ≥2 new findings, front-run a
    // council review so weak findings are caught before the next round builds
    // on them. Score 8 so it beats verify (6), chain (5), gaps (~3).
    if (input.lastRoundDelta.newFindings >= 2) {
      const id = AttackGraph.newActionId()
      const newFindingNodeIds = input.findings.slice(0, 20).map((f) => `finding:${f.hash}`)
      const action: ActionNode = {
        id,
        objective: `council-review-r${round}`,
        agent: "general",
        command: "council",
        prompt: `Run the council review protocol against ${target} covering this round's new findings.`,
        priority: 1,
        score: 8,
        expectedGain: 3,
        requires: newFindingNodeIds,
        produces: [],
        spawnedRound: round,
        status: "queued",
      }
      addNodes.push(action)
      for (const req of newFindingNodeIds) addEdges.push(AttackGraph.edge(action.id, req, "requires", round))
      hybridCount++
    }
    // Triage — when coverage and combos are both wide open, run the triage
    // macro to structure the next-round gap list. Score 6 so it competes with
    // verify actions but doesn't dominate.
    if (input.combinationGaps && input.coverageGaps.length > 20 && input.combinationGaps.methods.length > 5) {
      const id = AttackGraph.newActionId()
      const action: ActionNode = {
        id,
        objective: `triage-r${round}`,
        agent: "general",
        command: "triage",
        prompt: `Run the triage macro against ${target} — code quality + coverage gap enumeration.`,
        priority: 2,
        score: 6,
        expectedGain: 2,
        requires: [],
        produces: [],
        spawnedRound: round,
        status: "queued",
      }
      addNodes.push(action)
      hybridCount++
    }
    // OSINT — round 1 only, when the graph is starting cold. Score 4, priority 1
    // so it dispatches ahead of the standard recon frontier.
    if (round === 1) {
      const id = AttackGraph.newActionId()
      const action: ActionNode = {
        id,
        objective: `osint-r1`,
        agent: "osint",
        prompt: `Passive intel enumeration on ${target}: certificate transparency, passive DNS, historical WHOIS, GitHub leaks. Zero direct probes.`,
        priority: 1,
        score: 4,
        expectedGain: 2,
        requires: [],
        produces: [],
        spawnedRound: round,
        status: "queued",
      }
      addNodes.push(action)
      hybridCount++
    }
    // Cleanup — when the whole checklist is closed, emit a cleanup action to
    // decommission any artifacts. Low score (2) but explicit `priority: 99` so
    // the frontier scheduler runs it last.
    if (
      input.combinationGaps &&
      input.combinationGaps.methods.length === 0 &&
      input.combinationGaps.payloads.length === 0 &&
      input.combinationGaps.chains.length === 0 &&
      input.coverageGaps.length === 0
    ) {
      const id = AttackGraph.newActionId()
      const action: ActionNode = {
        id,
        objective: `cleanup-final`,
        agent: "cleanup",
        command: "cleanup",
        prompt: `Run the cleanup macro against ${target}. Reverse-deploy order; verify each removal; report leftovers.`,
        priority: 99,
        score: 2,
        expectedGain: 1,
        requires: [],
        produces: [],
        spawnedRound: round,
        status: "queued",
      }
      addNodes.push(action)
      hybridCount++
    }

    // --- 6) Score reweighting from persistent per-kind history ---
    // Multiply each ActionNode's score by the prior for its agent kind — a kind
    // that's produced findings before gets bumped, one that consistently returns
    // nothing gets dampened. This is what turns the deterministic controller
    // into an adaptive one across runs. Failure to load the store leaves
    // scores untouched (defensive: never break the controller on a fresh engagement).
    let scoreStore: Scores.Store | null = null
    try { scoreStore = Scores.load(target) } catch {}
    if (scoreStore) {
      for (const n of addNodes) {
        if (n.kind === "action" || (n as ActionNode).agent !== undefined) {
          const a = n as ActionNode
          const prior = Scores.priorFor(scoreStore, a.agent)
          if (prior !== 1.0) a.score = Math.round(a.score * prior * 100) / 100
        }
      }
    }

    // We do NOT preselect `dispatch` — the loop driver's frontier(k) already picks the
    // top-k by score for us and marks them dispatched. Returning dispatch: [] keeps the
    // controller and driver responsibilities cleanly separated.
    return {
      addNodes,
      addEdges,
      reprioritize: [],
      prune: [],
      dispatch: [],
      rationale: `heuristic:round=${round} verify=${toVerify.length} chain=${toChain.length} gaps=${gapSlice.length} combo=${comboCount} hybrid=${hybridCount}`,
    }
  }

  /** Public no-op for symmetry with the LLM path. */
  export function empty(): GraphUpdate {
    return emptyUpdate("heuristic:noop")
  }

  // ---- Helpers -------------------------------------------------------------

  function severityWeight(s: Severity): number {
    return s === "critical" ? 3 : s === "high" ? 2 : s === "medium" ? 1 : 0
  }

  /**
   * MoE routing wrapper that gracefully falls back to a doctrine default when
   * the router throws or returns an unroutable value. Any agent name the
   * caller trusts (from `.openhack/agents/*.md`) is fine; the only names we
   * reject are empty strings / non-strings. This is deliberately permissive —
   * the loop's own MoE call at dispatch time is the real enforcement point.
   */
  function routeAgentWithFallback(router: (p: string) => string, prompt: string, fallback: string): string {
    try {
      const picked = router(prompt)
      if (typeof picked === "string" && picked.length) return picked
    } catch {}
    return fallback
  }

  function classifyGapAgent(g: CoverageGap): string {
    const name = (g.className + " " + g.classId).toLowerCase()
    if (/recon|enum|discovery|dns|port|host|surface|version/.test(name)) return "recon"
    if (/rce|injection|xss|csrf|ssrf|auth|bypass|deserial|upload|traversal|redir/.test(name)) return "exploit"
    if (/leak|expos|info|verbose|error|listing/.test(name)) return "post-exploit"
    return "exploit"
  }

  function gapPriority(g: CoverageGap): number {
    const name = (g.className + " " + g.classId).toLowerCase()
    if (/rce|inject|auth|bypass|deserial/.test(name)) return 2
    if (/xss|csrf|ssrf|upload|traversal/.test(name)) return 3
    return 4
  }

  function gapScore(g: CoverageGap): number {
    // Complement of priority so higher priority (lower number) sorts first.
    return 5 - gapPriority(g)
  }

  function sanitize(s: string): string {
    return s.replace(/[^a-zA-Z0-9-]/g, "_").slice(0, 40)
  }

  function verifyPrompt(target: string, f: FindingLike): string {
    return `Target: ${target}

Objective: verify the finding "${f.title}" (${f.severity}${f.cwe ? `, ${f.cwe}` : ""})${f.affected_component ? ` on ${f.affected_component}` : ""}.

- Read the existing evidence in .openhack/findings/ and reproduce the PoC.
- If reproducible with a benign, non-destructive proof, mark the finding verified with the reproduced PoC and an on-disk evidence file.
- If not reproducible, mark false-positive with a reason.
- Every action stays within scope + ROE (the runtime enforces this).`
  }

  function chainPrompt(target: string, f: FindingLike): string {
    return `Target: ${target}

Objective: chain the verified finding "${f.title}" forward.

- Given this access, what additional in-scope systems, credentials, or data become reachable?
- Attempt one reversible pivot (credential replay, lateral SSRF-to-internal, IDOR-to-sibling) and capture evidence.
- Record any new findings and mark the chain in each finding's audit trail.
- Never destructive. Never DoS.`
  }

  function gapPrompt(target: string, g: CoverageGap): string {
    return `Target: ${target}

Objective: test ${g.method.toUpperCase()} ${g.endpoint} for ${g.className} (${g.classId}).

- Use the appropriate preset or MCP tool for this vuln class.
- On any hit, record a finding with reproducible PoC + on-disk evidence file, and update the coverage cell to vulnerable.
- On no hit, mark the coverage cell "safe" (not "untested").
- Stay in scope; never destructive.`
  }

  function methodComboPrompt(target: string, endpoint: string, method: string, testedMethods: string[]): string {
    return `Target: ${target}

Objective: extend HTTP-method coverage on \`${endpoint}\` by trying \`${method}\`.

Already tested methods for this endpoint: [${testedMethods.join(", ") || "none"}].

- Send a minimal, non-destructive \`${method}\` request. Distinguish accepted / 405 / 401 / 403 / 500.
- If ${method} is accepted, RE-RUN the vulnerability class checklist for this endpoint against ${method} (the applicable classes may differ from what was applicable for the previously-tested methods).
- Record the outcome in \`.openhack/coverage/\` (\`openhack coverage --target ${target}\`) so the combinatorial-coverage frontier deducts this method from the missing set.
- Stay in scope; never destructive.`
  }

  function payloadFamilyPrompt(
    target: string,
    pg: { endpoint: string; method: string; classId: string; className: string; missingFamilies: string[] },
  ): string {
    return `Target: ${target}

Objective: exercise \`${pg.method} ${pg.endpoint}\` for **${pg.className}** with the payload families you have NOT yet tried.

Missing PayloadsAllTheThings families for this cell: [${pg.missingFamilies.join(", ")}].

- Send one representative payload from each missing family (see \`packages/openhack/knowledge/payloadsallthethings-index.json\` for the upstream directory pointer).
- Record every family attempted via the coverage store's \`payloadFamilies\` field so the combinatorial-coverage frontier deducts this axis from the missing set.
- If any family lands, record a finding with reproducible PoC + evidence file. Otherwise mark the family as covered but the cell result stays "safe".
- Stay in scope; never destructive.`
  }

  function chainComboPrompt(
    target: string,
    cg: { endpointA: string; methodA: string; classA: string; endpointB: string; methodB: string; classB: string },
  ): string {
    return `Target: ${target}

Objective: prove the CHAIN from vulnerable \`${cg.classA}\` on \`${cg.methodA} ${cg.endpointA}\` into \`${cg.classB}\` on \`${cg.methodB} ${cg.endpointB}\`.

- Leg A is already verified vulnerable. Use its access (session/cred/injection primitive) to reach Leg B.
- If Leg B lands, record a chained finding whose \`promotionChain\` cites Leg A's finding id.
- Record Leg B's result in the coverage matrix so the chain-pair frontier deducts this pair from the missing set.
- Non-destructive proof only; do NOT weaponize the chain further than needed to demonstrate.`
  }
}
