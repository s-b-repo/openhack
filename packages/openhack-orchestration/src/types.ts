/**
 * OpenHack attack-graph orchestration types.
 *
 * The AttackGraph is a live *view* over the engagement, layered on top of the
 * existing (HMAC-signed) `Findings` and `Coverage` sources of truth. It never
 * duplicates their contents — Finding nodes reference `Findings` by hash and
 * Action nodes reference `Coverage` cells by (endpoint, method, classId).
 *
 * The graph is mutated once per orchestration round by a small AI controller
 * (or a deterministic heuristic fallback) which turns "what happened last
 * round" into "what to dispatch next round". The loop driver calls the
 * controller, prunes the produced Action nodes against the pure enforcement
 * decisions (safety / scope / ROE / resource lock), and dispatches only the
 * survivors — feeding the round's actual observations back in on the next
 * iteration.
 *
 * The legacy `OrchestrationMode = "self" | "graph"` alias is kept so older
 * callers still type-check; nothing in the runtime reads it any more.
 */

// ---------- Legacy alias (kept only so existing type imports keep resolving) --

export type OrchestrationMode = "self" | "graph"

// ---------- Node identity --------------------------------------------------

/**
 * Namespaced graph node id. Prefixes are structural, not decorative:
 *   `asset:host/<value>`
 *   `asset:port/<value>`           e.g. `asset:port/1.2.3.4:80`
 *   `asset:service/<value>`        e.g. `asset:service/1.2.3.4:80/http`
 *   `asset:endpoint/<method> <url>`
 *   `asset:cred/<label>`
 *   `asset:host_domain/<value>`
 *   `finding:<Findings.hash>`
 *   `action:<uuid>`
 */
export type NodeId = string

export type AssetKind = "host" | "port" | "service" | "endpoint" | "cred" | "host_domain"

export interface AssetNode {
  id: NodeId
  kind: AssetKind
  value: string
  parents: NodeId[]
  discoveredInRound: number
  lastSeenRound: number
  attrs: Record<string, string>
}

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export interface FindingNode {
  id: NodeId
  /** Reference into `Findings` — its content hash, not its short id. */
  findingHash: string
  severity: Severity
  cwe?: string
  affectedComponent?: string
  verified: boolean
}

export type ActionStatus = "queued" | "dispatched" | "done" | "blocked" | "pruned"

export interface ActionNode {
  id: NodeId
  /** Human-readable objective / subagent handle (e.g. "recon-depth", "verify-finding"). */
  objective: string
  /** Target subagent name (`recon` | `exploit` | `post-exploit` | `report` | `general`, ...). */
  agent: string
  /**
   * Slash-command macro name (`"council"`, `"triage"`, `"plan"`, `"cleanup"`).
   * When set, dispatch bypasses the agent path and invokes the macro via
   * `runCommandMacro(command, prompt)` — the loop-graph hybrid's mechanism
   * for promoting a review/QA meta-objective to a first-class graph node.
   * Absent → normal `--agent <agent>` subprocess dispatch.
   */
  command?: string
  /** The full instruction body sent to the subagent. */
  prompt: string
  /** 1 = highest, 5 = lowest — matches Automode.TaskSpec.priority. */
  priority: number
  /** Controller's expected-value score for scheduling (higher first). */
  score: number
  /** Predicted marginal information / access gain if this action succeeds. */
  expectedGain: number
  /** Coverage cell this action targets, if any (drives dedup + gap satisfaction). */
  classId?: string
  endpointKey?: string
  /** Node ids this action needs to already exist (pruned if unmet). */
  requires: NodeId[]
  /** Node ids this action is predicted to produce (advisory — controller learns). */
  produces: NodeId[]
  spawnedRound: number
  status: ActionStatus
  blockedReason?: string
}

export type NodeUnion = AssetNode | FindingNode | ActionNode

export type EdgeKind =
  | "produced-by"
  | "requires"
  | "invalidates"
  | "pivots-to"
  | "parent-of"
  /** Chain-pair combination edge — links two endpoint AssetNodes whose class-pair
   *  (attrs.classPair = "A/B") the operator still needs to exercise as a combo. */
  | "combines-with"

export interface Edge {
  from: NodeId
  to: NodeId
  kind: EdgeKind
  addedInRound: number
  source: "controller" | "seed" | "observation"
}

// ---------- Snapshot -------------------------------------------------------

export interface AttackGraphSnapshot {
  target: string
  createdAt: string
  lastRound: number
  nodes: Record<NodeId, NodeUnion>
  edges: Edge[]
  /** HMAC over the canonical structural digest (see `store.ts`). */
  hmac: string
}

// ---------- Controller I/O -------------------------------------------------

export interface FindingLike {
  hash: string
  severity: Severity
  status: "verified" | "uncertain" | "false_positive"
  title: string
  cwe?: string
  affected_component?: string
}

export interface CoverageGap {
  endpoint: string
  method: string
  classId: string
  className: string
}

export interface CoverageSummary {
  endpoints: number
  cells: number
  tested: number
  untested: number
  vulnerable: number
  percent: number
}

export interface RoundDelta {
  newFindings: number
  newHigh: number
  costUsd: number
}

/** Minimal shape of `Combinations.CombinationReport` — mirrored here so this
 *  package doesn't have to import from `@opencode-ai/openhack`. */
export interface CombinationGapsLike {
  methods: Array<{ endpoint: string; testedMethods: string[]; missingMethods: string[] }>
  payloads: Array<{
    endpoint: string
    method: string
    classId: string
    className: string
    missingFamilies: string[]
    /** Max weight across the missing families for this gap — feeds heuristic scoring. */
    weight?: "high" | "medium" | "low"
  }>
  chains: Array<{
    endpointA: string; methodA: string; classA: string
    endpointB: string; methodB: string; classB: string
    /** Severity weight of the vulnerable A-leg — feeds heuristic scoring. */
    weight?: "high" | "medium" | "low"
  }>
  perFinding: Array<{
    findingId: string
    title: string
    description: string
    severity: string
    status: string
    classId?: string
    affectedComponent?: string
    inferredEndpoint?: string
    chainHints: string[]
    promotionChain: Array<{ councilId: string; action: string; rationale: string; timestamp: string }>
    evidenceFiles: string[]
    missingCombos: Array<{ endpoint: string; method: string; classId: string; payloadFamilyId: string }>
  }>
  universeSize: number
  satisfiedSize: number
}

export interface ControllerInput {
  target: string
  round: number
  snapshot: AttackGraphSnapshot
  findings: FindingLike[]
  coverageSummary: CoverageSummary | null
  coverageGaps: CoverageGap[]
  /** Combinatorial-coverage gaps — null when the checklist hasn't been computed yet. */
  combinationGaps: CombinationGapsLike | null
  lastRoundDelta: RoundDelta
  budgetRemainingUsd: number
  roeMinsRemaining?: number
  /** Ids already queued in the frontier so the controller doesn't re-emit them. */
  currentFrontierIds: NodeId[]
  /**
   * Optional MoE-routed agent picker. When supplied, the controller consults
   * it to choose an ActionNode's `agent` from the prompt content — persisted
   * MoE scores (`.openhack/moe-stats.json`) then adapt future routing to what
   * actually worked. When absent, the controller falls back to its
   * doctrine-derived hardcoded defaults (recon→recon, exploit→exploit, etc.).
   * The callback is passed through by the loop driver so the orchestration
   * package doesn't have to import the openhack MoE module directly.
   */
  routeAgent?: (prompt: string) => string
}

export interface GraphUpdate {
  addNodes: NodeUnion[]
  addEdges: Edge[]
  reprioritize: Array<{ id: NodeId; score: number }>
  /** ActionNode ids to mark `status: "pruned"`. */
  prune: NodeId[]
  /** Subset of queued ActionNode ids the controller wants to dispatch this round. */
  dispatch: NodeId[]
  /** One-line audit trail line saved with the round. */
  rationale: string
}

export interface Controller {
  (input: ControllerInput): Promise<GraphUpdate>
}

/**
 * Empty-update sentinel — returned by the LLM controller on error / timeout /
 * schema-validation failure. The loop driver treats an empty update as "reuse
 * the static batch this round", so nothing is dispatched extra and nothing is
 * pruned. Keep this as the single canonical empty shape.
 */
export function emptyUpdate(rationale = "no-op"): GraphUpdate {
  return { addNodes: [], addEdges: [], reprioritize: [], prune: [], dispatch: [], rationale }
}
