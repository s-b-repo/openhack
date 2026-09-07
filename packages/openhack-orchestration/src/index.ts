/**
 * @openhack/orchestration — the live attack-graph loop driver primitives.
 *
 * See ./types.ts for the data model, ./graph.ts for the AttackGraph namespace,
 * ./store.ts for HMAC-signed persistence, ./frontier.ts for pure-enforcement
 * pruning, ./heuristic.ts for the deterministic controller, and ./controller.ts
 * for the LLM controller shell.
 *
 * The adaptive-harness subsystem (OpenHack's Harness-R1 port) lives in
 * ./harness-taxonomy.ts (the failure catalogue + deterministic detector),
 * ./harness-patch.ts (the declarative, validated intervention model),
 * ./harness-engineer.ts (synthesis + self-preference ranking + rerun reward),
 * ./harness-store.ts (HMAC-signed learned-state persistence), and ./harness.ts
 * (the `AdaptiveHarness` runtime the loop consults at four lifecycle points).
 */
export * from "./types"
export { AttackGraph } from "./graph"
export { GraphStore } from "./store"
export { Frontier } from "./frontier"
export { HeuristicController } from "./heuristic"
export { LlmController } from "./controller"
export { Scores } from "./scores"
export { LoopPhysics } from "./loop-physics"
export { RoundEngine } from "./round-engine"
export * as HarnessTaxonomy from "./harness-taxonomy"
export * as HarnessPatch from "./harness-patch"
export * as HarnessEngineer from "./harness-engineer"
export { HarnessStore } from "./harness-store"
export { AdaptiveHarness } from "./harness"
