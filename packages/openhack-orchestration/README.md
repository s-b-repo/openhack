# @openhack/orchestration

The live **attack-graph loop primitives** OpenHack's `automode` iterates over.
This package used to ship two orphaned "backends" (a while-loop and a
single-node LangGraph). It was rebuilt around a real multi-node graph and a
per-round controller — see `AGENTS.md` § "Attack graph & tight loop" for the
end-user description; this README is the internal API map.

## Files

| File | Exports | Purpose |
|---|---|---|
| `src/types.ts` | `AttackGraphSnapshot`, `AssetNode`, `FindingNode`, `ActionNode`, `Edge`, `GraphUpdate`, `Controller`, `ControllerInput`, `emptyUpdate` | Data model. |
| `src/store.ts` | `GraphStore.{load,save,empty,filePath,computeHmac,verifyHmac,withLock}` | HMAC-signed JSON persistence at `.openhack/graph/<safeTarget>.json` (mode 0600) + advisory mkdir lock (mirrors `Findings.withLock`). |
| `src/graph.ts` | `AttackGraph.{load,save,withLock,seed,apply,frontier,gc,isAsset,isFinding,isAction,toActionNode,toTaskSpec,newActionId,endpointId,edge}` | AttackGraph namespace — mutations are idempotent by node id / edge triple so a repeat `apply(update)` is a no-op. |
| `src/frontier.ts` | `Frontier.{pruneWithEnforcement,pruneAndAnnotateEdges}` | Pure-enforcement pruning. Reuses `evaluateToolCall`, `ROE.enforce`, `ResourceManager.findConflicting` from `@openhack-ai/openhack`. |
| `src/heuristic.ts` | `HeuristicController.{make,run,empty}` | Deterministic fallback controller. Emits verify-finding, chain-finding, and test-gap ActionNodes. Used both as the LLM-controller fallback AND as the mock driver for `bench:loop`. |
| `src/controller.ts` | `LlmController.{make,convert,buildUser,noop}`, `LlmController.Options`, `LlmController.Generate` | LLM controller shell — accepts an operator-supplied `generate` callable (built from `Provider.getSmallModel` + `generateObject` at the call site), 15 s timeout, graceful degrade to the heuristic on any failure. |
| `src/index.ts` | Re-exports. | — |

## Integration

- **Loop driver** — `packages/openhack-cli/src/cli/cmd/openhack.automode.ts`. Extends `runOrchestrationLoop` behind the `graph.controller_enabled` config flag (default off). See the header in that file for the exact insertion points.
- **Persistence** — `.openhack/graph/<safeTarget>.json` HMAC-signed, mode 0600. The signing key at `.openhack/graph/.signing_key` mirrors the findings-store key.
- **Enforcement** — the controller *proposes*; the frontier *filters*. Every candidate ActionNode is dry-run through the same policy the real tool call would face, and blocked candidates carry their reason back to the graph so the controller sees them next round.
- **Combination edges** — chain-pair gaps materialize as `"combines-with"` edges between two `asset:endpoint` nodes. The AttackGraph therefore records not just *what was found* but *what pairs still need to be tested together* — the combinatorial-coverage checklist and the graph are the same object under two projections.
- **Model resolution** — the controller uses the `Generate` you supply. The intended pattern is: `Provider.getSmallModel(defaultProvider)` → `generateObject({model, schema, prompt: buildUser(input)})` → your `Generate` returns the model's `GraphUpdate` (or `null` on error/timeout).

## Tests

`packages/openhack/test/`:
- `graph.test.ts` — store round-trip, HMAC tamper, apply-idempotence, frontier ordering, gc.
- `controller.heuristic.test.ts` — deterministic verify/chain/gap emission, budget cap, class-based agent routing.
- `frontier.enforcement.test.ts` — scope/ROE/resource conflict paths.
- `controller.llm.test.ts` — stubbed `generate` for happy / timeout / throw / invalid-shape paths, plus `convert` clamping.
- `loop.graph.integration.test.ts` — end-to-end with the real loop driver + a mock LLM factory, byte-identical fallback, static→graph handoff, early-terminate.

Run from `packages/openhack/`: `bun test test/`.
