import type { ActionNode } from "./types"

/**
 * RoundEngine — the frontier selection stage of an orchestration round, as a
 * swappable engine.
 *
 * The default `native` engine is the battle-tested `AttackGraph.frontier`
 * ordering (discounted score desc, priority asc, FIFO by spawned round). The
 * `langgraph` engine runs the SAME selection contract as a compiled LangGraph
 * StateGraph (`@langchain/langgraph` — the npm dep is the wired artifact of
 * `vendor/langgraph`): a three-node pipeline (score → prioritize → select)
 * that produces the identical ordering. `auto` prefers langgraph when the dep
 * resolves and falls back to native with a recorded reason — a fallback that
 * is always reported, never swallowed.
 */
export namespace RoundEngine {

  export type RoundEngineName = "native" | "langgraph" | "auto"

  export interface SelectInput {
    /** Queued ActionNodes in arbitrary order. */
    queued: readonly ActionNode[]
    /** Frontier width (top-k to return). */
    k: number
    /** Optional per-node score discount (e.g. LoopPhysics chain reliability). */
    discount?: (node: ActionNode) => number
  }

  export interface SelectResult {
    selected: ActionNode[]
    engine: "native" | "langgraph"
    /** Why a fallback happened / what the engine decided — never swallowed. */
    note?: string
  }

  /** The shared ordering contract: discounted score desc, priority asc, FIFO. */
  export function rank(queued: readonly ActionNode[], discount?: (node: ActionNode) => number): ActionNode[] {
    const effective = (n: ActionNode) => n.score - (discount ? discount(n) : 0)
    return [...queued].sort((a, b) => {
      const ea = effective(a)
      const eb = effective(b)
      if (eb !== ea) return eb - ea
      if (a.priority !== b.priority) return a.priority - b.priority
      return a.spawnedRound - b.spawnedRound
    })
  }

  export function nativeSelect(input: SelectInput): SelectResult {
    return { selected: rank(input.queued, input.discount).slice(0, Math.max(0, input.k)), engine: "native" }
  }

  // ─── engine health (surfaced by loop logs + tests) ───────────────────────────

  let langgraphResolved: boolean | null = null
  let lastNote: string | null = null
  let selections = 0
  let fallbacks = 0

  export const status = (): { langgraph: boolean | null; lastNote: string | null; selections: number; fallbacks: number } => ({
    langgraph: langgraphResolved,
    lastNote,
    selections,
    fallbacks,
  })

  /** True when @langchain/langgraph resolves in this runtime (cached probe). */
  export async function langgraphAvailable(): Promise<boolean> {
    if (langgraphResolved !== null) return langgraphResolved
    try {
      await import("@langchain/langgraph")
      langgraphResolved = true
    } catch {
      langgraphResolved = false
    }
    return langgraphResolved
  }

  /**
   * LangGraph selection pipeline — three pure nodes over a small state:
   *   score      — attach effective (discounted) scores per node id
   *   prioritize — order the queue by the shared contract
   *   select     — cut the top-k frontier
   * The discount is captured per build (functions are not graph state).
   */
  export async function langgraphSelect(input: SelectInput): Promise<SelectResult> {
    let mod: any
    try {
      mod = await import("@langchain/langgraph")
      langgraphResolved = true
    } catch (error) {
      langgraphResolved = false
      fallbacks++
      lastNote = `langgraph engine unavailable (@langchain/langgraph import failed: ${error instanceof Error ? error.message : String(error)}) → native`
      return { ...nativeSelect(input), engine: "native", note: lastNote }
    }
    const { Annotation, StateGraph, START, END } = mod
    if (typeof StateGraph !== "function" || typeof Annotation?.Root !== "function") {
      fallbacks++
      lastNote = "langgraph engine unavailable (StateGraph/Annotation export missing) → native"
      return { ...nativeSelect(input), engine: "native", note: lastNote }
    }
  const discount = input.discount
  const k = Math.max(0, input.k)
  const RoundState = Annotation.Root({
    scores: Annotation({ reducer: (_prev: Record<string, number>, next: Record<string, number>) => next ?? {}, default: () => ({}) }),
    ordered: Annotation({ reducer: (_prev: ActionNode[], next: ActionNode[]) => next ?? [], default: () => [] as ActionNode[] }),
    selected: Annotation({ reducer: (_prev: ActionNode[], next: ActionNode[]) => next ?? [], default: () => [] as ActionNode[] }),
  })
    const graph = new StateGraph(RoundState)
      .addNode("score", () => ({
        scores: Object.fromEntries(input.queued.map((n) => [n.id, n.score - (discount ? discount(n) : 0)])),
      }))
      .addNode("prioritize", (state: { scores: Record<string, number> }) => ({
        ordered: [...input.queued].sort((a, b) => {
          const ea = state.scores[a.id] ?? a.score
          const eb = state.scores[b.id] ?? b.score
          if (eb !== ea) return eb - ea
          if (a.priority !== b.priority) return a.priority - b.priority
          return a.spawnedRound - b.spawnedRound
        }),
      }))
      .addNode("select", (state: { ordered: ActionNode[] }) => ({ selected: state.ordered.slice(0, k) }))
      .addEdge(START, "score")
      .addEdge("score", "prioritize")
      .addEdge("prioritize", "select")
      .addEdge("select", END)
    const compiled = graph.compile()
    const result: any = await compiled.invoke({ scores: {}, ordered: [], selected: [] }, { recursionLimit: 10 })
    const selected: ActionNode[] = Array.isArray(result?.selected) ? result.selected : []
    return { selected, engine: "langgraph" }
  }

  /**
   * Select this round's frontier with the configured engine. `auto` tries
   * langgraph first and falls back to native with a recorded note.
   */
  export async function selectFrontier(input: SelectInput, engine: RoundEngineName = "native"): Promise<SelectResult> {
    selections++
    if (engine === "native") return nativeSelect(input)
    const result = await langgraphSelect(input)
    if (result.engine === "native") {
      fallbacks++
      lastNote = result.note ?? "langgraph fallback"
      return result
    }
    lastNote = `langgraph round-engine selected ${result.selected.length} of ${input.queued.length}`
    return result
  }

}
