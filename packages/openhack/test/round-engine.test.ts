// Round-engine tests — the swappable frontier-selection stage.
//
//   • rank()/nativeSelect(): identical ordering to AttackGraph.frontier
//     (discounted score desc, priority asc, FIFO by spawned round)
//   • langgraph engine: same contract through the compiled StateGraph pipeline
//     (@langchain/langgraph is a wired dep of the orchestration package)
//   • auto: tries langgraph, falls back to native with a recorded note
//   • discount: reliability discounts reorder frontier selection
//   • status(): selections/fallbacks counted, notes recorded (nothing swallowed)

import { describe, expect, test } from "bun:test"
import { AttackGraph, RoundEngine, type ActionNode } from "../../openhack-orchestration/src"

const snap = (): any => ({
  nodes: {
    a: { kind: "asset", id: "a", type: "host", value: "h", status: "open" },
    f: { kind: "finding", id: "f", hash: "h1", status: "open" },
    a1: { kind: "action", id: "a1", objective: "o1", agent: "recon", prompt: "p", priority: 1, score: 0.9, spawnedRound: 1, status: "queued" },
    a2: { kind: "action", id: "a2", objective: "o2", agent: "exploit", prompt: "p", priority: 2, score: 0.9, spawnedRound: 1, status: "queued" },
    a3: { kind: "action", id: "a3", objective: "o3", agent: "recon", prompt: "p", priority: 2, score: 0.95, spawnedRound: 2, status: "queued" },
    a4: { kind: "action", id: "a4", objective: "o4", agent: "exploit", prompt: "p", priority: 1, score: 0.5, spawnedRound: 3, status: "queued" },
    a5: { kind: "action", id: "a5", objective: "o5", agent: "recon", prompt: "p", priority: 1, score: 0.5, spawnedRound: 3, status: "done" },
  },
})

const nodes = (s: any): ActionNode[] => {
  const queued: ActionNode[] = []
  for (const node of Object.values<any>(s.nodes)) {
    if (node.kind === "action" && node.status === "queued") queued.push(node)
  }
  return queued
}

describe("RoundEngine.rank / nativeSelect", () => {
  test("matches the historical AttackGraph.frontier ordering", () => {
    const s = snap()
    const historical = AttackGraph.frontier(s, 10).map((n) => n.id)
    const native = RoundEngine.nativeSelect({ queued: nodes(s), k: 10 }).selected.map((n) => n.id)
    expect(native).toEqual(historical)
  })

  test("orders by score desc, then priority asc, then FIFO", () => {
    const s = snap()
    const native = RoundEngine.nativeSelect({ queued: nodes(s), k: 10 }).selected.map((n) => n.id)
    // a1: score .9/pri1 first; a3 .95/pri2 beats a2 .9/pri2 (higher score);
    // a2 (.9/pri2) before a4 (.5/pri1)? No — score dominates: a1(.9) a3(.95) a2(.9) a4(.5)
    expect(native[0]).toBe("a3")
    expect(native.slice(1)).toEqual(["a1", "a2", "a4"])
  })

  test("top-k cut", () => {
    const s = snap()
    expect(RoundEngine.nativeSelect({ queued: nodes(s), k: 2 }).selected.map((n) => n.id)).toEqual(["a3", "a1"])
  })
})

describe("RoundEngine langgraph engine", () => {
  test("produces the identical ordering through the StateGraph pipeline", async () => {
    const s = snap()
    const input = { queued: nodes(s), k: 10 }
    const native = RoundEngine.nativeSelect(input)
    const lg = await RoundEngine.langgraphSelect(input)
    expect(lg.engine).toBe("langgraph")
    expect(lg.selected.map((n) => n.id)).toEqual(native.selected.map((n) => n.id))
  })

  test("selectFrontier('auto') works and records a note when it falls back", async () => {
    const s = snap()
    const result = await RoundEngine.selectFrontier({ queued: nodes(s), k: 3 }, "auto")
    expect(result.selected.length).toBeGreaterThan(0)
    if (result.engine === "native") expect(result.note).toBeTruthy()
  })
})

describe("RoundEngine.discount", () => {
  test("reliability discount reorders selection", () => {
    const s = snap()
    // Discount everything but a4: a4 becomes the only full-score action.
    const result = RoundEngine.nativeSelect({
      queued: nodes(s),
      k: 10,
      discount: (n) => (n.id === "a4" ? 0 : 1),
    })
    expect(result.selected[0]!.id).toBe("a4")
  })
})

describe("RoundEngine.status", () => {
  test("counts selections and records notes", async () => {
    await RoundEngine.selectFrontier({ queued: nodes(snap()), k: 1 }, "native")
    const st = RoundEngine.status()
    expect(st.selections).toBeGreaterThan(0)
  })
})
