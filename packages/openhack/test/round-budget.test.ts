// Adaptive round budget tests.
//
// The behavior under test:
//   • Fresh empty log → no termination, not productive.
//   • One productive round → productive=true, dry=0.
//   • Two dry rounds with empty frontier/combos → terminates with "converged".
//   • Two dry rounds with combos still open → terminates with "stalled" reason.
//   • shouldExtend returns true only when productive AND at ceiling AND budget headroom holds.
//   • Config overrides from .openhack/openhack.jsonc are honored.

import { describe, expect, test, beforeEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { RoundBudget } from "../src/round-budget"
import { ConfigStore } from "../src/config-store"

function mkRec(overrides: Partial<RoundBudget.RoundRecord>): RoundBudget.RoundRecord {
  return {
    round: 1,
    at: "2026-08-06T00:00:00Z",
    findingsTotal: 0,
    findingsHigh: 0,
    newFindings: 0,
    newHigh: 0,
    totalCostUsd: 0,
    roundCostUsd: 0,
    coverage: null,
    combos: { open: 0, universeSize: 100, satisfiedSize: 100 },
    frontierSize: 0,
    rssMb: 32,
    ...overrides,
  }
}

let tmpdir: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), "rb-test-"))
  process.chdir(tmpdir)
})

describe("RoundBudget.verdict", () => {
  test("empty log → no termination, no productivity", () => {
    const v = RoundBudget.verdict([])
    expect(v.terminate).toBe(false)
    expect(v.productive).toBe(false)
    expect(v.dryStreak).toBe(0)
  })

  test("single productive round → productive, dry=0", () => {
    const v = RoundBudget.verdict([mkRec({ newFindings: 3 })])
    expect(v.productive).toBe(true)
    expect(v.dryStreak).toBe(0)
    expect(v.terminate).toBe(false)
  })

  test("two consecutive dry rounds with 0 combos + 0 frontier → converged", () => {
    const v = RoundBudget.verdict([
      mkRec({ round: 1, newFindings: 0, frontierSize: 0, combos: { open: 0, universeSize: 100, satisfiedSize: 100 } }),
      mkRec({ round: 2, newFindings: 0, frontierSize: 0, combos: { open: 0, universeSize: 100, satisfiedSize: 100 } }),
    ])
    expect(v.terminate).toBe(true)
    expect(v.reason).toContain("converged")
    expect(v.dryStreak).toBe(2)
  })

  test("two dry rounds with combos still open → stalled", () => {
    const v = RoundBudget.verdict([
      mkRec({ round: 1, newFindings: 0, combos: { open: 20, universeSize: 100, satisfiedSize: 80 } }),
      mkRec({ round: 2, newFindings: 0, combos: { open: 20, universeSize: 100, satisfiedSize: 80 } }),
    ])
    expect(v.terminate).toBe(true)
    expect(v.reason).toContain("stalled")
  })

  test("productive round after two dry → dry-streak resets to 0", () => {
    const v = RoundBudget.verdict([
      mkRec({ round: 1, newFindings: 0 }),
      mkRec({ round: 2, newFindings: 0 }),
      mkRec({ round: 3, newFindings: 5 }),
    ])
    expect(v.dryStreak).toBe(0)
    expect(v.productive).toBe(true)
    expect(v.terminate).toBe(false)
  })

  test("closing combos counts as productive even with 0 new findings", () => {
    const v = RoundBudget.verdict([
      mkRec({ round: 1, combos: { open: 10, universeSize: 100, satisfiedSize: 90 } }),
      mkRec({ round: 2, newFindings: 0, combos: { open: 5, universeSize: 100, satisfiedSize: 95 } }),
    ])
    expect(v.productive).toBe(true)
    expect(v.combosClosed).toBe(5)
    expect(v.terminate).toBe(false)
  })
})

describe("RoundBudget.shouldExtend", () => {
  const productiveRecs = [
    mkRec({ round: 1, newFindings: 2, roundCostUsd: 0.10 }),
    mkRec({ round: 2, newFindings: 3, roundCostUsd: 0.10 }),
    mkRec({ round: 3, newFindings: 4, roundCostUsd: 0.10 }),
  ]

  test("below caller ceiling → don't extend (loop keeps going anyway)", () => {
    const ex = RoundBudget.shouldExtend({
      currentRound: 1, callerMaxRounds: 3, records: productiveRecs, remainingBudgetUsd: 10,
    })
    expect(ex.extend).toBe(false)
    expect(ex.reason).toContain("within")
  })

  test("at ceiling + productive + budget OK → extend +1", () => {
    const ex = RoundBudget.shouldExtend({
      currentRound: 3, callerMaxRounds: 3, records: productiveRecs, remainingBudgetUsd: 10,
    })
    expect(ex.extend).toBe(true)
    expect(ex.newMax).toBe(4)
  })

  test("at ceiling + unproductive → don't extend", () => {
    const ex = RoundBudget.shouldExtend({
      currentRound: 3, callerMaxRounds: 3,
      records: [mkRec({ round: 1, newFindings: 0 }), mkRec({ round: 2, newFindings: 0 }), mkRec({ round: 3, newFindings: 0 })],
      remainingBudgetUsd: 10,
    })
    expect(ex.extend).toBe(false)
    expect(ex.reason).toContain("unproductive")
  })

  test("productive but budget too tight → don't extend", () => {
    const expensive = [
      mkRec({ round: 1, newFindings: 2, roundCostUsd: 5.0 }),
      mkRec({ round: 2, newFindings: 3, roundCostUsd: 5.0 }),
      mkRec({ round: 3, newFindings: 4, roundCostUsd: 5.0 }),
    ]
    const ex = RoundBudget.shouldExtend({
      currentRound: 3, callerMaxRounds: 3, records: expensive, remainingBudgetUsd: 1.0,
    })
    expect(ex.extend).toBe(false)
    expect(ex.reason).toContain("headroom")
  })

  test("hard ceiling caps extensions", () => {
    fs.mkdirSync(".openhack", { recursive: true })
    fs.writeFileSync(".openhack/openhack.jsonc", JSON.stringify({ round_budget: { hard_ceiling: 5 } }))
    const ex = RoundBudget.shouldExtend({
      currentRound: 5, callerMaxRounds: 5, records: productiveRecs, remainingBudgetUsd: 100,
    })
    expect(ex.extend).toBe(false)
    expect(ex.reason).toContain("hard ceiling")
  })
})

describe("RoundBudget.readRoundLog", () => {
  test("reads valid JSONL, safe name mangling", () => {
    const dir = ".openhack/rounds"
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.join(dir, "example.com.jsonl"), JSON.stringify(mkRec({ round: 1 })) + "\n" + JSON.stringify(mkRec({ round: 2 })) + "\n")
    const recs = RoundBudget.readRoundLog("example.com")
    expect(recs.length).toBe(2)
    expect(recs[0]!.round).toBe(1)
  })

  test("target with special chars is mangled to file", () => {
    const dir = ".openhack/rounds"
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.join(dir, "https___example.com_path.jsonl"), JSON.stringify(mkRec({ round: 1 })))
    const recs = RoundBudget.readRoundLog("https://example.com/path")
    expect(recs.length).toBe(1)
  })

  test("missing file → empty array, no throw", () => {
    expect(RoundBudget.readRoundLog("nonexistent")).toEqual([])
  })
})

describe("RoundBudget.metrics", () => {
  test("aggregates per-round costs, findings, combos-closed", () => {
    const dir = ".openhack/rounds"
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.join(dir, "t.jsonl"),
      JSON.stringify(mkRec({ round: 1, newFindings: 2, roundCostUsd: 0.05, combos: { open: 30, universeSize: 100, satisfiedSize: 70 } })) + "\n" +
      JSON.stringify(mkRec({ round: 2, newFindings: 1, roundCostUsd: 0.03, combos: { open: 20, universeSize: 100, satisfiedSize: 80 } })) + "\n" +
      JSON.stringify(mkRec({ round: 3, newFindings: 3, roundCostUsd: 0.04, combos: { open: 10, universeSize: 100, satisfiedSize: 90 } })) + "\n"
    )
    const m = RoundBudget.metrics("t")
    expect(m.rounds).toBe(3)
    expect(m.findingsAdded).toBe(6)
    expect(m.combosClosed).toBe(20) // (30→20) + (20→10)
    expect(m.avgFindingsPerRound).toBe(2)
    expect(m.totalCostUsd).toBeCloseTo(0.12, 3)
  })
})

describe("RoundBudget.config overrides", () => {
  test("honors dry_streak_limit override", () => {
    fs.mkdirSync(".openhack", { recursive: true })
    fs.writeFileSync(".openhack/openhack.jsonc", JSON.stringify({ round_budget: { dry_streak_limit: 3 } }))
    ConfigStore.invalidateCache?.()
    const recs = [mkRec({ round: 1, newFindings: 0 }), mkRec({ round: 2, newFindings: 0 })]
    const v = RoundBudget.verdict(recs)
    expect(v.terminate).toBe(false)
    expect(v.dryStreak).toBe(2)
  })
})
