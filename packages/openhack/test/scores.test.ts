// Graph controller score persistence tests.
//
// Cross-run learning: after N rounds we know which agent kinds produce
// findings and which are dead weight. Verify:
//
//   • Unknown kind → prior 1.0 (neutral).
//   • A kind that produces 1 finding/round consistently → prior > 2.0.
//   • A kind that produces 0 findings over many rounds → prior < 1.0.
//   • Prior is clamped to [0.25, 3.0].
//   • Roundtrip through save/load preserves stats.
//   • HMAC tamper is caught → empty store returned.
//   • record() is idempotent on the same roundNumber (dedup guard).

import { describe, expect, test, beforeEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Scores } from "../../openhack-orchestration/src/scores"

let tmpdir: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), "scores-test-"))
  process.chdir(tmpdir)
})

describe("Scores.priorFor", () => {
  test("unknown kind → 1.0 (neutral)", () => {
    const s = Scores.load("example.com")
    expect(Scores.priorFor(s, "recon")).toBe(1.0)
  })

  test("all-productive kind → prior > 2.0", () => {
    const s = Scores.load("example.com")
    for (let r = 1; r <= 10; r++) {
      Scores.record(s, { roundNumber: r, dispatchedKinds: ["exploit"], newFindings: 2, newHigh: 1, roundCostUsd: 0.1 })
    }
    const p = Scores.priorFor(s, "exploit")
    expect(p).toBeGreaterThan(2.0)
    expect(p).toBeLessThanOrEqual(3.0)
  })

  test("zero-productive kind → prior < 1.0", () => {
    const s = Scores.load("example.com")
    for (let r = 1; r <= 10; r++) {
      Scores.record(s, { roundNumber: r, dispatchedKinds: ["dead-agent"], newFindings: 0, newHigh: 0, roundCostUsd: 0.1 })
    }
    const p = Scores.priorFor(s, "dead-agent")
    expect(p).toBeLessThan(1.0)
    expect(p).toBeGreaterThanOrEqual(0.25)
  })

  test("prior is bounded [0.25, 3.0]", () => {
    const s = Scores.load("example.com")
    for (let r = 1; r <= 100; r++) {
      Scores.record(s, { roundNumber: r, dispatchedKinds: ["overproductive"], newFindings: 100, newHigh: 100, roundCostUsd: 0.001 })
    }
    expect(Scores.priorFor(s, "overproductive")).toBeLessThanOrEqual(3.0)
  })
})

describe("Scores.record", () => {
  test("splits findings evenly across dispatched kinds", () => {
    const s = Scores.load("example.com")
    Scores.record(s, { roundNumber: 1, dispatchedKinds: ["a", "b"], newFindings: 2, newHigh: 0, roundCostUsd: 0.4 })
    expect(s.kinds["a"]!.meanNewFindings).toBe(1)
    expect(s.kinds["b"]!.meanNewFindings).toBe(1)
    expect(s.kinds["a"]!.meanCostUsd).toBe(0.2)
  })

  test("dedup on same roundNumber", () => {
    const s = Scores.load("example.com")
    Scores.record(s, { roundNumber: 1, dispatchedKinds: ["a"], newFindings: 5, newHigh: 2, roundCostUsd: 1.0 })
    Scores.record(s, { roundNumber: 1, dispatchedKinds: ["a"], newFindings: 100, newHigh: 100, roundCostUsd: 100 })
    expect(s.kinds["a"]!.dispatches).toBe(1) // second call should be a no-op
  })

  test("cumulative rolling mean with Welford-style update", () => {
    const s = Scores.load("example.com")
    Scores.record(s, { roundNumber: 1, dispatchedKinds: ["a"], newFindings: 2, newHigh: 0, roundCostUsd: 0.1 })
    Scores.record(s, { roundNumber: 2, dispatchedKinds: ["a"], newFindings: 4, newHigh: 0, roundCostUsd: 0.3 })
    // avg=(2+4)/2=3, avg cost=(0.1+0.3)/2=0.2
    expect(s.kinds["a"]!.meanNewFindings).toBe(3)
    expect(s.kinds["a"]!.meanCostUsd).toBe(0.2)
    expect(s.kinds["a"]!.dispatches).toBe(2)
    expect(s.kinds["a"]!.productiveRounds).toBe(2)
  })
})

describe("Scores.save / load roundtrip", () => {
  test("stats preserved through save + reload", () => {
    const s = Scores.load("example.com")
    Scores.record(s, { roundNumber: 1, dispatchedKinds: ["recon", "exploit"], newFindings: 3, newHigh: 1, roundCostUsd: 0.5 })
    Scores.save(s)
    const loaded = Scores.load("example.com")
    expect(loaded.kinds["recon"]?.dispatches).toBe(1)
    expect(loaded.kinds["exploit"]?.dispatches).toBe(1)
    expect(loaded.lastAppliedRound).toBe(1)
  })

  test("HMAC tamper detected → empty store returned", () => {
    const s = Scores.load("example.com")
    Scores.record(s, { roundNumber: 1, dispatchedKinds: ["recon"], newFindings: 1, newHigh: 0, roundCostUsd: 0.1 })
    Scores.save(s)
    // Corrupt the body but keep the file structurally valid JSON.
    const files = fs.readdirSync(".openhack").filter((f) => f.startsWith("graph-scores.") && f.endsWith(".json"))
    expect(files.length).toBe(1)
    const p = path.join(".openhack", files[0]!)
    const raw = JSON.parse(fs.readFileSync(p, "utf-8"))
    raw.body = raw.body.replace("recon", "attacker-controlled")
    fs.writeFileSync(p, JSON.stringify(raw))
    const loaded = Scores.load("example.com")
    expect(Object.keys(loaded.kinds).length).toBe(0)
  })
})

describe("Scores.summary", () => {
  test("top and bottom sort by prior", () => {
    const s = Scores.load("example.com")
    for (let r = 1; r <= 5; r++) Scores.record(s, { roundNumber: r, dispatchedKinds: ["hot"], newFindings: 3, newHigh: 1, roundCostUsd: 0.1 })
    for (let r = 6; r <= 10; r++) Scores.record(s, { roundNumber: r, dispatchedKinds: ["cold"], newFindings: 0, newHigh: 0, roundCostUsd: 0.1 })
    const sum = Scores.summary(s)
    expect(sum.top[0]!.kind).toBe("hot")
    expect(sum.bottom[0]!.kind).toBe("cold")
  })
})
