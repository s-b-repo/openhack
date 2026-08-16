// Inter-manager blackboard store tests.
//
// Verifies the durable peer-messaging channel the five phase-managers use:
//   • post → inbox delivery (addressed + broadcast, sender excluded)
//   • onlyOpen / markConsumed lifecycle
//   • prune drops old consumed messages but never open ones
//   • HMAC tamper is caught → message dropped on load
//   • concurrent withLock writes don't lose a message

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Blackboard } from "../src/blackboard"

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "blackboard-test-"))
  process.chdir(scratch)
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

const T = "example.com"

describe("Blackboard.post / inbox", () => {
  test("directed message is delivered to the addressed phase only", () => {
    Blackboard.post(T, { round: 1, from: "recon", to: "exploitation", kind: "directive", text: "found /admin" })
    expect(Blackboard.inbox(T, "exploitation").map((m) => m.text)).toEqual(["found /admin"])
    expect(Blackboard.inbox(T, "post-exploitation")).toEqual([])
  })

  test("broadcast reaches every phase except the sender", () => {
    Blackboard.post(T, { round: 1, from: "recon", to: "all", kind: "hint", text: "target is slow" })
    expect(Blackboard.inbox(T, "exploitation").length).toBe(1)
    expect(Blackboard.inbox(T, "c2").length).toBe(1)
    expect(Blackboard.inbox(T, "recon").length).toBe(0) // sender doesn't get its own broadcast
  })

  test("includeAll:false hides broadcasts", () => {
    Blackboard.post(T, { round: 1, from: "recon", to: "all", kind: "hint", text: "bc" })
    Blackboard.post(T, { round: 1, from: "recon", to: "exploitation", kind: "directive", text: "direct" })
    const only = Blackboard.inbox(T, "exploitation", { includeAll: false })
    expect(only.map((m) => m.text)).toEqual(["direct"])
  })

  test("post fills id/timestamp/hmac and defaults refs", () => {
    const m = Blackboard.post(T, { round: 2, from: "enumeration", to: "exploitation", kind: "request", text: "re-scan" })
    expect(m.id).toMatch(/^MSG-/)
    expect(m.status).toBe("open")
    expect(m.refs).toEqual([])
    expect(m.hmac.length).toBe(64)
  })
})

describe("Blackboard.markConsumed", () => {
  test("consumed messages drop out of the open inbox", () => {
    const m = Blackboard.post(T, { round: 1, from: "recon", to: "exploitation", kind: "directive", text: "x" })
    Blackboard.markConsumed(T, [m.id], "exploitation")
    expect(Blackboard.inbox(T, "exploitation").length).toBe(0)
    expect(Blackboard.inbox(T, "exploitation", { onlyOpen: false }).length).toBe(1)
  })

  test("markConsumed is idempotent and records consumedBy", () => {
    const m = Blackboard.post(T, { round: 1, from: "recon", to: "exploitation", kind: "directive", text: "x" })
    Blackboard.markConsumed(T, [m.id], "exploitation")
    Blackboard.markConsumed(T, [m.id], "exploitation")
    const all = Blackboard.inbox(T, "exploitation", { onlyOpen: false })
    expect(all[0]!.consumedBy).toBe("exploitation")
  })
})

describe("Blackboard.prune", () => {
  test("drops old consumed messages, keeps open ones", () => {
    const consumed = Blackboard.post(T, { round: 1, from: "recon", to: "exploitation", kind: "directive", text: "old" })
    Blackboard.post(T, { round: 1, from: "recon", to: "exploitation", kind: "directive", text: "still-open" })
    Blackboard.markConsumed(T, [consumed.id], "exploitation")
    Blackboard.prune(T, 2, 10) // round 10, keep < 2 rounds old → the consumed (r1) is dropped
    const remaining = Blackboard.load(T).messages.map((m) => m.text)
    expect(remaining).toEqual(["still-open"])
  })
})

describe("Blackboard HMAC integrity", () => {
  test("tampered message text is dropped on load", () => {
    const m = Blackboard.post(T, { round: 1, from: "recon", to: "exploitation", kind: "directive", text: "legit" })
    const files = fs.readdirSync(".openhack/blackboard").filter((f) => f.endsWith(".json"))
    const p = path.join(".openhack/blackboard", files[0]!)
    const store = JSON.parse(fs.readFileSync(p, "utf-8"))
    store.messages[0].text = "attacker-controlled"
    fs.writeFileSync(p, JSON.stringify(store))
    expect(Blackboard.load(T).messages.length).toBe(0)
    void m
  })
})

describe("Blackboard concurrency", () => {
  test("many concurrent posts all persist (no lost update under withLock)", async () => {
    const N = 25
    await Promise.all(
      Array.from({ length: N }, (_, i) =>
        Promise.resolve().then(() =>
          Blackboard.post(T, { round: 1, from: "recon", to: "exploitation", kind: "hint", text: `m${i}` }),
        ),
      ),
    )
    expect(Blackboard.load(T).messages.length).toBe(N)
  })
})
