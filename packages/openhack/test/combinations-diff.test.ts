import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Combinations } from "../src/combinations"
import { Coverage } from "../src/coverage"

/**
 * Coverage snapshots + Combinations.diffSince — the workflow the CLI's
 * `combos-snapshot` + `combos-diff` commands drive.
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-diff-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

function seed(target: string, ep: string, m: string, cls: string, r: Coverage.Result, fams: string[] = []) {
  let s = Coverage.load(target)
  s = Coverage.mark(s, { endpoint: ep, method: m, classId: cls, result: r, ...(fams.length ? { payloadFamilies: fams } : {}) })
}

describe("Coverage snapshot storage", () => {
  test("snapshot() writes a JSON at .openhack/coverage/snapshots/<safeTarget>/<label>.json", () => {
    seed("t", "/x", "GET", "sqli", "safe")
    const fp = Coverage.snapshot("t", "round-1")
    expect(fs.existsSync(fp)).toBe(true)
    expect(fp).toMatch(/coverage\/snapshots\/t\/round-1\.json$/)
  })

  test("loadSnapshot returns null when the label doesn't exist", () => {
    expect(Coverage.loadSnapshot("t", "no-such")).toBeNull()
  })

  test("loadSnapshot round-trips a saved snapshot", () => {
    seed("t", "/x", "POST", "sqli", "vulnerable", ["error-based"])
    Coverage.snapshot("t", "s1")
    const snap = Coverage.loadSnapshot("t", "s1")
    expect(snap).not.toBeNull()
    expect(snap!.endpoints.length).toBe(1)
    expect(snap!.endpoints[0]!.cells.sqli!.result).toBe("vulnerable")
  })

  test("listSnapshots enumerates saved labels newest-first", async () => {
    seed("t", "/x", "GET", "sqli", "safe")
    Coverage.snapshot("t", "old")
    // Sleep briefly so mtime differs.
    await new Promise((r) => setTimeout(r, 10))
    Coverage.snapshot("t", "new")
    const list = Coverage.listSnapshots("t")
    expect(list.length).toBe(2)
    expect(list[0]!.label).toBe("new")
    expect(list[1]!.label).toBe("old")
  })

  test("path traversal in labels is neutralized", () => {
    seed("t", "/x", "GET", "sqli", "safe")
    const fp = Coverage.snapshot("t", "../../../etc/passwd")
    const resolved = path.resolve(fp)
    const snapRoot = path.resolve(".openhack", "coverage", "snapshots")
    expect(resolved.startsWith(snapRoot + path.sep)).toBe(true)
  })
})

describe("Combinations.diffSince", () => {
  test("returns null when the snapshot label doesn't exist", () => {
    expect(Combinations.diffSince("t", "no-such")).toBeNull()
  })

  test("closed set: combos open at snapshot, satisfied now", () => {
    // Snapshot with 0 payload families tested.
    seed("t", "/x", "POST", "sqli", "safe")
    Coverage.snapshot("t", "before")
    // Then close one family.
    seed("t", "/x", "POST", "sqli", "safe", ["error-based"])
    const d = Combinations.diffSince("t", "before")!
    expect(d).not.toBeNull()
    // The error-based family combo must appear in 'closed'.
    const found = d.closed.find((c) => c.classId === "sqli" && c.payloadFamilyId === "error-based" && c.endpoint === "/x" && c.method === "POST")
    expect(found).toBeDefined()
  })

  test("opened set: newly-discovered endpoint gets its combos in the opened list", () => {
    seed("t", "/x", "GET", "sqli", "safe")
    Coverage.snapshot("t", "before")
    // Later: discover /y.
    seed("t", "/y", "POST", "sqli", "safe")
    const d = Combinations.diffSince("t", "before")!
    expect(d.opened.some((c) => c.endpoint === "/y")).toBe(true)
  })

  test("still-open + still-satisfied tallies are non-negative and correlate with the sets", () => {
    seed("t", "/x", "GET", "sqli", "safe", ["error-based"])
    Coverage.snapshot("t", "s")
    seed("t", "/x", "GET", "sqli", "safe", ["boolean-blind"])
    const d = Combinations.diffSince("t", "s")!
    expect(d.stillOpen).toBeGreaterThanOrEqual(0)
    expect(d.stillSatisfied).toBeGreaterThanOrEqual(0)
    // At minimum, the previously-satisfied error-based combo is still satisfied.
    expect(d.stillSatisfied).toBeGreaterThan(0)
  })
})
