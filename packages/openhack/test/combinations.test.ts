import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Combinations } from "../src/combinations"
import { Coverage } from "../src/coverage"
import { Checklist } from "../src/checklist"
import { Knowledge } from "../src/knowledge"

/**
 * Combinations set-diff correctness — one describe block per axis, plus a
 * `checklist()` assembly test and the idempotency property required by the plan.
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-combos-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

function seedEndpoint(target: string, endpoint: string, method: string, classId: string, result: Coverage.Result, families: string[] = []): void {
  let store = Coverage.load(target)
  store = Coverage.mark(store, {
    endpoint, method, classId, result,
    ...(families.length ? { payloadFamilies: families } : {}),
  })
}

describe("Combinations.methodGaps", () => {
  test("empty store → no gaps", () => {
    expect(Combinations.methodGaps(Coverage.empty("t"))).toEqual([])
  })

  test("endpoint tested only on GET reports the other six methods missing", () => {
    seedEndpoint("t", "/x", "GET", "sqli", "safe")
    const gaps = Combinations.methodGaps(Coverage.load("t"))
    expect(gaps.length).toBe(1)
    expect(gaps[0]!.endpoint).toBe("/x")
    expect(gaps[0]!.testedMethods).toEqual(["GET"])
    expect(gaps[0]!.missingMethods).toEqual(["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
  })

  test("endpoint tested on all 7 universe methods → no gap", () => {
    for (const m of Combinations.METHOD_UNIVERSE) seedEndpoint("t", "/full", m, "sqli", "safe")
    expect(Combinations.methodGaps(Coverage.load("t"))).toEqual([])
  })

  test("multiple endpoints independent", () => {
    seedEndpoint("t", "/a", "GET", "sqli", "safe")
    seedEndpoint("t", "/b", "POST", "sqli", "safe")
    seedEndpoint("t", "/b", "DELETE", "sqli", "safe")
    const gaps = Combinations.methodGaps(Coverage.load("t"))
    expect(gaps.length).toBe(2)
    const a = gaps.find((g) => g.endpoint === "/a")!
    const b = gaps.find((g) => g.endpoint === "/b")!
    expect(a.missingMethods).toContain("POST")
    expect(b.missingMethods).toContain("GET")
    expect(b.missingMethods).not.toContain("POST")
  })
})

describe("Combinations.payloadFamilyGaps", () => {
  test("untested cell is NOT emitted (already covered by Coverage.gaps)", () => {
    // seed the endpoint but leave a cell untested by not calling mark on it directly:
    // instead, add an endpoint (which seeds all applicable classes as untested)
    let store = Coverage.load("t")
    Coverage.addEndpoint(store, "/x", "GET")
    Coverage.save(store)
    expect(Combinations.payloadFamilyGaps(Coverage.load("t"))).toEqual([])
  })

  test("engaged cell with NO tested families reports every family as missing", () => {
    seedEndpoint("t", "/x", "POST", "sqli", "safe")
    const gaps = Combinations.payloadFamilyGaps(Coverage.load("t"))
    expect(gaps.length).toBe(1)
    const known = Knowledge.payloadFamilies("sqli").map((f) => f.id)
    expect(gaps[0]!.missingFamilies.sort()).toEqual([...known].sort())
    expect(gaps[0]!.testedFamilies).toEqual([])
  })

  test("engaged cell with SOME tested families reports only the remainder", () => {
    seedEndpoint("t", "/x", "POST", "sqli", "safe", ["error-based", "boolean-blind"])
    const gaps = Combinations.payloadFamilyGaps(Coverage.load("t"))
    expect(gaps.length).toBe(1)
    expect(gaps[0]!.testedFamilies).toContain("error-based")
    expect(gaps[0]!.testedFamilies).toContain("boolean-blind")
    expect(gaps[0]!.missingFamilies).not.toContain("error-based")
    expect(gaps[0]!.missingFamilies.length).toBeGreaterThan(0)
  })

  test("engaged cell with FULL family set → no gap for that cell", () => {
    const all = Knowledge.payloadFamilies("sqli").map((f) => f.id)
    seedEndpoint("t", "/x", "POST", "sqli", "safe", all)
    expect(Combinations.payloadFamilyGaps(Coverage.load("t"))).toEqual([])
  })

  test("class with no vendored families is silently skipped", () => {
    seedEndpoint("t", "/x", "GET", "sec-headers", "safe")
    // sec-headers has no PayloadsAllTheThings entry — no gap emitted.
    const gaps = Combinations.payloadFamilyGaps(Coverage.load("t"))
    expect(gaps.find((g) => g.classId === "sec-headers")).toBeUndefined()
  })
})

describe("Combinations.chainGaps", () => {
  test("no vulnerable cells → no chain gaps", () => {
    seedEndpoint("t", "/x", "POST", "sqli", "safe")
    expect(Combinations.chainGaps(Coverage.load("t"))).toEqual([])
  })

  test("vulnerable sqli → emits gaps for each chainHint present in the coverage matrix", () => {
    seedEndpoint("t", "/login", "POST", "sqli", "vulnerable")
    // Also seed a cell for a chainHint of sqli — 'auth' is a chainHint.
    seedEndpoint("t", "/login", "POST", "auth", "untested")
    const gaps = Combinations.chainGaps(Coverage.load("t"))
    const authGap = gaps.find((g) => g.classB === "auth")
    expect(authGap).toBeDefined()
    expect(authGap!.classA).toBe("sqli")
    expect(authGap!.whyA).toBe("vulnerable")
    expect(authGap!.whyB).toBe("untested")
  })

  test("vulnerable A → still emits a virtual gap when B has NO coverage anywhere", () => {
    seedEndpoint("t", "/x", "GET", "xss", "vulnerable")
    // xss has chainHints including 'csrf' — but we haven't touched csrf on any endpoint.
    const gaps = Combinations.chainGaps(Coverage.load("t"))
    const csrfGap = gaps.find((g) => g.classB === "csrf")
    expect(csrfGap).toBeDefined()
    expect(csrfGap!.endpointB).toBe(csrfGap!.endpointA) // anchored to A's endpoint
  })

  test("skip self-pairs on same endpoint+method", () => {
    seedEndpoint("t", "/x", "POST", "sqli", "vulnerable")
    // Because we insert a chainHint of the vulnerable class itself into its own list
    // via the augment table wouldn't happen (sqli's chainHints don't include sqli).
    // Sanity: no gap where A === B on the same location.
    const gaps = Combinations.chainGaps(Coverage.load("t"))
    for (const g of gaps) {
      const same = g.classA === g.classB && g.endpointA === g.endpointB && g.methodA === g.methodB
      expect(same).toBe(false)
    }
  })

  test("chain gap dedup — same (A,B) pair on same endpoints reported once", () => {
    seedEndpoint("t", "/login", "POST", "sqli", "vulnerable")
    seedEndpoint("t", "/login", "POST", "auth", "untested")
    // Mark same class twice to force a re-emit path:
    Coverage.mark(Coverage.load("t"), { endpoint: "/login", method: "POST", classId: "auth", result: "untested" })
    const gaps = Combinations.chainGaps(Coverage.load("t"))
    const sqliAuth = gaps.filter((g) => g.classA === "sqli" && g.classB === "auth" && g.endpointB === "/login" && g.methodB === "POST")
    expect(sqliAuth.length).toBe(1)
  })
})

describe("Combinations.checklist assembly", () => {
  test("returns all three axes and a target/generatedAt", () => {
    seedEndpoint("t", "/a", "POST", "sqli", "vulnerable")
    const report = Combinations.checklist("t")
    expect(report.target).toBe("t")
    expect(report.generatedAt.length).toBeGreaterThan(0)
    expect(Array.isArray(report.methods)).toBe(true)
    expect(Array.isArray(report.payloads)).toBe(true)
    expect(Array.isArray(report.chains)).toBe(true)
    expect(Combinations.totalGaps(report)).toBe(report.methods.length + report.payloads.length + report.chains.length)
  })
})

describe("Combinations.writeMarkdown", () => {
  test("writes a checklist under .openhack/checklists/<target>.md", () => {
    seedEndpoint("t", "/a", "GET", "sqli", "safe")
    const report = Combinations.checklist("t")
    const fp = Combinations.writeMarkdown(report)
    expect(fs.existsSync(fp)).toBe(true)
    const body = fs.readFileSync(fp, "utf-8")
    expect(body).toContain("Combinatorial coverage checklist — t")
    expect(body).toContain("Method-tuple coverage")
    expect(body).toContain("Payload-family coverage")
    expect(body).toContain("Chain-pair coverage")
  })

  test("empty report renders satisfied-language across all three axis sections", () => {
    const report = Combinations.checklist("nothing")
    const md = Combinations.renderMarkdown(report)
    expect(md).toContain("All discovered endpoints")
    expect(md).toContain("Every engaged cell")
    expect(md).toContain("Every vulnerable finding")
    // The exhaustive renderer includes a Legend that documents `[ ]` as a
    // symbol — presence of that symbol in the legend does NOT imply an open
    // combo. Instead, check that no checklist SECTION (h3) has an unchecked
    // action item under it in an empty report.
    // Sections start with "### " — split and confirm none contains "- [ ]".
    const sections = md.split(/\n### /)
    for (const s of sections.slice(1)) {
      // headings we do expect to remain empty in an empty report don't emit `- [ ]`
      expect(s.includes("- [ ]")).toBe(false)
    }
  })
})

describe("Combinations — property: gap-satisfaction idempotency", () => {
  test("marking every missing method once removes those method gaps", () => {
    seedEndpoint("t", "/x", "GET", "sqli", "safe")
    const initial = Combinations.methodGaps(Coverage.load("t"))
    expect(initial.length).toBe(1)
    // Fulfil every missing method.
    for (const m of initial[0]!.missingMethods) seedEndpoint("t", "/x", m, "sqli", "safe")
    expect(Combinations.methodGaps(Coverage.load("t"))).toEqual([])
  })

  test("marking every missing payload family removes those payload gaps", () => {
    seedEndpoint("t", "/x", "POST", "sqli", "safe")
    const missing = Combinations.payloadFamilyGaps(Coverage.load("t"))[0]!.missingFamilies
    seedEndpoint("t", "/x", "POST", "sqli", "safe", missing)
    expect(Combinations.payloadFamilyGaps(Coverage.load("t")).find((g) => g.classId === "sqli" && g.endpoint === "/x" && g.method === "POST")).toBeUndefined()
  })
})
