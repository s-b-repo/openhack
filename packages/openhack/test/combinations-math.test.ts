import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Combinations } from "../src/combinations"
import { Coverage } from "../src/coverage"
import { Findings } from "../src/findings"
import { Knowledge } from "../src/knowledge"
import { Checklist } from "../src/checklist"

/**
 * Mathematical-completeness guarantees for the checking algorithm. These tests
 * pin the properties the user asked for — that the enumeration walks EVERY
 * possible combo, and that per-finding views are proper subsets of that walk.
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-combos-math-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

function seed(target: string, endpoint: string, method: string, classId: string, result: Coverage.Result, families: string[] = []): void {
  let store = Coverage.load(target)
  store = Coverage.mark(store, {
    endpoint, method, classId, result,
    ...(families.length ? { payloadFamilies: families } : {}),
  })
}

describe("enumerateAllCombos — mathematical completeness", () => {
  test("single endpoint × single class covers exactly METHOD_UNIVERSE × applicable-classes × families", () => {
    seed("t", "/x", "GET", "sqli", "safe")
    const universe = Combinations.enumerateAllCombos(Coverage.load("t"))
    // Every combo shares the same endpoint.
    for (const c of universe) expect(c.endpoint).toBe("/x")
    // For every METHOD_UNIVERSE method, expect at least one combo of every applicable class.
    for (const m of Combinations.METHOD_UNIVERSE) {
      const applicable = Checklist.forMethod(m)
      for (const cls of applicable) {
        const combos = universe.filter((c) => c.method === m && c.classId === cls.id)
        // If the class has payload families, expect one combo per family; else exactly one.
        const fams = Knowledge.payloadFamilies(cls.id)
        expect(combos.length).toBe(fams.length === 0 ? 1 : fams.length)
      }
    }
  })

  test("combosSatisfied is a strict subset of enumerateAllCombos (as keys)", () => {
    seed("t", "/x", "POST", "sqli", "safe", ["error-based", "boolean-blind"])
    const universe = new Set(Combinations.enumerateAllCombos(Coverage.load("t")).map((c) => `${c.endpoint}|${c.method}|${c.classId}|${c.payloadFamilyId}`))
    const sat = Combinations.combosSatisfied(Coverage.load("t")).map((c) => `${c.endpoint}|${c.method}|${c.classId}|${c.payloadFamilyId}`)
    for (const k of sat) expect(universe.has(k)).toBe(true)
  })

  test("combosMissing + combosSatisfied == enumerateAllCombos (partition)", () => {
    seed("t", "/x", "POST", "sqli", "safe", ["error-based"])
    seed("t", "/y", "GET", "xss", "safe", ["reflected"])
    const universe = Combinations.enumerateAllCombos(Coverage.load("t"))
    const sat = Combinations.combosSatisfied(Coverage.load("t"))
    const missing = Combinations.combosMissing(Coverage.load("t"))
    expect(sat.length + missing.length).toBe(universe.length)
  })

  test("marking a combo as tested moves it from missing to satisfied (monotonicity)", () => {
    seed("t", "/x", "POST", "sqli", "safe")
    const beforeMissing = Combinations.combosMissing(Coverage.load("t")).length
    seed("t", "/x", "POST", "sqli", "safe", ["error-based"])
    const afterMissing = Combinations.combosMissing(Coverage.load("t")).length
    expect(afterMissing).toBe(beforeMissing - 1)
  })

  test("empty coverage → empty universe (no discovered endpoints yet)", () => {
    expect(Combinations.enumerateAllCombos(Coverage.empty("t"))).toEqual([])
    expect(Combinations.combosMissing(Coverage.empty("t"))).toEqual([])
  })

  test("universe size matches the analytic formula for one endpoint", () => {
    seed("t", "/x", "GET", "sqli", "safe")
    const universe = Combinations.enumerateAllCombos(Coverage.load("t"))
    // Per-method sum of (family-count or 1) over applicable classes.
    let expected = 0
    for (const m of Combinations.METHOD_UNIVERSE) {
      for (const cls of Checklist.forMethod(m)) {
        const fams = Knowledge.payloadFamilies(cls.id)
        expected += Math.max(1, fams.length)
      }
    }
    expect(universe.length).toBe(expected)
  })
})

describe("perFindingCombos — checking algorithm per relevant finding", () => {
  function seedFinding(target: string, title: string, severity: Findings.Finding["severity"], component: string, description = ""): void {
    const store = Findings.load(target)
    Findings.add(store, {
      id: "", timestamp: new Date().toISOString(),
      target, title, description: description || title,
      severity, status: "verified", source_agent: "test", source_session: "test",
      evidence_files: [], manual_verify_required: false, audit_trail: [],
      promotionChain: [], challengedByCouncils: [], hash: "", hmac: "", tags: [],
      affected_component: component,
      proof_of_concept: "reproduced with curl",
    })
    // The finding's status will be downgraded to uncertain by the evidence gate;
    // that's fine — the per-finding walker doesn't require verified status.
  }

  test("returns one entry per Finding, ordered by severity desc", () => {
    seed("t", "/login", "POST", "sqli", "vulnerable")
    seedFinding("t", "low finding", "low", "/login")
    seedFinding("t", "critical finding", "critical", "/login")
    seedFinding("t", "medium finding", "medium", "/login")
    const perF = Combinations.perFindingCombos("t")
    expect(perF.length).toBe(3)
    expect(perF[0]!.severity).toBe("critical")
    expect(perF[1]!.severity).toBe("medium")
    expect(perF[2]!.severity).toBe("low")
  })

  test("infers classId from title/description keywords", () => {
    seedFinding("t", "SQL injection at login form", "critical", "/login")
    const perF = Combinations.perFindingCombos("t")
    expect(perF[0]!.classId).toBe("sqli")
  })

  test("infers classId from explicit id present in the tags/text", () => {
    seedFinding("t", "Vulnerable cors", "high", "/api", "The cors config exposes sensitive")
    const perF = Combinations.perFindingCombos("t")
    expect(perF[0]!.classId).toBe("cors")
  })

  test("missingCombos are drawn from combosMissing (strict subset)", () => {
    seed("t", "/login", "POST", "sqli", "vulnerable")
    seedFinding("t", "SQL injection", "critical", "/login")
    const universeMissing = new Set(Combinations.combosMissing(Coverage.load("t")).map((c) => `${c.endpoint}|${c.method}|${c.classId}|${c.payloadFamilyId}`))
    const pf = Combinations.perFindingCombos("t")[0]!
    for (const c of pf.missingCombos) {
      expect(universeMissing.has(`${c.endpoint}|${c.method}|${c.classId}|${c.payloadFamilyId}`)).toBe(true)
    }
  })

  test("chainHints reflect Checklist.get(classId).chainHints", () => {
    seed("t", "/login", "POST", "sqli", "vulnerable")
    seedFinding("t", "SQL injection", "critical", "/login")
    const pf = Combinations.perFindingCombos("t")[0]!
    expect(pf.chainHints.sort()).toEqual([...(Checklist.get("sqli")?.chainHints ?? [])].sort())
  })

  test("no findings recorded → empty perFinding array (never throws)", () => {
    expect(Combinations.perFindingCombos("t")).toEqual([])
  })

  test("endpoint inference — URL / method+path / bare path all normalized to `/path`", () => {
    // Direct unit test on the inference primitive — cleaner than piping through combos.
    const mk = (affected: string): Findings.Finding => ({
      id: "", timestamp: "", target: "t", title: "", description: "",
      severity: "high" as const, status: "verified" as const, source_agent: "", source_session: "",
      evidence_files: [], manual_verify_required: false, audit_trail: [],
      promotionChain: [], challengedByCouncils: [], hash: "", hmac: "", tags: [],
      affected_component: affected,
    })
    // Access the inference function through the module — exported for tests.
    const inferEndpoint = (f: Findings.Finding) => {
      // Reflect via a checklist() report on a seeded matching-endpoint store.
      // Simpler: re-implement the assertion in terms of observable output when
      // the endpoint IS present in coverage.
      seed("t2", "/api/v1/users", "GET", "sqli", "safe")
      seed("t2", "/login", "POST", "sqli", "safe")
      seed("t2", "/admin", "GET", "sqli", "safe")
      const store = Findings.load("t2")
      Findings.add(store, { ...f, target: "t2", title: "SQLi", description: "SQL injection here" })
      const pf = Combinations.perFindingCombos("t2")
      return pf[0]?.missingCombos.map((c) => c.endpoint) ?? []
    }
    expect(inferEndpoint(mk("https://example.com/api/v1/users?id=1")).some((e) => e === "/api/v1/users")).toBe(true)
    expect(inferEndpoint(mk("POST /login")).some((e) => e === "/login")).toBe(true)
    expect(inferEndpoint(mk("/admin")).some((e) => e === "/admin")).toBe(true)
  })
})

describe("checklist() report contains mathematical envelope fields", () => {
  test("universeSize, satisfiedSize, and perFinding all populated", () => {
    seed("t", "/x", "POST", "sqli", "safe", ["error-based"])
    const report = Combinations.checklist("t")
    expect(report.universeSize).toBeGreaterThan(0)
    expect(report.satisfiedSize).toBeGreaterThanOrEqual(1) // the one family we marked
    expect(report.satisfiedSize).toBeLessThanOrEqual(report.universeSize)
    expect(Array.isArray(report.perFinding)).toBe(true)
  })

  test("openComboCount == universeSize − satisfiedSize (never negative)", () => {
    seed("t", "/x", "POST", "sqli", "safe", ["error-based"])
    const report = Combinations.checklist("t")
    expect(Combinations.openComboCount(report)).toBe(report.universeSize - report.satisfiedSize)
    expect(Combinations.openComboCount(report)).toBeGreaterThanOrEqual(0)
  })
})
