import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Combinations } from "../src/combinations"
import { Coverage } from "../src/coverage"
import { ROE } from "../src/roe"

/**
 * ROE-aware method / combo enumeration. When a signed ROE restricts the
 * method-verb (via `authorized_tools` on the ROE document), the checklist
 * must never emit those methods as gaps or actionable combos — they'd be
 * blocked at the tool call anyway.
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-combos-roe-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

function seedCell(target: string, endpoint: string, method: string, classId: string, result: Coverage.Result): void {
  let store = Coverage.load(target)
  store = Coverage.mark(store, { endpoint, method, classId, result })
}

function signRoe(targets: string[], authorized: string[]): ROE.ROEDocument {
  const roe = ROE.createTemplate("Acme", "Acme")
  roe.targets = targets
  roe.authorized_tools = authorized
  roe.expires_at = new Date(Date.now() + 30 * 86400_000).toISOString()
  ROE.sign(roe)
  return roe
}

describe("allowedMethodsFor / ROE-aware universe", () => {
  test("no ROE → full METHOD_UNIVERSE", () => {
    expect(Combinations.allowedMethodsFor("t")).toEqual(Combinations.METHOD_UNIVERSE)
  })

  test("null target → full METHOD_UNIVERSE (bench / unit path)", () => {
    expect(Combinations.allowedMethodsFor(null)).toEqual(Combinations.METHOD_UNIVERSE)
  })

  test("wildcard ROE authorized_tools → all methods still allowed", () => {
    signRoe(["t"], ["*"])
    expect(Combinations.allowedMethodsFor("t")).toEqual(Combinations.METHOD_UNIVERSE)
  })

  test("ROE authorized_tools=[GET,POST] → only those methods enumerated", () => {
    signRoe(["t"], ["GET", "POST"])
    const allowed = Combinations.allowedMethodsFor("t")
    expect(allowed).toContain("GET")
    expect(allowed).toContain("POST")
    expect(allowed).not.toContain("DELETE")
    expect(allowed).not.toContain("PUT")
  })

  test("methodGaps.missingMethods excludes ROE-forbidden methods", () => {
    signRoe(["t"], ["GET", "POST"])
    seedCell("t", "/x", "GET", "sqli", "safe")
    const gaps = Combinations.methodGaps(Coverage.load("t"))
    expect(gaps.length).toBe(1)
    expect(gaps[0]!.missingMethods).toEqual(["POST"])
    // DELETE / PUT / etc. are NOT in the missing list because ROE forbids them.
    expect(gaps[0]!.missingMethods).not.toContain("DELETE")
  })

  test("enumerateAllCombos shrinks with ROE — universe size proportional to allowed methods", () => {
    seedCell("t", "/x", "GET", "sqli", "safe")
    const beforeSize = Combinations.enumerateAllCombos(Coverage.load("t"), null).length
    signRoe(["t"], ["GET", "POST"])
    const afterSize = Combinations.enumerateAllCombos(Coverage.load("t")).length
    // 2/7 of METHOD_UNIVERSE is allowed → new size should be ~2/7 of the old one
    // (exact ratio depends on Checklist.forMethod applicability, so we only
    // require afterSize < beforeSize and both non-zero).
    expect(afterSize).toBeGreaterThan(0)
    expect(afterSize).toBeLessThan(beforeSize)
  })
})
