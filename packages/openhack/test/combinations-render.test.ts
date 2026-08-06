import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Combinations } from "../src/combinations"
import { Coverage } from "../src/coverage"
import { Findings } from "../src/findings"
import { Checklist } from "../src/checklist"
import { Knowledge } from "../src/knowledge"

/**
 * Exhaustive-detail contract for the persisted markdown checklist. The
 * artefact is meant to stand alone as a report deliverable — these tests pin
 * the "everything and every combination in detail" invariants the user asked
 * for.
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-render-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

function seedCell(target: string, endpoint: string, method: string, classId: string, result: Coverage.Result, fams: string[] = []): void {
  let store = Coverage.load(target)
  store = Coverage.mark(store, {
    endpoint, method, classId, result,
    ...(fams.length ? { payloadFamilies: fams } : {}),
  })
}

function seedFinding(target: string, title: string, severity: Findings.Finding["severity"], component: string, description = "seeded"): void {
  const store = Findings.load(target)
  Findings.add(store, {
    id: "", timestamp: new Date().toISOString(),
    target, title, description,
    severity, status: "verified", source_agent: "test", source_session: "test",
    evidence_files: [], manual_verify_required: false, audit_trail: [],
    promotionChain: [], challengedByCouncils: [], hash: "", hmac: "", tags: [],
    affected_component: component,
    proof_of_concept: "curl … --data 'x=1'",
  })
}

describe("renderMarkdown — exhaustive detail", () => {
  test("overview table lists all six metric rows and total-open row", () => {
    seedCell("t", "/x", "GET", "sqli", "safe")
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    expect(md).toMatch(/\| Method-tuple gaps \| \d+ \|/)
    expect(md).toMatch(/\| Payload-family gaps \| \d+ \|/)
    expect(md).toMatch(/\| Chain-pair gaps \| \d+ \|/)
    expect(md).toMatch(/\| Findings inspected \| \d+ \|/)
    expect(md).toMatch(/\| Mathematical universe \| \d+ combos \|/)
    expect(md).toMatch(/\| Combos satisfied \| \d+ \|/)
    expect(md).toMatch(/\| Combos open \| \d+ \(\d+%\) \|/)
  })

  test("table of contents links all seven top-level sections", () => {
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    expect(md).toContain("(#1-method-tuple-coverage)")
    expect(md).toContain("(#2-payload-family-coverage-payloadsallthethings)")
    expect(md).toContain("(#3-chain-pair-coverage)")
    expect(md).toContain("(#4-per-relevant-finding-combinations)")
    expect(md).toContain("(#5-mathematical-universe-walk)")
    expect(md).toContain("(#6-legend--references)")
    expect(md).toContain("(#7-attributions)")
  })

  test("method-tuple section expands every missing method with applicable classes + refs", () => {
    seedCell("t", "/only-get", "GET", "sqli", "safe")
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    // Endpoint appears as a heading, missing methods each get an item, and
    // each missing method enumerates applicable classes with WSTG / HackTricks links.
    expect(md).toMatch(/### `\/only-get`/)
    expect(md).toContain("`POST`")
    expect(md).toContain("`DELETE`")
    // Applicable classes for the missing methods must be enumerated with refs.
    expect(md).toContain("HackTricks")
    expect(md).toContain("WSTG")
  })

  test("payload-family section enumerates every missing family with hint + upstream path + techniques", () => {
    seedCell("t", "/api", "POST", "sqli", "safe", ["error-based"])
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    // The heading includes the class name.
    expect(md).toContain("× **SQL injection**")
    // Every missing family shows its hint and upstreamPath.
    const missing = Knowledge.payloadFamilies("sqli").filter((f) => f.id !== "error-based")
    for (const f of missing) {
      expect(md).toContain(`\`${f.id}\``)
      expect(md).toContain(f.hint)
      expect(md).toContain(f.upstreamPath)
    }
    // Every Checklist technique for the class is enumerated too.
    for (const t of Checklist.get("sqli")!.techniques) {
      expect(md).toContain(`\`${t.id}\``)
    }
  })

  test("chain-pair section includes WSTG ids and HackTricks links for both sides when present", () => {
    seedCell("t", "/login", "POST", "sqli", "vulnerable")
    seedCell("t", "/login", "POST", "auth", "untested")
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    expect(md).toMatch(/SQL injection.*Authentication|Authentication.*SQL injection/is)
    expect(md).toContain("A: WSTG `WSTG-INPV-05`")
    // HackTricks references shown per pair.
    expect(md).toContain("HackTricks:")
  })

  test("per-finding section decomposes each finding into L1 / L2 / L3 shells with counts", () => {
    seedCell("t", "/login", "POST", "sqli", "vulnerable")
    seedFinding("t", "SQL injection at login", "critical", "https://example.com/login")
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    expect(md).toMatch(/🔴 CRITICAL — SQL injection at login/)
    expect(md).toContain("L1 — same endpoint × same class")
    expect(md).toContain("L2 — same endpoint × chain-hint class")
    expect(md).toContain("L3 — same class × other endpoints")
    // Counts appear in the aggregate line.
    expect(md).toMatch(/Missing combos in neighbourhood: \*\*\d+\*\* \(L1 \d+ · L2 \d+ · L3 \d+\)/)
    // Class + chain hints + Inferred endpoint all surfaced.
    expect(md).toContain("class: **sqli**")
    expect(md).toContain("Inferred endpoint: `/login`")
    expect(md).toContain("chains with:")
  })

  test("mathematical-universe walk enumerates every combo with ✓ / [ ] status", () => {
    seedCell("t", "/api", "POST", "sqli", "safe", ["error-based"])
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    // Section heading present.
    expect(md).toContain("Mathematical universe walk")
    // At least one satisfied and one open combo must appear.
    expect(md).toContain("✓")
    expect(md).toContain("[ ]")
    // Cell heading includes the class name.
    expect(md).toContain("× **SQL injection**")
  })

  test("legend section documents ✓ / [ ] / L1-L2-L3 / METHOD_UNIVERSE explicitly", () => {
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    expect(md).toContain("`✓`")
    expect(md).toContain("`[ ]`")
    expect(md).toContain("L1 / L2 / L3")
    expect(md).toContain("METHOD_UNIVERSE")
  })

  test("attributions section names the three sources with URLs", () => {
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    expect(md).toContain("PayloadsAllTheThings")
    expect(md).toContain("swisskyrepo")
    expect(md).toContain("book.hacktricks.wiki")
    expect(md).toContain("owasp.org/www-project-web-security-testing-guide")
  })

  test("nothing is truncated — no `… +N more` markers in the persisted markdown", () => {
    // Seed a very wide surface to bait the old cap of 60 groups.
    for (let i = 0; i < 80; i++) {
      seedCell("t", `/ep-${i}`, "POST", "sqli", "vulnerable")
    }
    seedFinding("t", "SQLi everywhere", "critical", "/ep-0")
    const md = Combinations.renderMarkdown(Combinations.checklist("t"))
    // The old renderer emitted "… +N more". The new one must not.
    expect(md).not.toMatch(/… \+\d+ more/)
  })
})
