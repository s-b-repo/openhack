import { describe, expect, test } from "bun:test"
import { Checklist } from "../src/checklist"
import { Knowledge } from "../src/knowledge"

/**
 * The augmentation table on Checklist adds `chainHints`, `wstgId`, and
 * `hacktricksSlug` to declared classes. These tests guard the cross-references:
 *   - every chainHint id must resolve to a known class
 *   - every hacktricksSlug must resolve in the vendored HackTricks index
 *   - every wstgId must look like WSTG-XXX
 *   - existing helpers (`all`, `get`, `byCategory`, `forMethod`) all return the
 *     augmented shape, not raw CLASSES
 */

const CHECKLIST_IDS = new Set(Checklist.ids())

describe("Checklist — augmentation", () => {
  test("every chainHint refers to a known class id", () => {
    for (const c of Checklist.all()) {
      for (const hint of c.chainHints ?? []) {
        expect(CHECKLIST_IDS.has(hint)).toBe(true)
      }
    }
  })

  test("every hacktricksSlug resolves in the HackTricks index", () => {
    const idx = Knowledge.load()
    for (const c of Checklist.all()) {
      if (!c.hacktricksSlug) continue
      expect(idx.hacktricks[c.hacktricksSlug]).toBeDefined()
    }
  })

  test("every wstgId matches WSTG-* form", () => {
    for (const c of Checklist.all()) {
      if (!c.wstgId) continue
      expect(/^WSTG-[A-Z]+(-\d+)?$/.test(c.wstgId)).toBe(true)
    }
  })

  test("at least 15 classes are backfilled with chainHints", () => {
    const backfilled = Checklist.all().filter((c) => (c.chainHints?.length ?? 0) > 0)
    expect(backfilled.length).toBeGreaterThanOrEqual(15)
  })

  test("get() returns augmented shape", () => {
    const c = Checklist.get("sqli")!
    expect(c.chainHints).toBeDefined()
    expect(c.wstgId).toBe("WSTG-INPV-05")
    expect(c.hacktricksSlug).toBe("sqli")
  })

  test("byCategory('injection') returns augmented entries", () => {
    const inj = Checklist.byCategory("injection")
    expect(inj.length).toBeGreaterThan(0)
    // Every entry either has chainHints (backfilled) or is a niche class — never
    // silently loses the field.
    for (const c of inj) {
      if (c.id === "sqli") expect(c.chainHints).toBeDefined()
    }
  })

  test("forMethod('POST') returns augmented entries", () => {
    const post = Checklist.forMethod("POST")
    const sqli = post.find((c) => c.id === "sqli")
    expect(sqli).toBeDefined()
    expect(sqli!.chainHints).toContain("auth")
  })
})
