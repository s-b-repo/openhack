import { describe, expect, test } from "bun:test"
import { Knowledge } from "../src/knowledge"
import { Checklist } from "../src/checklist"

/**
 * Structural integrity for the vendored knowledge indexes.
 * - Every class-id used in the three indexes must exist in Checklist.all().
 * - Every PayloadsAllTheThings family entry has non-empty {id, hint, upstreamPath}.
 * - Every HackTricks URL points at book.hacktricks.wiki.
 * - Every WSTG id is a WSTG-prefixed dashed identifier.
 * - The three indexes carry a machine-parseable version string.
 * - Convenience accessors don't throw on unknown classes.
 */

const CHECKLIST_IDS = new Set(Checklist.ids())

describe("Knowledge — index integrity", () => {
  test("PayloadsAllTheThings: every class-id exists in Checklist", () => {
    const idx = Knowledge.load()
    for (const id of Object.keys(idx.payloadsAllTheThings)) {
      expect(CHECKLIST_IDS.has(id)).toBe(true)
    }
  })

  test("PayloadsAllTheThings: every family has non-empty {id, hint, upstreamPath}", () => {
    const idx = Knowledge.load()
    for (const [_classId, families] of Object.entries(idx.payloadsAllTheThings)) {
      expect(families.length).toBeGreaterThan(0)
      for (const f of families) {
        expect(f.id.length).toBeGreaterThan(0)
        expect(f.hint.length).toBeGreaterThan(0)
        expect(f.upstreamPath.length).toBeGreaterThan(0)
        // No duplicate family ids within a class.
        expect(families.filter((x) => x.id === f.id).length).toBe(1)
        // When weight is set, it's one of the three legal values.
        if (f.weight) expect(["high", "medium", "low"]).toContain(f.weight)
        // When exemplars are set, none is empty.
        if (f.exemplars) {
          expect(f.exemplars.length).toBeGreaterThan(0)
          for (const ex of f.exemplars) expect(typeof ex === "string" && ex.length > 0).toBe(true)
        }
      }
    }
  })

  test("PayloadsAllTheThings: top-severity classes carry at least one high-weight family", () => {
    for (const cls of ["sqli", "cmdi", "xss", "ssti", "ssrf", "xxe", "upload", "traversal-lfi", "auth", "deserialization"]) {
      const fams = Knowledge.payloadFamilies(cls)
      expect(fams.length).toBeGreaterThan(0)
      const anyHigh = fams.some((f) => f.weight === "high")
      expect(anyHigh).toBe(true)
    }
  })

  test("weightScore ranking: high > medium > low", () => {
    expect(Knowledge.weightScore("high")).toBeGreaterThan(Knowledge.weightScore("medium"))
    expect(Knowledge.weightScore("medium")).toBeGreaterThan(Knowledge.weightScore("low"))
  })

  test("familyExemplars returns curated payloads for high-severity families", () => {
    expect(Knowledge.familyExemplars("sqli", "time-blind").length).toBeGreaterThan(0)
    expect(Knowledge.familyExemplars("cmdi", "inline-unix").length).toBeGreaterThan(0)
    // Unknown family safely returns [].
    expect(Knowledge.familyExemplars("sqli", "no-such-family")).toEqual([])
  })

  test("familyWeight defaults to 'medium' when unset or unknown", () => {
    expect(Knowledge.familyWeight("sec-headers", "no-such")).toBe("medium")
  })

  test("HackTricks: URLs live on book.hacktricks.wiki", () => {
    const idx = Knowledge.load()
    for (const [id, entry] of Object.entries(idx.hacktricks)) {
      expect(CHECKLIST_IDS.has(id)).toBe(true)
      expect(entry.title.length).toBeGreaterThan(0)
      expect(entry.url.startsWith("https://book.hacktricks.wiki/")).toBe(true)
    }
  })

  test("WSTG: ids look like WSTG-XXXX", () => {
    const idx = Knowledge.load()
    for (const [id, wstg] of Object.entries(idx.wstg)) {
      expect(CHECKLIST_IDS.has(id)).toBe(true)
      expect(/^WSTG-[A-Z]+(-\d+)?$/.test(wstg)).toBe(true)
    }
  })

  test("Every version string looks like YYYY-MM-DD (or 'missing' when unindexed)", () => {
    const v = Knowledge.versions()
    for (const s of [v.payloads, v.hacktricks, v.wstg]) {
      expect(s.length).toBeGreaterThan(0)
      expect(/^(missing|unknown|\d{4}-\d{2}-\d{2})$/.test(s)).toBe(true)
    }
  })
})

describe("Knowledge — accessors", () => {
  test("payloadFamilies() on an unknown class returns []", () => {
    expect(Knowledge.payloadFamilies("no-such-class")).toEqual([])
  })

  test("payloadFamilies() on 'xss' returns the curated top families", () => {
    const fams = Knowledge.payloadFamilies("xss").map((f) => f.id)
    expect(fams).toContain("polyglot")
    expect(fams).toContain("dom-based")
  })

  test("hacktricks() on an unknown class returns undefined", () => {
    expect(Knowledge.hacktricks("no-such-class")).toBeUndefined()
  })

  test("wstgId() on an unknown class returns undefined", () => {
    expect(Knowledge.wstgId("no-such-class")).toBeUndefined()
  })

  test("forClass() bundles all three", () => {
    const bundle = Knowledge.forClass("sqli")
    expect(bundle.payloads.length).toBeGreaterThan(0)
    expect(bundle.hacktricks?.url.includes("sql-injection")).toBe(true)
    expect(bundle.wstg).toBe("WSTG-INPV-05")
  })

  test("indexedClassIds() returns a sorted union across all three indexes", () => {
    const ids = Knowledge.indexedClassIds()
    const sorted = [...ids].sort()
    expect(ids).toEqual(sorted)
    // We backfilled at least the top ~25.
    expect(ids.length).toBeGreaterThanOrEqual(25)
  })
})
