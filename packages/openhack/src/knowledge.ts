import * as fs from "node:fs"
import * as path from "node:path"
import * as url from "node:url"

/**
 * Vendored external-catalogue indexes:
 *
 *   • `payloadsallthethings-index.json` — taxonomy over swisskyrepo/PayloadsAllTheThings
 *     (MIT). Class-id → array of payload FAMILIES with a hint + upstream directory path.
 *     We index the *shape* of what families exist per class; the raw payload strings stay
 *     upstream (network / disk fetch is out of scope for this module).
 *   • `hacktricks-index.json` — book.hacktricks.wiki page URLs per class (CC-BY-4.0).
 *   • `wstg-index.json` — OWASP Web Security Testing Guide id per class (CC-BY-SA-4.0).
 *
 * All three are read once, cached in the module, and returned as read-only structures.
 * A malformed / missing index degrades to empty maps so the caller never crashes — a
 * fresh checkout without run `ingest-knowledge.ts` still boots. Reload with
 * `Knowledge.reload()` after the operator refreshes the indexes.
 */
export namespace Knowledge {
  export type Weight = "high" | "medium" | "low"

  export interface PayloadFamily {
    id: string
    hint: string
    upstreamPath: string
    /** Priority weight — the frontier scorer favors "high"-weighted families
     *  (RCE gadgets, auth-bypass polyglots, cloud-metadata) so the loop pursues
     *  high-impact combos before the informational tail. Absent → "medium". */
    weight?: Weight
    /** Small curated exemplar strings for this family. NOT the full payload
     *  catalogue — 1-4 representative examples so an agent has something
     *  concrete to send without cloning PayloadsAllTheThings first. Absent →
     *  the agent should consult upstreamPath. */
    exemplars?: string[]
  }

  export interface HacktricksEntry {
    title: string
    url: string
  }

  export interface Index {
    payloadsAllTheThings: Record<string, PayloadFamily[]>
    hacktricks: Record<string, HacktricksEntry>
    wstg: Record<string, string>
    payloadsVersion: string
    hacktricksVersion: string
    wstgVersion: string
  }

  // ── module-scoped cache ─────────────────────────────────────────────────
  let cached: Index | null = null

  /**
   * Path to the vendored JSON dir. Uses import.meta.url so it works whether
   * the package is installed under node_modules or symlinked in the workspace.
   */
  function dir(): string {
    // src/knowledge.ts → ../knowledge/
    const here = url.fileURLToPath(new URL(".", import.meta.url))
    return path.resolve(here, "..", "knowledge")
  }

  function readJson<T>(name: string, fallback: T): { data: T; version: string } {
    try {
      const raw = fs.readFileSync(path.join(dir(), name), "utf-8")
      const parsed = JSON.parse(raw)
      return { data: (parsed.byClass ?? parsed) as T, version: parsed.version ?? "unknown" }
    } catch {
      return { data: fallback, version: "missing" }
    }
  }

  export function load(): Index {
    if (cached) return cached
    const pat = readJson<Record<string, PayloadFamily[]>>("payloadsallthethings-index.json", {})
    const ht = readJson<Record<string, HacktricksEntry>>("hacktricks-index.json", {})
    const w = readJson<Record<string, string>>("wstg-index.json", {})
    cached = {
      payloadsAllTheThings: pat.data,
      hacktricks: ht.data,
      wstg: w.data,
      payloadsVersion: pat.version,
      hacktricksVersion: ht.version,
      wstgVersion: w.version,
    }
    return cached
  }

  /** Test-only: force the next load() to re-read the indexes from disk. */
  export function reload(): Index {
    cached = null
    return load()
  }

  // ── convenience accessors ────────────────────────────────────────────────

  /** Payload families known for a class-id. Empty array if the class isn't indexed. */
  export function payloadFamilies(classId: string): PayloadFamily[] {
    return load().payloadsAllTheThings[classId] ?? []
  }

  /** Weight for a family — defaults to "medium" when unset. */
  export function familyWeight(classId: string, familyId: string): Weight {
    const f = payloadFamilies(classId).find((f) => f.id === familyId)
    return f?.weight ?? "medium"
  }

  /** Numeric priority for a Weight — used to score frontier actions. */
  export function weightScore(w: Weight): number {
    return w === "high" ? 3 : w === "medium" ? 2 : 1
  }

  /** Curated exemplar payloads for a family; empty when unset. */
  export function familyExemplars(classId: string, familyId: string): string[] {
    return payloadFamilies(classId).find((f) => f.id === familyId)?.exemplars ?? []
  }

  /** HackTricks page for a class-id, or undefined if unindexed. */
  export function hacktricks(classId: string): HacktricksEntry | undefined {
    return load().hacktricks[classId]
  }

  /** WSTG id for a class-id (e.g. "WSTG-INPV-05"), or undefined. */
  export function wstgId(classId: string): string | undefined {
    return load().wstg[classId]
  }

  /** A single-shot bundle of all vendored references for a class. */
  export function forClass(classId: string): {
    payloads: PayloadFamily[]
    hacktricks?: HacktricksEntry
    wstg?: string
  } {
    return {
      payloads: payloadFamilies(classId),
      hacktricks: hacktricks(classId),
      wstg: wstgId(classId),
    }
  }

  /** Every class-id the taxonomy knows about (union of the three indexes). */
  export function indexedClassIds(): string[] {
    const idx = load()
    return Array.from(new Set([
      ...Object.keys(idx.payloadsAllTheThings),
      ...Object.keys(idx.hacktricks),
      ...Object.keys(idx.wstg),
    ])).sort()
  }

  /** Version strings for `openhack combos --version`. */
  export function versions(): { payloads: string; hacktricks: string; wstg: string } {
    const idx = load()
    return { payloads: idx.payloadsVersion, hacktricks: idx.hacktricksVersion, wstg: idx.wstgVersion }
  }
}
