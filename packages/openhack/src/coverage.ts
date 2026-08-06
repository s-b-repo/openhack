import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"
import { Checklist } from "./checklist"

/**
 * Coverage tracking: which methodology cells (endpoint × HTTP method × vuln class)
 * have actually been tested, and with what result. This is what lets automode assert
 * "every type of test was done on every endpoint × method" and compute a real
 * completion percentage — driving the loop toward untested high-value cells instead
 * of stopping at the first convergence.
 *
 * Store: `.openhack/coverage/<target>.json` (plain signed-by-hash JSON, mode 0600).
 * Mirrors the findings-store layout so the two sit side by side.
 */
export namespace Coverage {
  export type Result = "untested" | "safe" | "vulnerable" | "inconclusive" | "blocked"

  export interface Cell {
    classId: string
    result: Result
    techniquesTested: string[]
    findingIds: string[]
    lastTested?: string
    notes?: string
    /**
     * Payload families from `packages/openhack/knowledge/payloadsallthethings-index.json`
     * that have already been sent against this cell. Consumed by
     * `Combinations.payloadFamilyGaps()` to detect "we tested SQLi with
     * boolean-blind but never tried time-blind or oob-dns" cases. Back-compat:
     * older on-disk stores don't carry this field; readers should treat it as `[]`.
     */
    payloadFamiliesTested?: string[]
  }

  export interface EndpointCoverage {
    endpoint: string // e.g. "/wp-json/wc/store/v1/checkout"
    method: string // GET/POST/...
    cells: Record<string, Cell> // keyed by classId
  }

  export interface Store {
    target: string
    createdAt: string
    lastUpdated: string
    endpoints: EndpointCoverage[]
    /** HMAC over the canonical digest — see `computeHmac` below. Absent on legacy
     *  plain-JSON stores; those load with a one-time warning and re-save signed. */
    hmac?: string
  }

  const DIR = path.join(".openhack", "coverage")
  const KEY_FILE = path.join(DIR, ".signing_key")

  function file(target: string): string {
    return path.join(DIR, `${target.replace(/[^a-zA-Z0-9.-]/g, "_")}.json`)
  }

  // ── HMAC signing ────────────────────────────────────────────────────────
  // Combinatorial-coverage state derives from this store; if the store can be
  // silently edited, the whole checklist can be gamed. Sign it with the same
  // pattern findings.ts uses so mutation is detectable.
  //
  // Cache keys by the ABSOLUTE dir path (not a single module-level slot). The
  // absolute path resolves against `process.cwd()` at call time, so switching
  // cwd (a common test pattern, and any long-running server that services
  // multiple engagements) does NOT reuse a stale key that a sibling cwd never
  // wrote to disk — the on-disk .signing_key stays the source of truth.
  const signingKeys = new Map<string, string>()
  function getSigningKey(): string {
    const absDir = path.resolve(DIR)
    const cached = signingKeys.get(absDir)
    if (cached) return cached
    fs.mkdirSync(absDir, { recursive: true })
    const keyPath = path.join(absDir, ".signing_key")
    let key: string
    try {
      key = fs.readFileSync(keyPath, "utf-8").trim()
    } catch {
      key = crypto.randomBytes(32).toString("hex")
      fs.writeFileSync(keyPath, key, { encoding: "utf-8", mode: 0o600 })
    }
    signingKeys.set(absDir, key)
    return key
  }

  /**
   * Canonical digest: target + endpoint × method × classId × result. Any change
   * to a Cell's result invalidates the HMAC; ordering-independent by sorting
   * endpoints and cells before hashing.
   */
  function digest(store: Store): string {
    const eps = [...store.endpoints]
      .sort((a, b) => (a.method + a.endpoint).localeCompare(b.method + b.endpoint))
      .map((ep) => {
        const cells = Object.keys(ep.cells).sort().map((k) => `${k}=${ep.cells[k]?.result ?? ""}`).join(",")
        return `${ep.method} ${ep.endpoint}#${cells}`
      })
      .join("|")
    return JSON.stringify({ target: store.target, eps })
  }

  export function computeHmac(store: Store): string {
    return crypto.createHmac("sha256", getSigningKey()).update(digest(store)).digest("hex")
  }

  export function verifyHmac(store: Store): boolean {
    if (!store.hmac) return false
    const expected = Buffer.from(computeHmac(store), "hex")
    let provided: Buffer
    try { provided = Buffer.from(store.hmac, "hex") } catch { return false }
    return expected.length === provided.length && crypto.timingSafeEqual(expected, provided)
  }

  export function empty(target: string): Store {
    const now = new Date().toISOString()
    const s: Store = { target, createdAt: now, lastUpdated: now, endpoints: [] }
    s.hmac = computeHmac(s)
    return s
  }

  export function load(target: string): Store {
    try {
      const parsed = JSON.parse(fs.readFileSync(file(target), "utf8")) as Store
      // Back-compat: pre-signing stores have no `hmac`. Accept once with a warning
      // and let the next save() sign them. This avoids an immediate drop that
      // would erase real coverage progress on upgrade.
      if (!parsed.hmac) {
        console.error(`[coverage] Unsigned legacy store for ${target} — accepting and re-signing on next save.`)
        return parsed
      }
      if (!verifyHmac(parsed)) {
        console.error(`[coverage] HMAC verification failed for ${target} — starting fresh (tampered snapshot dropped).`)
        return empty(target)
      }
      return parsed
    } catch {
      return empty(target)
    }
  }

  export function save(store: Store): void {
    fs.mkdirSync(DIR, { recursive: true })
    store.lastUpdated = new Date().toISOString()
    store.hmac = computeHmac(store)
    fs.writeFileSync(file(store.target), JSON.stringify(store, null, 2), { encoding: "utf8", mode: 0o600 })
  }

  /**
   * Immutable point-in-time snapshot of a coverage store under
   * `.openhack/coverage/snapshots/<safeTarget>/<label>.json`. Used by
   * `openhack combos diff <since>` to compute combos closed since a labelled
   * point (e.g. "after-round-3", "pre-hotfix"). Every snapshot is HMAC-signed
   * with the current signing key.
   */
  export function snapshot(target: string, label: string): string {
    fs.mkdirSync(DIR, { recursive: true })
    const store = load(target)
    const snapDir = path.join(DIR, "snapshots", target.replace(/[^a-zA-Z0-9.-]/g, "_"))
    fs.mkdirSync(snapDir, { recursive: true })
    const safeLabel = label.replace(/[^a-zA-Z0-9._-]/g, "_")
    const fp = path.join(snapDir, `${safeLabel}.json`)
    // The snapshot is a deep-copy — mutations to the live store must not touch it.
    fs.writeFileSync(fp, JSON.stringify(store, null, 2), { encoding: "utf-8", mode: 0o600 })
    return fp
  }

  /** Load a snapshot by label; returns null if absent. */
  export function loadSnapshot(target: string, label: string): Store | null {
    const snapDir = path.join(DIR, "snapshots", target.replace(/[^a-zA-Z0-9.-]/g, "_"))
    const safeLabel = label.replace(/[^a-zA-Z0-9._-]/g, "_")
    const fp = path.join(snapDir, `${safeLabel}.json`)
    try { return JSON.parse(fs.readFileSync(fp, "utf-8")) as Store } catch { return null }
  }

  /** List every snapshot label for a target, newest first (by mtime). */
  export function listSnapshots(target: string): Array<{ label: string; mtimeMs: number }> {
    const snapDir = path.join(DIR, "snapshots", target.replace(/[^a-zA-Z0-9.-]/g, "_"))
    try {
      return fs.readdirSync(snapDir)
        .filter((f) => f.endsWith(".json"))
        .map((f) => ({ label: f.slice(0, -5), mtimeMs: fs.statSync(path.join(snapDir, f)).mtimeMs }))
        .sort((a, b) => b.mtimeMs - a.mtimeMs)
    } catch { return [] }
  }

  /** Canonical "METHOD /endpoint" key. */
  export function key(endpoint: string, method: string): string {
    return `${method.toUpperCase()} ${endpoint}`
  }

  /** Register an endpoint (idempotent), seeding untested cells for every applicable class. */
  export function addEndpoint(store: Store, endpoint: string, method: string): EndpointCoverage {
    const m = method.toUpperCase()
    let ep = store.endpoints.find((e) => e.endpoint === endpoint && e.method === m)
    if (!ep) {
      ep = { endpoint, method: m, cells: {} }
      store.endpoints.push(ep)
    }
    for (const cls of Checklist.forMethod(m)) {
      if (!ep.cells[cls.id]) ep.cells[cls.id] = { classId: cls.id, result: "untested", techniquesTested: [], findingIds: [] }
    }
    return ep
  }

  /** Record a test result for one endpoint × method × class (creates the endpoint if new). */
  export function mark(
    store: Store,
    input: {
      endpoint: string
      method: string
      classId: string
      result: Result
      technique?: string
      findingIds?: string[]
      notes?: string
      /** Payload families exercised on this call. Dedup-merged into the cell. */
      payloadFamilies?: string[]
    },
  ): Store {
    const ep = addEndpoint(store, input.endpoint, input.method)
    const cell = ep.cells[input.classId] ?? { classId: input.classId, result: "untested", techniquesTested: [], findingIds: [] }
    cell.result = input.result
    cell.lastTested = new Date().toISOString()
    if (input.technique && !cell.techniquesTested.includes(input.technique)) cell.techniquesTested.push(input.technique)
    if (input.findingIds) for (const id of input.findingIds) if (!cell.findingIds.includes(id)) cell.findingIds.push(id)
    if (input.notes) cell.notes = input.notes
    if (input.payloadFamilies?.length) {
      const seen = new Set(cell.payloadFamiliesTested ?? [])
      for (const f of input.payloadFamilies) seen.add(f)
      cell.payloadFamiliesTested = [...seen]
    }
    ep.cells[input.classId] = cell
    save(store)
    return store
  }

  export interface Summary {
    endpoints: number
    cells: number
    tested: number
    untested: number
    vulnerable: number
    percent: number
  }

  export function summary(store: Store): Summary {
    let cells = 0, tested = 0, vulnerable = 0
    for (const ep of store.endpoints) {
      for (const cell of Object.values(ep.cells)) {
        cells++
        if (cell.result !== "untested") tested++
        if (cell.result === "vulnerable") vulnerable++
      }
    }
    return { endpoints: store.endpoints.length, cells, tested, untested: cells - tested, vulnerable, percent: cells ? Math.round((tested / cells) * 1000) / 10 : 0 }
  }

  /** Untested cells, so the loop (and `openhack coverage`) can target the gaps. */
  export function gaps(store: Store): Array<{ endpoint: string; method: string; classId: string; className: string }> {
    const out: Array<{ endpoint: string; method: string; classId: string; className: string }> = []
    for (const ep of store.endpoints) {
      for (const cell of Object.values(ep.cells)) {
        if (cell.result === "untested") out.push({ endpoint: ep.endpoint, method: ep.method, classId: cell.classId, className: Checklist.get(cell.classId)?.name ?? cell.classId })
      }
    }
    return out
  }
}
