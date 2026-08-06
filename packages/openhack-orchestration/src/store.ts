import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"
import type { AttackGraphSnapshot, Edge, NodeId, NodeUnion } from "./types"

/**
 * Persistence + integrity for AttackGraph snapshots.
 *
 * One JSON per target at `.openhack/graph/<safeTarget>.json`, mode 0600, keyed
 * with an HMAC over a canonical *structural* digest (sorted node ids + kinds,
 * sorted edge triples). Any post-write tampering — hand-edit, disk corruption,
 * or an attacker replacing nodes — mismatches the HMAC and `load()` returns a
 * fresh empty snapshot with a stderr warning (parity with `Findings.load`).
 *
 * The advisory `withLock` mirrors the findings lock exactly so the two stores
 * behave the same under parallel subprocess writers.
 */
export namespace GraphStore {
  const DIR = path.join(".openhack", "graph")
  const KEY_FILE = path.join(DIR, ".signing_key")

  function ensureDir(): void {
    if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true })
  }

  function safe(target: string): string {
    return target.replace(/[^a-zA-Z0-9.-]/g, "_")
  }

  export function filePath(target: string): string {
    return path.join(DIR, `${safe(target)}.json`)
  }

  // -------- Signing key (module-cached; 0600 on first materialization) ------

  let signingKey: string | null = null
  /**
   * The same key that HMAC-signs the AttackGraph. Exported so sibling stores
   * in this package (Scores, future extensions) can reuse the same signing
   * material — one keyfile per engagement, one tamper trust root.
   */
  export function getSigningKey(): string {
    if (signingKey) return signingKey
    ensureDir()
    try {
      signingKey = fs.readFileSync(KEY_FILE, "utf-8").trim()
    } catch {
      signingKey = crypto.randomBytes(32).toString("hex")
      fs.writeFileSync(KEY_FILE, signingKey, { encoding: "utf-8", mode: 0o600 })
    }
    return signingKey!
  }

  // -------- Canonical digest & HMAC ----------------------------------------

  /**
   * Structural digest over what actually matters for integrity: the target,
   * the last round, and the *shape* of the graph (node ids + kinds, edge
   * triples), each sorted so JSON key ordering / edge insertion order cannot
   * change the signature.
   */
  function digest(snap: {
    target: string
    lastRound: number
    nodes: Record<NodeId, NodeUnion>
    edges: Edge[]
  }): string {
    const nodeKeys = Object.keys(snap.nodes)
      .sort()
      .map((id) => `${id}|${(snap.nodes[id] as any).kind ?? (id.startsWith("finding:") ? "finding" : "action")}`)
      .join(";")
    const edgeKeys = [...snap.edges]
      .map((e) => `${e.from}|${e.kind}|${e.to}`)
      .sort()
      .join(";")
    return JSON.stringify({ target: snap.target, lastRound: snap.lastRound, nodeKeys, edgeKeys })
  }

  export function computeHmac(snap: AttackGraphSnapshot): string {
    return crypto.createHmac("sha256", getSigningKey()).update(digest(snap)).digest("hex")
  }

  export function verifyHmac(snap: AttackGraphSnapshot): boolean {
    if (!snap.hmac) return false
    const expected = Buffer.from(computeHmac(snap), "hex")
    let provided: Buffer
    try {
      provided = Buffer.from(snap.hmac, "hex")
    } catch {
      return false
    }
    return expected.length === provided.length && crypto.timingSafeEqual(expected, provided)
  }

  // -------- IO -------------------------------------------------------------

  export function empty(target: string): AttackGraphSnapshot {
    const now = new Date().toISOString()
    const snap: AttackGraphSnapshot = {
      target,
      createdAt: now,
      lastRound: 0,
      nodes: {},
      edges: [],
      hmac: "",
    }
    snap.hmac = computeHmac(snap)
    return snap
  }

  export function load(target: string): AttackGraphSnapshot {
    ensureDir()
    const fp = filePath(target)
    if (!fs.existsSync(fp)) return empty(target)
    try {
      const snap = JSON.parse(fs.readFileSync(fp, "utf-8")) as AttackGraphSnapshot
      if (!verifyHmac(snap)) {
        console.error(`[graph] HMAC verification failed for ${target} — snapshot dropped, starting fresh.`)
        return empty(target)
      }
      return snap
    } catch {
      return empty(target)
    }
  }

  export function save(snap: AttackGraphSnapshot): void {
    ensureDir()
    snap.hmac = computeHmac(snap)
    fs.writeFileSync(filePath(snap.target), JSON.stringify(snap, null, 2), {
      encoding: "utf-8",
      mode: 0o600,
    })
  }

  // -------- Advisory lock (mirrors Findings.withLock exactly) --------------

  /**
   * Cross-process advisory lock (atomic mkdir) around a mutation. 15 s wait,
   * 10 s stale reclaim. Used from the loop driver so a graph write from one
   * automode subprocess doesn't clobber a concurrent one.
   */
  export function withLock<T>(target: string, fn: () => T): T {
    ensureDir()
    const lock = path.join(DIR, `.lock-${safe(target)}`)
    const start = Date.now()
    for (;;) {
      try {
        fs.mkdirSync(lock)
        break
      } catch {
        try {
          if (Date.now() - fs.statSync(lock).mtimeMs > 10_000) fs.rmSync(lock, { recursive: true, force: true })
        } catch {}
        if (Date.now() - start > 15_000) {
          try {
            fs.rmSync(lock, { recursive: true, force: true })
          } catch {}
          continue
        }
        try {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25)
        } catch {}
      }
    }
    try {
      return fn()
    } finally {
      try {
        fs.rmSync(lock, { recursive: true, force: true })
      } catch {}
    }
  }
}
