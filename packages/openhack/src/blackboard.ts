import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"

/**
 * Inter-manager blackboard — the durable, polled channel the five phase-managers
 * use to message each other ("recon → exploitation: found /admin login, prioritize
 * authn bypass"). Findings are already shared via `.openhack/findings/`; this store
 * is for peer DIRECTIVES / HINTS / REQUESTS that don't fit the findings schema.
 *
 * Why a file store (not the in-process `GlobalBus`): every worker/manager step runs
 * as an isolated `openhack run` subprocess, so the only cross-process channel is a
 * durable one on disk, re-read at the round boundary. This mirrors `findings.ts`
 * exactly: HMAC-signed per record, atomic-mkdir advisory `withLock`, `.signing_key`
 * (0600), `safeTarget` filename — so parallel writers can't clobber each other.
 */
export namespace Blackboard {
  export type Phase = "recon" | "enumeration" | "exploitation" | "post-exploitation" | "c2" | "main"
  export type Kind = "directive" | "hint" | "request" | "ack"

  export interface Message {
    id: string
    timestamp: string
    round: number
    from: Phase
    /** A specific phase, or "all" for a broadcast (delivered to every phase but the sender). */
    to: Phase | "all"
    kind: Kind
    text: string
    /** Optional finding ids / node ids this message references. */
    refs: string[]
    status: "open" | "consumed"
    consumedBy?: string
    hmac: string
  }

  export interface Store {
    target: string
    messages: Message[]
    lastUpdated: string
  }

  const STORE_DIR = ".openhack/blackboard"

  function ensureDir(): void {
    if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true })
  }

  function safeTarget(target: string): string {
    return target.replace(/[^a-zA-Z0-9.-]/g, "_")
  }

  function getStorePath(target: string): string {
    return path.join(STORE_DIR, `${safeTarget(target)}.json`)
  }

  let signingKey: string | null = null

  function getSigningKey(): string {
    if (signingKey) return signingKey
    const keyPath = path.join(STORE_DIR, ".signing_key")
    try {
      signingKey = fs.readFileSync(keyPath, "utf-8").trim()
    } catch {
      signingKey = crypto.randomBytes(32).toString("hex")
      ensureDir()
      fs.writeFileSync(keyPath, signingKey, { encoding: "utf-8", mode: 0o600 })
    }
    return signingKey
  }

  /** HMAC over the immutable fields of a message (status/consumedBy are mutable, excluded). */
  function computeHMAC(m: Omit<Message, "hmac">, key: string): string {
    const content = JSON.stringify({
      id: m.id, timestamp: m.timestamp, round: m.round,
      from: m.from, to: m.to, kind: m.kind, text: m.text, refs: m.refs,
    })
    return crypto.createHmac("sha256", key).update(content).digest("hex")
  }

  function verifyHMAC(m: Message): boolean {
    const { hmac, ...rest } = m
    return computeHMAC(rest, getSigningKey()) === hmac
  }

  export function generateId(): string {
    const ts = Date.now().toString(36)
    const rand = crypto.randomBytes(4).toString("hex")
    return `MSG-${ts}-${rand}`
  }

  export function emptyStore(target: string): Store {
    return { target, messages: [], lastUpdated: new Date().toISOString() }
  }

  export function load(target: string): Store {
    ensureDir()
    const filepath = getStorePath(target)
    if (!fs.existsSync(filepath)) return emptyStore(target)
    try {
      const store: Store = JSON.parse(fs.readFileSync(filepath, "utf-8"))
      // Drop any tampered message (HMAC mismatch) — same policy as Findings.
      store.messages = (store.messages ?? []).filter((m) => {
        const valid = verifyHMAC(m)
        if (!valid) console.error(`[blackboard] HMAC verification failed for message ${m.id} — dropped.`)
        return valid
      })
      return store
    } catch {
      return emptyStore(target)
    }
  }

  export function save(store: Store): void {
    ensureDir()
    store.lastUpdated = new Date().toISOString()
    fs.writeFileSync(getStorePath(store.target), JSON.stringify(store, null, 2), { encoding: "utf-8", mode: 0o600 })
  }

  /**
   * Cross-process advisory lock (atomic mkdir) around a store mutation — a copy of
   * `Findings.withLock` so parallel manager/worker subprocesses can't clobber each
   * other. Reclaims a stale lock after 10s; forces through after ~15s.
   */
  export function withLock<T>(target: string, fn: () => T): T {
    ensureDir()
    const lock = path.join(STORE_DIR, `.lock-${safeTarget(target)}`)
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
          try { fs.rmSync(lock, { recursive: true, force: true }) } catch {}
          continue
        }
        try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25) } catch {}
      }
    }
    try {
      return fn()
    } finally {
      try { fs.rmSync(lock, { recursive: true, force: true }) } catch {}
    }
  }

  /**
   * Post one peer message. Atomic under the target lock: reload the on-disk store so a
   * concurrent writer's messages aren't lost, append, sign, persist. Returns the stored
   * message (with id/timestamp/hmac filled in).
   */
  export function post(
    target: string,
    msg: { round: number; from: Phase; to: Phase | "all"; kind: Kind; text: string; refs?: string[] },
  ): Message {
    return withLock(target, () => {
      const store = load(target)
      const base: Omit<Message, "hmac"> = {
        id: generateId(),
        timestamp: new Date().toISOString(),
        round: msg.round,
        from: msg.from,
        to: msg.to,
        kind: msg.kind,
        text: msg.text,
        refs: msg.refs ?? [],
        status: "open",
      }
      const message: Message = { ...base, hmac: computeHMAC(base, getSigningKey()) }
      store.messages.push(message)
      save(store)
      return message
    })
  }

  /**
   * Messages addressed to `phase` (or broadcast to "all"), excluding the phase's own
   * posts. `onlyOpen` (default true) hides already-consumed messages; `includeAll`
   * (default true) includes broadcasts.
   */
  export function inbox(
    target: string,
    phase: Phase,
    opts: { includeAll?: boolean; onlyOpen?: boolean } = {},
  ): Message[] {
    const includeAll = opts.includeAll !== false
    const onlyOpen = opts.onlyOpen !== false
    const store = load(target)
    return store.messages.filter((m) => {
      if (m.from === phase) return false
      const addressed = m.to === phase || (includeAll && m.to === "all")
      if (!addressed) return false
      if (onlyOpen && m.status !== "open") return false
      return true
    })
  }

  /** Mark the given message ids consumed by `by` (a phase/agent label). Idempotent. */
  export function markConsumed(target: string, ids: string[], by: string): void {
    if (!ids.length) return
    const idSet = new Set(ids)
    withLock(target, () => {
      const store = load(target)
      let changed = false
      for (const m of store.messages) {
        if (idSet.has(m.id) && m.status !== "consumed") {
          m.status = "consumed"
          m.consumedBy = by
          changed = true
        }
      }
      if (changed) save(store)
    })
  }

  /**
   * Drop consumed messages older than `keepRounds` rounds (open messages are always
   * kept so a directive is never lost before it's read). Bounds store growth.
   */
  export function prune(target: string, keepRounds: number, currentRound: number): void {
    withLock(target, () => {
      const store = load(target)
      const before = store.messages.length
      store.messages = store.messages.filter(
        (m) => m.status !== "consumed" || currentRound - m.round < Math.max(1, keepRounds),
      )
      if (store.messages.length !== before) save(store)
    })
  }

  /** Compact human/LLM-readable rendering of an inbox for a manager planner prompt. */
  export function formatInbox(msgs: Message[]): string {
    if (!msgs.length) return "(no peer messages)"
    return msgs
      .map((m) => {
        const refs = m.refs.length ? ` [refs: ${m.refs.join(", ")}]` : ""
        return `- (r${m.round}) ${m.from} → ${m.to} [${m.kind}]: ${m.text}${refs}`
      })
      .join("\n")
  }
}
