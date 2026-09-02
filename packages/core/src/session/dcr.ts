export * as SessionDcr from "./dcr"

import { execFile } from "node:child_process"
import { mkdir, writeFile } from "node:fs/promises"
import path from "node:path"
import { Effect } from "effect"
import { Global } from "../global"
import { Config } from "../config"
import { Token } from "../util/token"
import { SessionMessage } from "./message"
import { SessionSchema } from "./schema"
import { serialize as serializeMessage } from "./compaction"

/**
 * Dynamic Context Runtime bridge over the reference implementation
 * (github.com/s-b-repo/subnext, DCR-TR-2026-01).
 *
 * History is stored as immutable spans in a per-session turns directory and
 * indexed by the `dcr` binary; each turn the runtime plans a budgeted working
 * set for the model. The Memory Runtime makes zero model calls: the host
 * session stays the reasoner and receives only the planned working set plus a
 * small verbatim recent tail instead of the full transcript.
 *
 * Any runtime failure degrades the turn to the legacy full-history path — never
 * silently: the failure is recorded per session (`degradation`) and surfaced by
 * the caller — and compaction still guards provider overflow.
 *
 * Two session runtimes share this one context system: the V2 `SessionRunner`
 * projects core `SessionMessage` entries (`assemble`), and the V1
 * `SessionPrompt` projects `SessionV1.WithParts` (`assembleSpans`). Both lower
 * to the same engine, budget model, escalation protocol and degradation
 * contract.
 */

/** A wedged runtime degrades the turn to the legacy full-history path. */
const ENGINE_TIMEOUT_MS = 5_000
const MAX_ENGINES = 32

type Entry = {
  readonly seq: number
  readonly message: SessionMessage.Message
}

export type Settings = {
  readonly enabled: boolean
  readonly bin: string
  readonly budget: number
  readonly recentTokens: number
}

const DEFAULTS: Settings = {
  enabled: process.env.DCR_ENABLED === "1",
  bin: process.env.DCR_BIN ?? "dcr",
  budget: 1200,
  recentTokens: 4_000,
}

/**
 * Engine resolution, mirroring the Lattice pattern:
 *   1. an absolute/explicit `bin` from config or $DCR_BIN — used as-is
 *   2. the vendored reference implementation at <repo>/vendor/subnext/bin/dcr
 *      (bootstrap with `vendor/subnext/bootstrap.sh`)
 *   3. a bare name resolved on PATH
 */
export const resolveEngineBin = async (bin: string): Promise<string> => {
  if (bin.includes("/")) return bin
  let directory = process.cwd()
  for (let depth = 0; depth < 8; depth++) {
    const candidate = path.join(directory, "vendor", "subnext", "bin", bin)
    if (await Bun.file(candidate).exists()) return candidate
    const parent = path.dirname(directory)
    if (parent === directory) break
    directory = parent
  }
  return bin
}

export const settings = (documents: readonly Config.Entry[]) =>
  documents
    .filter((entry): entry is Config.Document => entry.type === "document")
    .flatMap((entry) => (entry.info.dcr ? [entry.info.dcr] : []))
    .reduce<Settings>(
      (result, current) => ({
        enabled: current.enabled ?? result.enabled,
        bin: current.bin ?? result.bin,
        budget: current.budget ?? result.budget,
        recentTokens: current.recentTokens ?? result.recentTokens,
      }),
      DEFAULTS,
    )

const run = (bin: string, args: string[]): Promise<string> =>
  new Promise((resolve, reject) => {
    execFile(bin, args, { timeout: ENGINE_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 }, (error, stdout) => {
      if (error) reject(error instanceof Error ? error : new Error(String(error)))
      else resolve(stdout)
    })
  })

/**
 * Model-facing escalation request (§3.7): `#ESCALATE <node_id>`.
 * Duplicated ids collapse; order is preserved.
 */
export const escalations = (text: string): string[] => {
  const ids: string[] = []
  for (const match of text.matchAll(/#ESCALATE\s+([A-Za-z0-9_.:-]+)/g)) {
    const nodeID = match[1]
    if (nodeID && !ids.includes(nodeID)) ids.push(nodeID)
  }
  return ids
}

/** Message kinds that lower to a user-role provider turn and may open resent history. */
const boundaryTypes = new Set(["user", "synthetic", "compaction", "shell"])

/**
 * Escalations still owed to the model: `#ESCALATE` tokens found in assistant
 * replies after the latest user-role boundary — requests raised during the
 * current exchange that this turn's plan must honour at raw fidelity.
 */
export const pendingEscalations = (entries: readonly Entry[]): string[] => {
  const ids: string[] = []
  for (let index = entries.length - 1; index >= 0; index--) {
    const message = entries[index].message
    if (boundaryTypes.has(message.type)) break
    if (message.type !== "assistant") continue
    for (const part of message.content) {
      if (part.type !== "text") continue
      for (const nodeID of escalations(part.text)) if (!ids.includes(nodeID)) ids.push(nodeID)
    }
  }
  return ids
}

export const recentTail = (entries: readonly Entry[], tokens: number) => {
  const start = recentWindowStart(
    entries.map((entry) => Token.estimate(serializeMessage(entry.message))),
    entries.map((entry) => boundaryTypes.has(entry.message.type)),
    tokens,
  )
  if (start === "full") return [...entries]
  return entries.slice(start)
}

/**
 * Shared recent-window math for both assembly paths: walk back from the newest
 * entry while the token budget allows (always keeping at least the newest), then
 * — providers reject visible history opening on an assistant turn — slide the
 * window start forward to the next boundary. If no boundary exists ahead, the
 * window is invalid and the caller falls back to full history.
 */
const recentWindowStart = (
  costs: readonly number[],
  boundaries: readonly boolean[],
  budget: number,
): number | "full" => {
  let start = costs.length
  let total = 0
  while (start > 0) {
    const cost = costs[start - 1]
    if (total + cost > budget && start < costs.length) break
    total += cost
    start--
  }
  if (start === 0) return 0
  if (boundaries[start]) return start
  while (start < costs.length && !boundaries[start]) start++
  if (start >= costs.length) return "full"
  return start
}

export type Assembled = {
  /** Budgeted working set rendered by the runtime, addressed to the model. */
  readonly rendered: string
  /** Tokens used by the working set against B_attention. */
  readonly tokens: number
  /** Verbatim messages kept in full alongside the working set. */
  readonly recentMessages: SessionMessage.Message[]
  /** Corrections detected during ingest this turn. */
  readonly corrections: ReadonlyArray<{ superseded: string; by: string }>
}

/**
 * Projection of one history entry for the span-based assembly path. The V2
 * runner projects its `SessionMessage` entries; the V1 `SessionPrompt` projects
 * `SessionV1.WithParts`. Both lower to the same engine, the same budget model
 * and the same degradation contract — one context system at every level.
 */
export type Span<T = unknown> = {
  /** The original entry, returned verbatim in `AssembledSpans.recent`. */
  readonly item: T
  /** Stable unique id (V2: derived from seq; V1: the message id). */
  readonly id: string
  /** Opens a resent-history window (user-role boundary). */
  readonly boundary: boolean
  /** Assistant turn — the only place `#ESCALATE` tokens are collected. */
  readonly assistant: boolean
  /** Serialized text of the entry. */
  readonly text: string
}

export type AssembledSpans<T> = {
  /** Budgeted working set rendered by the runtime, addressed to the model. */
  readonly rendered: string
  /** Tokens used by the working set against B_attention. */
  readonly tokens: number
  /** Original items of the verbatim recent window. */
  readonly recent: readonly T[]
  /** Corrections detected during ingest this turn. */
  readonly corrections: ReadonlyArray<{ superseded: string; by: string }>
}

// ─── degradation observability ────────────────────────────────────────────────
// The bridge never throws — a wedged runtime degrades the turn to the legacy
// full-history path — but nothing degrades silently: every failure is recorded
// per session and surfaced by the caller (Effect log / plugin diagnostics).

export type Degradation = {
  readonly sessionID: string
  readonly stage: string
  readonly at: number
  readonly error: string
}

const degradations = new Map<string, Degradation>()
const degradationCounts = new Map<string, number>()

/** Latest degradation for a session, if any (undefined = healthy or disabled). */
export const degradation = (sessionID: string): Degradation | undefined => degradations.get(sessionID)

/** Total degradations ever recorded for a session. */
export const degradationCount = (sessionID: string): number => degradationCounts.get(sessionID) ?? 0

const recordDegradation = (sessionID: string, stage: string, error: unknown) => {
  degradations.set(sessionID, {
    sessionID,
    stage,
    at: Date.now(),
    error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
  })
  degradationCounts.set(sessionID, (degradationCounts.get(sessionID) ?? 0) + 1)
}

class Engine {
  private ready?: Promise<void>

  constructor(
    private readonly bin: string,
    private readonly store: string,
    private readonly turns: string,
    private readonly budget: number,
  ) {}

  /**
   * One immutable file per ingested message seq; the directory ingest walks it
   * in modification-time order, which is revision order (§3.4). Role markers
   * (`[User]: `, `[Tool result]: `) are stripped per line — the runtime ingests
   * documents, and the prefixes would defeat its conservative extractor.
   */
  async write(entry: Entry): Promise<void> {
    await this.ensure()
    const text = serializeMessage(entry.message).replace(/^\[[^\]\n]+\]:\s?/gm, "")
    await writeFile(path.join(this.turns, `m${entry.seq}.txt`), text)
  }

  /**
   * Span-based write: the caller projects its entries to stable ids; the file
   * name is a deterministic hash of the id so re-ingesting the same message is
   * idempotent and the directory ingest keeps modification-time revision order.
   * Role markers are stripped exactly as in `write` — the runtime ingests
   * documents, and the prefixes would defeat its conservative extractor.
   */
  async writeSpan(fileID: string, text: string): Promise<void> {
    await this.ensure()
    await writeFile(path.join(this.turns, `${fileID}.txt`), text.replace(/^\[[^\]\n]+\]:\s?/gm, ""))
  }

  async ingest(): Promise<ReadonlyArray<{ superseded: string; by: string }>> {
    await this.ensure()
    const stdout = await run(this.bin, ["--store", this.store, "--budget", String(this.budget), "ingest", this.turns])
    // Contradiction lines name graph node ids; resolve them to values so the
    // NOTE block annotates facts rather than opaque identifiers. Best-effort —
    // an unresolved id is still reported, just less readable.
    const resolve = async (nodeID: string) => {
      try {
        const explained = await run(this.bin, ["--store", this.store, "--budget", String(this.budget), "explain", nodeID])
        const claim = /^- \[.*?\]\s+\w+:\s*(.+)$/m.exec(explained)?.[1]
        if (claim) return claim.trim()
      } catch {}
      return nodeID
    }
    const corrections: Array<{ superseded: string; by: string }> = []
    for (const match of stdout.matchAll(/^\s*contradiction:\s*(\S+)\s+superseded by\s+(\S+)\s*$/gm)) {
      const [supersededID, byID] = [match[1] ?? "", match[2] ?? ""]
      corrections.push({ superseded: await resolve(supersededID), by: await resolve(byID) })
    }
    return corrections
  }

  async plan(query: string): Promise<string> {
    await this.ensure()
    return (await run(this.bin, ["--store", this.store, "--budget", String(this.budget), "plan", query])).trim()
  }

  dispose() {
    this.ready = undefined
  }

  private ensure(): Promise<void> {
    const existing = this.ready
    if (existing) return existing
    const ready = mkdir(this.turns, { recursive: true }).then(() => undefined)
    ready.catch(() => {
      if (this.ready === ready) this.ready = undefined
    })
    this.ready = ready
    return ready
  }
}

const engines = new Map<string, Engine>()
const ingestedThrough = new Map<string, number>()
/** Span-path ingest watermark: ids already written to the turns directory. */
const ingestedSpanIDs = new Map<string, Set<string>>()

const engineRoot = (sessionID: SessionSchema.ID) => path.join(Global.Path.data, "dcr", sessionID)

const acquire = (sessionID: SessionSchema.ID, settingsValue: Settings) => {
  const existing = engines.get(sessionID)
  if (existing) return existing
  const root = engineRoot(sessionID)
  const created = new Engine(settingsValue.bin, path.join(root, "memory.dcr.json"), path.join(root, "turns"), settingsValue.budget)
  engines.set(sessionID, created)
  if (engines.size > MAX_ENGINES) {
    const oldest = engines.keys().next().value
    if (oldest !== undefined && oldest !== sessionID) {
      engines.get(oldest)?.dispose()
      engines.delete(oldest)
      ingestedThrough.delete(oldest)
    }
  }
  return created
}

const queryOf = (entries: readonly Entry[]) => {
  for (let index = entries.length - 1; index >= 0; index--) {
    const message = entries[index].message
    if (message.type === "user") return message.text
  }
  return ""
}

const ingestNew = async (engine: Engine, sessionID: SessionSchema.ID, entries: readonly Entry[]) => {
  const through = ingestedThrough.get(sessionID) ?? 0
  let highest = through
  for (const entry of entries) {
    if (entry.seq <= through) continue
    highest = Math.max(highest, entry.seq)
    await engine.write(entry)
  }
  if (highest === through) return []
  const corrections = await engine.ingest()
  ingestedThrough.set(sessionID, Math.max(highest, through))
  return corrections
}

const forget = (sessionID: SessionSchema.ID) => {
  engines.get(sessionID)?.dispose()
  engines.delete(sessionID)
  ingestedThrough.delete(sessionID)
  ingestedSpanIDs.delete(sessionID)
  // Degradation records intentionally survive `forget`: the caller inspects
  // them right after a failed assemble to surface the reason. They are cleared
  // with `disposeAll` (runner teardown) instead.
}

/**
 * Outstanding escalations that name one of our spans (`m<seq>`) are serviced
 * host-side: the raw bytes join the window ahead of the plan, charged against
 * B_attention first (§3.7). Foreign node ids belong to the runtime's graph and
 * ride its own routing.
 */
const serviceEscalations = (
  entries: readonly Entry[],
  ids: readonly string[],
  budget: number,
): { pinned: string; spent: number } => {
  let spent = 0
  const lines: string[] = []
  for (const id of ids) {
    const match = /^m(\d+)$/.exec(id)
    if (!match) continue
    const entry = entries.find((candidate) => candidate.seq === Number(match[1]))
    if (!entry) continue
    const text = `[${id}] ${serializeMessage(entry.message)}`
    const cost = Token.estimate(text)
    if (spent + cost > budget) break
    spent += cost
    lines.push(text)
  }
  return { pinned: lines.join("\n"), spent }
}

export const assemble = async (input: {
  sessionID: SessionSchema.ID
  entries: readonly Entry[]
  settings: Settings
  /** Node ids the model asked to see at raw fidelity this turn (§3.7). */
  escalate?: readonly string[]
}): Promise<Assembled | undefined> => {
  if (!input.settings.enabled || input.entries.length === 0) return undefined
  try {
    const engine = acquire(input.sessionID, { ...input.settings, bin: await resolveEngineBin(input.settings.bin) })
    const corrections = await ingestNew(engine, input.sessionID, input.entries)
    const query = queryOf(input.entries)
    if (!query.trim()) return undefined
    const planned = await engine.plan(query)

    const escalation = pendingEscalations(input.entries)
    const pinned = escalation.length > 0 ? serviceEscalations(input.entries, escalation, input.settings.budget) : { pinned: "", spent: 0 }
    const rendered = [pinned.pinned, planned].filter((section) => section.length > 0).join("\n")
    if (!rendered.trim()) return undefined
    return {
      rendered,
      tokens: Math.min(input.settings.budget, pinned.spent + Token.estimate(planned)),
      recentMessages: recentTail(input.entries, input.settings.recentTokens).map((entry) => entry.message),
      corrections,
    }
  } catch (error) {
    recordDegradation(input.sessionID, "assemble", error)
    forget(input.sessionID)
    return undefined
  }
}

/** Effect wrapper: never fails — DCR problems degrade to `undefined`. */
export const assembleEffect = (input: {
  sessionID: SessionSchema.ID
  entries: readonly Entry[]
  settings: Settings
  escalate?: readonly string[]
}) =>
  input.settings.enabled ? Effect.promise(() => assemble(input)) : Effect.succeed(undefined)

export const block = (assembled: Assembled | AssembledSpans<unknown>) =>
  [
    `<session-context engine="dcr" tokens="${assembled.tokens}">`,
    "Runtime-assembled working set distilled from earlier in this session.",
    "Every fact below traces to source spans; values marked NOTE were corrected later.",
    "",
    assembled.rendered,
    // Corrections are annotated rather than hidden (§3.4): a superseded value
    // that still appears in rendered material must reach the model marked, or a
    // settled contradiction walks back into the window unflagged.
    ...(assembled.corrections.length > 0
      ? [
          "",
          "NOTE — corrected values:",
          ...assembled.corrections.map(
            (correction) => `- "${correction.superseded}" was corrected later; current value in: ${correction.by}`,
          ),
        ]
      : []),
    "</session-context>",
  ].join("\n")

/** Dispose every tracked engine and its ingest watermark. */
export const disposeAll = () => {
  for (const engine of engines.values()) engine.dispose()
  engines.clear()
  ingestedThrough.clear()
  ingestedSpanIDs.clear()
  degradations.clear()
  degradationCounts.clear()
}

export const disposeSession = (sessionID: SessionSchema.ID) => forget(sessionID)

// ─── span-based assembly (shared context system for every session runtime) ───

/**
 * Deterministic, filesystem-safe span file id (`m<128-bit-ish hex>`) derived
 * from the source id. Stable across processes so re-ingesting the same message
 * is idempotent, and collision-resistant (two independent FNV-1a rounds).
 */
export const spanFileID = (id: string): string => {
  let h1 = 0x811c9dc5
  let h2 = 0x01000193
  for (let index = 0; index < id.length; index++) {
    const char = id.charCodeAt(index)
    h1 = Math.imul(h1 ^ char, 0x01000193) >>> 0
    h2 = Math.imul(h2 ^ (char + index), 0x85ebca6b) >>> 0
  }
  return `m${h1.toString(16)}${h2.toString(16)}`
}

/**
 * `#ESCALATE` tokens still owed to the model on the span path: found in
 * assistant spans after the latest boundary — same contract as
 * `pendingEscalations`, over projected spans.
 */
export const pendingEscalationsSpans = (spans: readonly Span<any>[]): string[] => {
  const ids: string[] = []
  for (let index = spans.length - 1; index >= 0; index--) {
    const span = spans[index]
    if (span.boundary) break
    if (!span.assistant) continue
    for (const nodeID of escalations(span.text)) if (!ids.includes(nodeID)) ids.push(nodeID)
  }
  return ids
}

/**
 * Host-side servicing of `#ESCALATE` requests that name one of our span files
 * (`m<hash>`): the raw bytes join the window ahead of the plan, charged against
 * B_attention first (§3.7). Foreign node ids ride the runtime's own routing.
 */
const serviceEscalationsSpans = (
  spans: readonly Span<any>[],
  ids: readonly string[],
  budget: number,
): { pinned: string; spent: number } => {
  const byFile = new Map(spans.map((span) => [spanFileID(span.id), span]))
  let spent = 0
  const lines: string[] = []
  for (const id of ids) {
    const match = /^(m[0-9a-f]+)$/.exec(id)
    if (!match) continue
    const span = byFile.get(match[1])
    if (!span) continue
    const text = `[${id}] ${span.text}`
    const cost = Token.estimate(text)
    if (spent + cost > budget) break
    spent += cost
    lines.push(text)
  }
  return { pinned: lines.join("\n"), spent }
}

/**
 * Span-based assembly — the same DCR contract as `assemble`, over caller-
 * projected entries. Used by the V1 `SessionPrompt` runtime (projecting
 * `SessionV1.WithParts`); the V2 runner keeps `assemble` over core messages.
 * Degrades to `undefined` on any failure, recording a `Degradation` so nothing
 * fails silently.
 */
export const assembleSpans = async <T>(input: {
  sessionID: SessionSchema.ID
  spans: readonly Span<T>[]
  settings: Settings
  /** Node ids the model asked to see at raw fidelity this turn (§3.7). */
  escalate?: readonly string[]
}): Promise<AssembledSpans<T> | undefined> => {
  if (!input.settings.enabled || input.spans.length === 0) return undefined
  try {
    const engine = acquire(input.sessionID, {
      ...input.settings,
      bin: await resolveEngineBin(input.settings.bin),
    })
    const seen = ingestedSpanIDs.get(input.sessionID) ?? new Set<string>()
    ingestedSpanIDs.set(input.sessionID, seen)
    let added = 0
    for (const span of input.spans) {
      if (seen.has(span.id)) continue
      seen.add(span.id)
      added++
      await engine.writeSpan(spanFileID(span.id), span.text)
    }
    const corrections = added > 0 ? await engine.ingest() : []
    const query = [...input.spans].reverse().find((span) => span.boundary)?.text ?? ""
    if (!query.trim()) return undefined
    const planned = await engine.plan(query)

    const escalation = input.escalate ?? pendingEscalationsSpans(input.spans)
    const pinned =
      escalation.length > 0 ? serviceEscalationsSpans(input.spans, escalation, input.settings.budget) : { pinned: "", spent: 0 }
    const rendered = [pinned.pinned, planned].filter((section) => section.length > 0).join("\n")
    if (!rendered.trim()) return undefined
    const start = recentWindowStart(
      input.spans.map((span) => Token.estimate(span.text)),
      input.spans.map((span) => span.boundary),
      input.settings.recentTokens,
    )
    const recent = start === "full" ? input.spans.map((span) => span.item) : input.spans.slice(start).map((span) => span.item)
    return {
      rendered,
      tokens: Math.min(input.settings.budget, pinned.spent + Token.estimate(planned)),
      recent,
      corrections,
    }
  } catch (error) {
    recordDegradation(input.sessionID, "assemble-spans", error)
    forget(input.sessionID)
    return undefined
  }
}
