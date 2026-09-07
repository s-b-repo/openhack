export * as SessionDcrSpans from "./dcr-spans"

import type { SessionV1 } from "@openhack-ai/core/v1/session"
import { SessionDcr } from "@openhack-ai/core/session/dcr"
import { SessionDcrCache } from "@openhack-ai/core/session/dcr-cache"
import type { SessionID } from "./schema"
import { ConfigStore } from "../../../openhack/src/config-store"

/**
 * V1-side adapter for the Dynamic Context Runtime. The V2 `SessionRunner`
 * projects core `SessionMessage` entries; the legacy `SessionPrompt` projects
 * `SessionV1.WithParts`. Both go through `SessionDcr.assembleSpans` so every
 * session runtime — TUI, HTTP prompt handler, automode `run` instances and the
 * V2 runner alike — shares one context system: budgeted working set + verbatim
 * recent tail instead of full history, with compaction as the overflow guard.
 *
 * Settings resolve from the same sources at every level: env (`DCR_*`) plus the
 * engagement config (`dcr` block in `.openhack/openhack.jsonc`, read here via
 * ConfigStore — the V2 runner reads the same block through core Config).
 */

/** Longest serialized part text fed to the runtime (per part, not per turn). */
const MAX_PART_CHARS = 8_000

const truncate = (text: string) => (text.length > MAX_PART_CHARS ? `${text.slice(0, MAX_PART_CHARS)}…` : text)

const toolInputText = (input: Record<string, any>) => {
  try {
    const text = JSON.stringify(input)
    return text === "{}" ? "" : text
  } catch {
    return "[unserializable input]"
  }
}

const partLines = (part: SessionV1.Part, role: "user" | "assistant"): string[] => {
  switch (part.type) {    case "text":
      return part.text ? [`${role === "user" ? "[User]" : "[Assistant]"}: ${part.text}`] : []
    case "reasoning":
      return part.text ? [`[Assistant reasoning]: ${part.text}`] : []
    case "file":
      return [`[Attached file: ${part.filename ?? part.url}]`]
    case "tool": {
      const input = toolInputText(part.state.input)
      if (part.state.status === "completed")
        return [`[Assistant tool call]: ${part.tool}(${input})`, `[Tool result]: ${truncate(part.state.output)}`]
      if (part.state.status === "error")
        return [`[Assistant tool call]: ${part.tool}(${input})`, `[Tool error]: ${part.state.error}`]
      if (part.state.status === "running") return [`[Assistant tool call]: ${part.tool}(${input})`, `[Tool title]: ${part.state.title ?? ""}`]
      return [`[Assistant tool call]: ${part.tool}(${input})`]
    }
    case "subtask":
      return [`[Subtask]: ${part.prompt}`]
    case "agent":
      return [`[Agent switch]: ${part.name}`]
    case "compaction":
      return [`[Compaction]: ${part.auto ? "auto" : "manual"} part summary of earlier history`]
    case "patch":
      return [`[Patch]: ${part.hash} (${part.files.join(", ")})`]
    case "snapshot":
      return [`[Snapshot]: ${part.snapshot}`]
    case "retry":
      return [`[Retry]: attempt ${part.attempt}`]
    case "step-start":
    case "step-finish":
      return []
  }
  // Exhaustive over SessionV1.Part; an unknown future part type contributes
  // nothing to the runtime's documents.
  return []
}

const serializeV1 = (message: SessionV1.WithParts): string => {
  const role = message.info.role === "assistant" ? "assistant" : "user"
  return message.parts.flatMap((part) => partLines(part, role)).join("\n")
}

/**
 * O(1)-per-part content fingerprint of a V1 message, mirroring the fields
 * `partLines` reads. Stable across turns for an immutable committed message
 * (archival token-cache hit); it changes when a part is edited in place.
 */
const fingerprintV1 = (message: SessionV1.WithParts): number => {
  const mix = (hash: number, value: number) => Math.imul(hash ^ value, 0x01000193) >>> 0
  let hash = mix(0x811c9dc5, message.info.role === "assistant" ? 1 : 0)
  hash = mix(hash, message.parts.length)
  for (const part of message.parts) {
    switch (part.type) {
      case "text":
      case "reasoning":
        hash = mix(hash, part.text?.length ?? 0)
        break
      case "file":
        hash = mix(hash, (part.filename ?? part.url ?? "").length)
        break
      case "tool":
        hash = mix(hash, part.state.status.length)
        if (part.state.status === "completed") hash = mix(hash, part.state.output.length)
        else if (part.state.status === "error") hash = mix(hash, part.state.error.length)
        break
      case "subtask":
        hash = mix(hash, part.prompt.length)
        break
      case "agent":
        hash = mix(hash, part.name.length)
        break
      case "patch":
        hash = mix(hash, part.files.length)
        break
      default:
        hash = mix(hash, part.type.length)
    }
  }
  return hash
}

/**
 * Project V1 history into the span shape the runtime bridge consumes. Each
 * message's serialization is priced once through the shared archival token
 * cache and reused across turns — the same cache the V2 runner warms.
 */
export const toSpans = (messages: readonly SessionV1.WithParts[]): SessionDcr.Span<SessionV1.WithParts>[] =>
  messages.map((message) => ({
    item: message,
    id: message.info.id,
    boundary: message.info.role !== "assistant",
    assistant: message.info.role === "assistant",
    text: SessionDcrCache.priced(message.info.id, fingerprintV1(message), () => serializeV1(message)).text,
  }))

/** Merge the engagement-config `dcr` block over the env-driven defaults. */
export const resolveSettings = (): SessionDcr.Settings => {
  const base = SessionDcr.settings([])
  let block: Record<string, unknown> | undefined
  try {
    block = ConfigStore.getObject("dcr")
  } catch (error) {
    // Visible, not fatal: engagement config is unreadable, env defaults still apply.
    console.warn(`[dcr] failed to read engagement config dcr block: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!block) return base
  return {
    enabled: typeof block.enabled === "boolean" ? block.enabled : base.enabled,
    bin: typeof block.bin === "string" && block.bin ? block.bin : base.bin,
    budget: typeof block.budget === "number" && block.budget > 0 ? block.budget : base.budget,
    recentTokens: typeof block.recentTokens === "number" && block.recentTokens > 0 ? block.recentTokens : base.recentTokens,
  }
}

export type Assembled = SessionDcr.AssembledSpans<SessionV1.WithParts>

/**
 * Assemble the DCR working set for a V1 turn. Returns `undefined` when disabled
 * or degraded — callers resend full history; check `SessionDcr.degradation`
 * to surface the reason (the bridge never swallows a failure silently).
 */
export const assemble = async (
  sessionID: SessionID,
  messages: readonly SessionV1.WithParts[],
  settings: SessionDcr.Settings,
): Promise<Assembled | undefined> => SessionDcr.assembleSpans<SessionV1.WithParts>({ sessionID, spans: toSpans(messages), settings })
