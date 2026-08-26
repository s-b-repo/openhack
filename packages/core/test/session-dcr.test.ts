import { describe, expect, test } from "bun:test"
import { rmSync } from "node:fs"
import path from "node:path"
import { DateTime, Effect } from "effect"
import { Config } from "@openhack-ai/core/config"
import { ConfigDcr } from "@openhack-ai/core/config/dcr"
import { Global } from "@openhack-ai/core/global"
import { ModelV2 } from "@openhack-ai/core/model"
import { ProviderV2 } from "@openhack-ai/core/provider"
import { SessionDcr } from "@openhack-ai/core/session/dcr"
import { SessionMessage } from "@openhack-ai/core/session/message"

const created = DateTime.makeUnsafe(0)
const id = (value: string) => SessionMessage.ID.make(`msg_${value}`)
const modelRef = { id: ModelV2.ID.make("model"), providerID: ProviderV2.ID.make("provider") }

const user = (value: string, text = `user ${value}`) =>
  SessionMessage.User.make({ id: id(value), type: "user", text, time: { created } })

const assistant = (value: string, text = `assistant ${value}`) =>
  SessionMessage.Assistant.make({
    id: id(value),
    type: "assistant",
    agent: "build",
    model: modelRef,
    content: [SessionMessage.AssistantText.make({ type: "text", id: value, text })],
    time: { created },
  })

const entries = (...messages: SessionMessage.Message[]) => messages.map((message, index) => ({ seq: index + 1, message }))

describe("SessionDcr.settings", () => {
  test("defaults with no config documents", () => {
    const settings = SessionDcr.settings([{ type: "directory", path: "/tmp" as never }])
    expect(settings.enabled).toBe(process.env.DCR_ENABLED === "1")
    expect(settings.bin).toBe(process.env.DCR_BIN ?? "dcr")
    expect(settings.budget).toBe(1200)
    expect(settings.recentTokens).toBe(4000)
  })

  test("merges document overrides over defaults", () => {
    const entry = Config.Document.make({
      type: "document",
      info: {
        dcr: ConfigDcr.Info.make({ enabled: true, bin: "/usr/local/bin/dcr-serve", budget: 10, recentTokens: 20 }),
      },
    })
    const settings = SessionDcr.settings([entry])
    expect(settings.enabled).toBe(true)
    expect(settings.bin).toBe("/usr/local/bin/dcr-serve")
    expect(settings.budget).toBe(10)
    expect(settings.recentTokens).toBe(20)
  })
})

describe("SessionDcr.recentTail", () => {
  test("returns the full window when it fits the token budget", () => {
    const input = entries(user("1"), assistant("2"), user("3"))
    expect(SessionDcr.recentTail(input, Number.POSITIVE_INFINITY)).toEqual(input)
  })

  test("truncates to the token budget from the newest side", () => {
    const long = user("long", "x".repeat(400))
    const short = user("short", "y")
    const input = entries(long, assistant("mid"), short)
    // Budget admits only the trailing short message ("[User]: user y" ≈ 4 tokens).
    const tail = SessionDcr.recentTail(input, 2)
    expect(tail).toEqual([input[2]])
  })

  test("never opens the window on an assistant turn — slides to the next boundary", () => {
    const boundary = user("1")
    const a1 = assistant("2")
    const a2 = assistant("3")
    const latest = user("4")
    const input = entries(boundary, a1, a2, latest)
    // Budget 12 naturally cuts to [a1, a2, latest]; an all-assistant opener is
    // invalid on role-alternating providers, so the window slides forward past
    // them to keep the latest boundary message.
    const tail = SessionDcr.recentTail(input, 12)
    expect(tail[0]?.message.type).not.toBe("assistant")
    expect(tail.at(-1)).toEqual(input.at(-1))
  })

  test("falls back to full history when no boundary exists in the tail", () => {
    const seed = user("seed", "seed")
    const input = entries(seed, assistant("1"), assistant("2"), assistant("3"))
    // Budget 18 cuts the boundary out entirely and every remaining entry is an
    // assistant turn; sliding would empty the window, so the known-valid full
    // history is resent instead.
    expect(SessionDcr.recentTail(input, 18)).toEqual(input)
  })
})

describe("SessionDcr.escalations", () => {
  test("extracts node ids from #ESCALATE tokens", () => {
    expect(SessionDcr.escalations("partial answer\n#ESCALATE clai_e36d7d2dd2bb")).toEqual(["clai_e36d7d2dd2bb"])
  })

  test("deduplicates and keeps order across multiple requests", () => {
    const text = "#ESCALATE span_1 then #ESCALATE doc_2, revisiting #ESCALATE span_1"
    expect(SessionDcr.escalations(text)).toEqual(["span_1", "doc_2"])
  })

  test("returns empty without escalation tokens", () => {
    expect(SessionDcr.escalations("#ESCALATE")).toEqual([])
    expect(SessionDcr.escalations("plain reply")).toEqual([])
  })
})

describe("SessionDcr.pendingEscalations", () => {
  test("collects escalations from assistant turns after the latest user boundary", () => {
    const input = entries(
      user("1"),
      assistant("2", `working\n#ESCALATE node_a`),
      assistant("3", `#ESCALATE node_b #ESCALATE node_a`),
      user("4"),
      assistant("5", `#ESCALATE node_c`),
    )
    expect(SessionDcr.pendingEscalations(input)).toEqual(["node_c"])
  })

  test("ignores tool parts and non-assistant messages", () => {
    const input = entries(user("1"), assistant("2", "no tokens here"))
    expect(SessionDcr.pendingEscalations(input)).toEqual([])
  })

  test("returns empty when history ends on the user turn itself", () => {
    expect(SessionDcr.pendingEscalations(entries(user("1")))).toEqual([])
  })
})

describe("SessionDcr.block", () => {
  test("wraps rendered output in a session-context block with token count", () => {
    const block = SessionDcr.block({ rendered: "fact one", tokens: 7, recentMessages: [], corrections: [] })
    expect(block).toContain('<session-context engine="dcr" tokens="7">')
    expect(block).toContain("fact one")
    expect(block.trimEnd().endsWith("</session-context>")).toBe(true)
  })

  test("renders corrections as NOTE annotations instead of dropping them", () => {
    const block = SessionDcr.block({
      rendered: "server.ip = 10.0.9.7",
      tokens: 7,
      recentMessages: [],
      corrections: [{ superseded: "10.0.9.7", by: "server.ip = 10.0.9.8" }],
    })
    expect(block).toContain("NOTE — corrected values:")
    expect(block).toContain(`- "10.0.9.7" was corrected later; current value in: server.ip = 10.0.9.8`)
  })

  test("omits the NOTE section when no corrections were detected", () => {
    const block = SessionDcr.block({ rendered: "fact one", tokens: 7, recentMessages: [], corrections: [] })
    expect(block).not.toContain("NOTE — corrected values:")
  })
})

describe("SessionDcr.assembleEffect", () => {
  test("degrades to undefined when the sidecar cannot launch", async () => {
    const assembled = await Effect.runPromise(
      SessionDcr.assembleEffect({
        sessionID: "ses_disabled" as never,
        entries: entries(user("1")),
        settings: { ...SessionDcr.settings([]), bin: "/nonexistent/dcr-serve-for-tests" },
      }),
    )
    expect(assembled).toBeUndefined()
  })
})

describe("SessionDcr.disposeSession", () => {
  test("is safe for untracked sessions", () => {
    expect(() => SessionDcr.disposeSession("ses_missing" as never)).not.toThrow()
  })
})

const dcrBinary = Bun.which(process.env.DCR_BIN ?? "dcr")
const maybeIntegration = dcrBinary ? test : test.skip

describe("SessionDcr.assemble (reference implementation)", () => {
  const sessionID = `ses_dcr_integration_${Date.now().toString(36)}` as never
  const liveSettings = { enabled: true, bin: process.env.DCR_BIN ?? "dcr", budget: 400, recentTokens: 200 }

  maybeIntegration("plans a corrected working set over unbounded history", async () => {
    // Assignments live in assistant turns — the scanner extracts unprefixed
    // state, and the second value contradicts the first (supersession §3.4).
    const history = entries(
      user("1", "starting work on the incident"),
      assistant("2", "server.ip = 10.0.9.7"),
      user("3", "acknowledged"),
      assistant("4", "server.ip = 10.0.9.8"),
      user("5", "what is the server ip?"),
    )
    try {
      const assembled = await Effect.runPromise(
        SessionDcr.assembleEffect({ sessionID, entries: history, settings: liveSettings }),
      )
      expect(assembled).toBeDefined()
      expect(assembled!.rendered).toContain("10.0.9.8")
      expect(assembled!.tokens).toBeGreaterThan(0)
      expect(assembled!.recentMessages.length).toBeGreaterThan(0)
      // The contradiction resolved to values, not opaque node ids.
      expect(assembled!.corrections.length).toBe(1)
      expect(assembled!.corrections[0]!.superseded).toContain("10.0.9.7")
      expect(assembled!.corrections[0]!.by).toContain("10.0.9.8")
    } finally {
      rmSync(path.join(Global.Path.data, "dcr", sessionID as string), { recursive: true, force: true })
      SessionDcr.disposeSession(sessionID as never)
    }
  })

  maybeIntegration("degrades to undefined when the runtime binary is unusable", async () => {
    const assembled = await Effect.runPromise(
      SessionDcr.assembleEffect({
        sessionID: `ses_dcr_broken_${Date.now().toString(36)}` as never,
        entries: entries(user("1")),
        settings: { ...liveSettings, bin: "/nonexistent/dcr-for-tests" },
      }),
    )
    expect(assembled).toBeUndefined()
  })
})
