// Deception / honeypot layer tests.
//
// Verify the three surfaces stay coherent and inert:
//   • config resolves from .openhack/openhack.jsonc (deception.*)
//   • the planter writes real, executable, refusing tool stubs + watcher logs
//     + honeytokens, all under the configured root, and clear() removes them
//   • the tarpit text is shared (same story the MCP server returns)
//   • sessionId is deterministic (no Date.now/Math.random — resume/test safe)

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Deception } from "../src/deception"
import { DeceptionPlanter } from "../src/deception-planter"
import { ConfigStore } from "../src/config-store"

let tmpdir: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), "deception-test-"))
  process.chdir(tmpdir)
  ConfigStore.invalidateCache()
})

afterEach(() => {
  process.chdir(origCwd)
})

describe("Deception.config", () => {
  test("defaults to disabled sandbox when unset", () => {
    const c = Deception.config()
    expect(c.enabled).toBe(false)
    expect(c.mode).toBe("sandbox")
    expect(c.root).toBe(".openhack/gym")
  })

  test("reads deception.* from openhack.jsonc", () => {
    ConfigStore.save({ deception: { enabled: true, mode: "honeypot", latencyMs: 0, root: ".openhack/trap" } })
    const c = Deception.config()
    expect(c.enabled).toBe(true)
    expect(c.mode).toBe("honeypot")
    expect(c.latencyMs).toBe(0)
    expect(c.root).toBe(".openhack/trap")
  })

  test("sessionId is deterministic for a given seed+mode", () => {
    const a = Deception.sessionId({ enabled: true, mode: "sandbox", root: "x", latencyMs: 0, seed: "s" })
    const b = Deception.sessionId({ enabled: true, mode: "sandbox", root: "x", latencyMs: 0, seed: "s" })
    const c = Deception.sessionId({ enabled: true, mode: "honeypot", root: "x", latencyMs: 0, seed: "s" })
    expect(a).toBe(b)
    expect(a).not.toBe(c) // mode participates
    expect(a).toMatch(/^obs-[0-9a-f]{8}$/)
  })
})

describe("Deception.tarpit", () => {
  test("is inert, refuses, and mentions logging", () => {
    const t = Deception.tarpit("exploit-gym")
    expect(t).toContain("exploit-gym")
    expect(t.toLowerCase()).toContain("observed")
    expect(t.toLowerCase()).toMatch(/disabled|logged/)
  })
})

describe("DeceptionPlanter", () => {
  const c: Deception.Config = { enabled: true, mode: "honeypot", root: ".openhack/gym", latencyMs: 0, seed: "t" }

  test("plan() covers every tool + watchers + honeytokens", () => {
    const specs = DeceptionPlanter.plan(c)
    for (const tool of Deception.TOOLS) {
      const stub = specs.find((s) => s.rel === `exploit-gym/bin/${tool.id}`)
      expect(stub).toBeDefined()
      expect(stub!.mode).toBe(0o755) // executable
      expect(stub!.content.startsWith("#!/bin/sh")).toBe(true)
      expect(stub!.content).toContain("exit 1") // never succeeds
    }
    expect(specs.some((s) => s.rel === ".watchers/audit.log")).toBe(true)
    expect(specs.some((s) => s.rel.startsWith("honeytokens/"))).toBe(true)
    expect(specs.some((s) => s.rel === "env.sh")).toBe(true)
  })

  test("plant() writes executable stubs and clear() removes them", () => {
    const { root, files } = DeceptionPlanter.plant(c)
    expect(files.length).toBeGreaterThan(Deception.TOOLS.length)
    const stub = path.join(root, "exploit-gym", "bin", "exploit-gym")
    expect(fs.existsSync(stub)).toBe(true)
    expect(fs.statSync(stub).mode & 0o111).toBeGreaterThan(0) // has an execute bit
    expect(DeceptionPlanter.isPlanted(c)).toBe(true)

    DeceptionPlanter.clear(c)
    expect(fs.existsSync(root)).toBe(false)
    expect(DeceptionPlanter.isPlanted(c)).toBe(false)
  })

  test("honeytokens are canaries, never plausible real secrets", () => {
    const specs = DeceptionPlanter.plan(c)
    const aws = specs.find((s) => s.rel === "honeytokens/aws_credentials")!
    expect(aws.content).toContain("CANARY")
    expect(aws.mode).toBe(0o600)
  })
})
