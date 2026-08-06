import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { ROE } from "../src/roe"
import { ConfigStore } from "../src/config-store"
import { Orchestrator } from "../src/orchestrator"

/**
 * Perf-cache verification. The goal isn't to benchmark raw µs — the goal is to
 * prove the plugin hot-path helpers don't hit disk on every call.
 *
 * We hook fs.readFileSync + fs.writeFileSync and count invocations against the
 * files we care about, then drive the helper N times and assert the count is
 * bounded by O(1) inside the cache window (not O(N)).
 */

let scratch: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-perfcache-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

function countMatching(calls: any[][], matches: (arg: any) => boolean): number {
  let n = 0
  for (const args of calls) if (matches(args[0])) n++
  return n
}

function withReadCounter<T>(matches: (arg: any) => boolean, fn: () => T): { result: T; count: number } {
  const spy = spyOn(fs, "readFileSync")
  try {
    const result = fn()
    const count = countMatching((spy.mock.calls as any[][]), matches)
    return { result, count }
  } finally {
    spy.mockRestore()
  }
}

function withWriteCounter<T>(matches: (arg: any) => boolean, fn: () => T): { result: T; count: number } {
  const spy = spyOn(fs, "writeFileSync")
  try {
    const result = fn()
    const count = countMatching((spy.mock.calls as any[][]), matches)
    return { result, count }
  } finally {
    spy.mockRestore()
  }
}

describe("ROE.load — mtime-cached", () => {
  test("100 calls with no file change → at most 1 disk read", () => {
    // Seed a valid ROE.
    const roe = ROE.createTemplate("t", "t")
    roe.targets = ["*"]; roe.authorized_tools = ["*"]
    ROE.sign(roe)
    // Warm.
    ROE.load()
    const { count } = withReadCounter(
      (p) => typeof p === "string" && p.includes("active.roe.json"),
      () => {
        for (let i = 0; i < 100; i++) ROE.load()
      },
    )
    expect(count).toBeLessThanOrEqual(1)
  })

  test("mtime change invalidates cache — next load re-reads", () => {
    const roe = ROE.createTemplate("t", "t")
    roe.targets = ["*"]; roe.authorized_tools = ["*"]
    ROE.sign(roe)
    ROE.load()
    // Bump mtime by writing (through ROE.save which busts cache).
    ROE.sign(roe)
    const { count } = withReadCounter(
      (p) => typeof p === "string" && p.includes("active.roe.json"),
      () => ROE.load(),
    )
    expect(count).toBe(1)
  })
})

describe("ConfigStore.load — mtime-cached", () => {
  test("500 calls with no file change → at most 1 disk read", () => {
    fs.writeFileSync(".openhack/openhack.jsonc", `{"graph": {"controller_enabled": false}}`)
    ConfigStore.invalidateCache()
    ConfigStore.load() // warm
    const { count } = withReadCounter(
      (p) => typeof p === "string" && p.endsWith("openhack.jsonc"),
      () => {
        for (let i = 0; i < 500; i++) ConfigStore.get("graph.controller_enabled")
      },
    )
    expect(count).toBe(0)
  })

  test("save() busts the cache — next get() re-reads", () => {
    fs.writeFileSync(".openhack/openhack.jsonc", `{"a": 1}`)
    ConfigStore.invalidateCache()
    ConfigStore.get("a") // warm cache
    ConfigStore.set("a", 2) // busts cache internally
    const val = ConfigStore.get("a")
    expect(val).toBe(2)
  })
})

describe("Orchestrator.recordResult — coalesced writes", () => {
  test("100 recordResult calls → at most a few writes (not 100)", () => {
    // Fresh dir → tool-scores.json will be written.
    const { count } = withWriteCounter(
      (p) => typeof p === "string" && p.endsWith("tool-scores.json"),
      () => {
        for (let i = 0; i < 100; i++) Orchestrator.recordResult("hexstrike", `t${i}`, true, 10)
        Orchestrator.flushScoresForTest()
      },
    )
    // The exact count depends on interval timing, but must be ≪ 100.
    // Empirically 1-3 flushes.
    expect(count).toBeLessThanOrEqual(5)
    expect(count).toBeGreaterThanOrEqual(1) // at least the final flush landed
  })
})
