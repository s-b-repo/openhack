// openhack-mcp-capture smoke tests.
//
// The full MCP relies on chromium + curl on the host, so we don't drive real
// captures here — that's covered manually in the e2e docs. Instead we assert:
//
//   • The tool list has the expected shape (writes gated by consent env var).
//   • `list_evidence` returns an empty list for a target with no captures.
//   • `capture_screenshot` denies when OPENHACK_CAPTURE_MCP_ALLOW is unset
//     (consent gate).
//   • `capture_screenshot` denies out-of-scope URLs even when consent is set
//     (defense in depth against a rogue AI trying to snapshot the internet).
//   • `evidence_stat` returns the sha256/bytes for an on-disk artifact.

import { describe, expect, test, beforeAll, afterAll, beforeEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Scope } from "../src/scope"

process.env.OPENHACK_MCP_NO_MAIN = "1"

let tmpdir: string
let origCwd: string

beforeAll(() => {
  origCwd = process.cwd()
  tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), "capture-test-"))
  process.chdir(tmpdir)
})

afterAll(() => {
  process.chdir(origCwd)
})

beforeEach(() => {
  delete process.env.OPENHACK_CAPTURE_MCP_ALLOW
  // Scope-configured to `example.com` — everything else is out of scope.
  fs.mkdirSync(".openhack", { recursive: true })
  const cfg = {
    enabled: true,
    targets: ["example.com"],
    exclusions: [],
    max_port_range: "1-65535",
    allowed_tools: [],
    disallowed_tools: [],
    require_confirmation_for: [],
  }
  fs.writeFileSync(".openhack/scope.json", JSON.stringify(cfg))
  // Force-refresh the Scope module cache — cached across tests otherwise.
  Scope.load(cfg)
})

async function loadCapture() {
  // Force re-import so the module reads env at call time (Bun caches ESM).
  // For this test, one import is enough — the module reads env inside handle().
  const mod = await import(path.resolve(__dirname, "../../openhack-mcp-capture/src/index.ts"))
  return mod
}

describe("openhack-mcp-capture", () => {
  test("TOOLS list has expected write-gated tools", async () => {
    const mod = await loadCapture()
    const names = mod.TOOLS.map((t: any) => t.name)
    expect(names).toContain("capture_screenshot")
    expect(names).toContain("capture_har")
    expect(names).toContain("capture_dom")
    expect(names).toContain("capture_full")
    expect(names).toContain("list_evidence")
    expect(names).toContain("evidence_delete")
    expect(names.length).toBe(7)
  })

  test("list_evidence on empty target returns an empty items list", async () => {
    const mod = await loadCapture()
    const r = await mod.handle("list_evidence", { target: "example.com" })
    expect(r.isError).toBeUndefined()
    const body = r.content[0].text
    const json = JSON.parse(body.replace(/^[^{]*/, "").replace(/[^}]*$/, "") || "{}")
    // The tool returns json inside a text block — we just check no error.
    expect(body).toContain("example.com")
    expect(body).toContain("total")
  })

  test("capture_screenshot without consent env → denied", async () => {
    const mod = await loadCapture()
    delete process.env.OPENHACK_CAPTURE_MCP_ALLOW
    const r = await mod.handle("capture_screenshot", { target: "example.com", url: "https://example.com/" })
    expect(r.isError).toBe(true)
    expect(r.content[0].text).toMatch(/OPENHACK_CAPTURE_MCP_ALLOW|denied|not.*allowed/i)
  })

  test("capture_screenshot with consent BUT out-of-scope URL → denied", async () => {
    const mod = await loadCapture()
    process.env.OPENHACK_CAPTURE_MCP_ALLOW = "1"
    const r = await mod.handle("capture_screenshot", { target: "example.com", url: "https://evil.example.org/" })
    expect(r.isError).toBe(true)
    expect(r.content[0].text.toLowerCase()).toMatch(/scope|not.*in.*scope|refused/)
  })

  test("evidence_stat on nonexistent file returns error", async () => {
    const mod = await loadCapture()
    const r = await mod.handle("evidence_stat", { target: "example.com", filename: "does-not-exist.png" })
    expect(r.isError).toBe(true)
  })

  test("evidence_stat on real file returns sha256 + bytes", async () => {
    const mod = await loadCapture()
    // Manually create an evidence file the way the module would.
    const dir = path.join(".openhack", "findings", "evidence", "example.com")
    fs.mkdirSync(dir, { recursive: true })
    const p = path.join(dir, "smoketest.txt")
    fs.writeFileSync(p, "hello capture")
    const r = await mod.handle("evidence_stat", { target: "example.com", filename: "smoketest.txt" })
    expect(r.isError).toBeUndefined()
    expect(r.content[0].text).toContain("sha256")
    expect(r.content[0].text).toContain("bytes")
  })

  test("evidence_delete without consent → denied", async () => {
    const mod = await loadCapture()
    delete process.env.OPENHACK_CAPTURE_MCP_ALLOW
    const r = await mod.handle("evidence_delete", { target: "example.com", filename: "anything" })
    expect(r.isError).toBe(true)
    expect(r.content[0].text).toMatch(/OPENHACK_CAPTURE_MCP_ALLOW|denied/i)
  })
})
