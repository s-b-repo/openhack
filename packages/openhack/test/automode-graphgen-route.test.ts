import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { extractJsonObject } from "../../opencode/src/cli/cmd/openhack.automode"
import { Orchestrator } from "../src/orchestrator"

// C1 — the graph controller's JSON extraction (the parse step that turns a model
// transcript into a GeneratedUpdate; a null result degrades to the heuristic).
describe("extractJsonObject — controller transcript parsing (C1)", () => {
  test("plain JSON object", () => {
    expect(extractJsonObject('{"addActions":[],"rationale":"x"}')).toEqual({ addActions: [], rationale: "x" })
  })
  test("fenced ```json block", () => {
    expect(extractJsonObject("```json\n{\"a\":1}\n```")).toEqual({ a: 1 })
  })
  test("JSON embedded in prose", () => {
    expect(extractJsonObject('Here is the plan:\n{"prune":["action:1"]} — done')).toEqual({ prune: ["action:1"] })
  })
  test("no JSON → null", () => {
    expect(extractJsonObject("I could not produce a plan.")).toBeNull()
  })
  test("malformed JSON → null (heuristic fallback)", () => {
    expect(extractJsonObject("{ this is not: valid")).toBeNull()
  })
  test("empty → null", () => {
    expect(extractJsonObject("")).toBeNull()
  })
})

// D — route() must honor the learned tool scores instead of always returning
// the first declared tool.
describe("Orchestrator.route — uses learned scores (D)", () => {
  let origCwd: string
  let scratch: string
  beforeEach(() => {
    origCwd = process.cwd()
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-route-"))
    process.chdir(scratch)
    fs.mkdirSync(".openhack", { recursive: true })
  })
  afterEach(() => {
    Orchestrator.flushScoresForTest()
    process.chdir(origCwd)
    fs.rmSync(scratch, { recursive: true, force: true })
  })

  test("route picks the higher-scored tool after recordResult feedback", () => {
    // Drive nmap_scan (the first-declared recon tool) to the floor and
    // rustscan_scan to the ceiling; route() should now prefer rustscan_scan.
    for (let i = 0; i < 40; i++) Orchestrator.recordResult("hexstrike", "nmap_scan", false, 10)
    for (let i = 0; i < 40; i++) Orchestrator.recordResult("hexstrike", "rustscan_scan", true, 10)

    const r = Orchestrator.route("run an nmap port scan on the host")
    expect(r.category).toBe("recon")
    expect(r.tool).toBe("rustscan_scan")
    expect(r.reason.toLowerCase()).toContain("learned score")
  })
})
