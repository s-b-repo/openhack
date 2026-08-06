import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { spawnSync } from "node:child_process"
import { Coverage } from "../src/coverage"

/**
 * Smoke test for `openhack combos`. Seeds a fixture coverage store in a scratch
 * cwd, spawns the CLI, and asserts every documented section renders. Runs the
 * script directly with `bun run` so we don't need the compiled bin present.
 */

let scratch: string
let origCwd: string
const repoRoot = path.resolve(__dirname, "../../..")

beforeEach(() => {
  origCwd = process.cwd()
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-combos-cli-"))
  process.chdir(scratch)
  fs.mkdirSync(".openhack", { recursive: true })

  // Seed: one vulnerable sqli cell on /login POST + a partial payload set,
  // plus a GET-only endpoint to force method gaps.
  let store = Coverage.load("example.com")
  store = Coverage.mark(store, {
    endpoint: "/login", method: "POST", classId: "sqli", result: "vulnerable",
    payloadFamilies: ["error-based", "boolean-blind"],
  })
  store = Coverage.mark(store, { endpoint: "/only-get", method: "GET", classId: "sqli", result: "safe" })
  Coverage.save(store)
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(scratch, { recursive: true, force: true })
})

function runCli(args: string[]) {
  // Invoke the openhack CLI's TypeScript entry directly. We call the openhack.ts
  // subcommand file via a small runner script — but a cleaner approach is to
  // point at the opencode/src entry. Since that has a heavy dep graph, we take
  // the pragmatic path: invoke the standalone openhack.ts via bun with a small
  // wrapper.
  const wrapperPath = path.join(scratch, "cli-wrapper.ts")
  fs.writeFileSync(wrapperPath, `
import yargs from "yargs"
import { OpenHackCommand } from "${path.join(repoRoot, "packages/opencode/src/cli/cmd/openhack.ts").replace(/\\/g, "/")}"
const y: any = yargs(process.argv.slice(2))
if (OpenHackCommand.builder) OpenHackCommand.builder(y)
await y.parseAsync()
`)
  return spawnSync("bun", ["run", wrapperPath, ...args], { encoding: "utf-8", cwd: scratch, env: { ...process.env } })
}

describe("openhack combos CLI", () => {
  test("--gaps prints all three sections with counts", () => {
    const p = runCli(["combos", "--target", "example.com", "--gaps"])
    expect(p.status).toBe(0)
    expect(p.stdout).toMatch(/method gaps/)
    expect(p.stdout).toMatch(/payload gaps/)
    expect(p.stdout).toMatch(/chain gaps/)
    expect(p.stdout).toMatch(/Method-tuple gaps/)
    expect(p.stdout).toMatch(/Payload-family gaps/)
    expect(p.stdout).toMatch(/Chain-pair gaps/)
  })

  test("--methods restricts output to the methods section", () => {
    const p = runCli(["combos", "--target", "example.com", "--methods"])
    expect(p.status).toBe(0)
    expect(p.stdout).toMatch(/Method-tuple gaps/)
    expect(p.stdout).not.toMatch(/Payload-family gaps/)
    expect(p.stdout).not.toMatch(/Chain-pair gaps/)
  })

  test("--payloads restricts output to the payloads section", () => {
    const p = runCli(["combos", "--target", "example.com", "--payloads"])
    expect(p.status).toBe(0)
    expect(p.stdout).toMatch(/Payload-family gaps/)
    // The sqli POST /login cell has time-blind, union, oob, polyglot missing.
    expect(p.stdout).toMatch(/time-blind|union|oob|polyglot/)
  })

  test("--chains restricts output to the chains section", () => {
    const p = runCli(["combos", "--target", "example.com", "--chains"])
    expect(p.status).toBe(0)
    expect(p.stdout).toMatch(/Chain-pair gaps/)
    expect(p.stdout).toMatch(/sqli.*auth|auth.*sqli/)
  })

  test("--report writes .openhack/checklists/<target>.md and mentions its path", () => {
    const p = runCli(["combos", "--target", "example.com", "--report"])
    expect(p.status).toBe(0)
    const expected = path.join(".openhack", "checklists", "example.com.md")
    expect(fs.existsSync(expected)).toBe(true)
    expect(p.stdout).toContain(expected)
    const body = fs.readFileSync(expected, "utf-8")
    expect(body).toContain("Combinatorial coverage checklist — example.com")
  })

  test("--version-info prints all three vendored index versions", () => {
    const p = runCli(["combos", "--target", "example.com", "--version-info"])
    expect(p.status).toBe(0)
    expect(p.stdout).toMatch(/PayloadsAllTheThings/)
    expect(p.stdout).toMatch(/HackTricks/)
    expect(p.stdout).toMatch(/WSTG/)
  })
})
