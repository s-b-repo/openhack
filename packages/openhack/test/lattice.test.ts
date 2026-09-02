// Unit tests for the Lattice bridge module (packages/openhack/src/lattice.ts).
//
// Verifies the write-path/read-path wiring contract without the real engine:
//   • engine resolution: env override → vendored artifact → PATH → null (recorded)
//   • language detection mirrors the engine's _LANG table
//   • differential verify parses the engine's report shape (stub engine)
//   • guardWrittenFile: cooldown, engine-missing hint (once), failure surfacing
//   • formatVerifyNote: file-priority regressions + clean → null
//   • annotateRead: known findings from the latest codeaudit report
//   • status(): every failure is recorded — nothing swallowed silently

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Lattice } from "../src/lattice"

const REPO_ROOT = path.resolve(__dirname, "../../..")

let tmp: string
let origCwd: string
const savedEnv: Record<string, string | undefined> = {}

function setEnv(key: string, value: string | undefined) {
  if (!(key in savedEnv)) savedEnv[key] = process.env[key]
  if (value === undefined) delete process.env[key]
  else process.env[key] = value
}

beforeEach(() => {
  origCwd = process.cwd()
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lattice-module-"))
  process.chdir(tmp)
  fs.mkdirSync(path.join(tmp, ".git"))
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(tmp, { recursive: true, force: true })
  Lattice.__resetForTests()
  for (const [key, value] of Object.entries(savedEnv)) setEnv(key, value)
})

describe("Lattice.detectLang", () => {
  test("maps the engine's language table", () => {
    expect(Lattice.detectLang("src/app.ts")).toBe("ts")
    expect(Lattice.detectLang("src/app.tsx")).toBe("ts")
    expect(Lattice.detectLang("main.go")).toBe("go")
    expect(Lattice.detectLang("lib.rs")).toBe("rs")
    expect(Lattice.detectLang("Cargo.toml")).toBe(null)
    expect(Lattice.detectLang("x.sql")).toBe("sql")
    expect(Lattice.detectLang("deploy/Dockerfile")).toBe("iac")
  })
})

describe("Lattice.resolveBin", () => {
  test("explicit absolute bin wins; missing explicit bin is null (recorded)", () => {
    const stub = path.join(tmp, "stub-lattice")
    fs.writeFileSync(stub, "#!/usr/bin/env bash\n")
    fs.chmodSync(stub, 0o755)
    expect(Lattice.resolveBin(stub)).toBe(stub)
    const missing = path.join(tmp, "nope")
    expect(Lattice.resolveBin(missing)).toBe(null)
  })

  test("vendored artifact resolves by walking up from cwd", () => {
    setEnv("OPENHACK_LATTICE_BIN", undefined)
    // Run from a nested temp dir INSIDE the repo so the vendored artifact is found.
    const nested = path.join(REPO_ROOT, "packages", "openhack")
    process.chdir(nested)
    const resolved = Lattice.resolveBin("lattice")
    expect(resolved).toContain(path.join("vendor", "lattice", ".venv", "bin", "lattice"))
  })

  test("nothing resolvable → null", () => {
    setEnv("OPENHACK_LATTICE_BIN", undefined)
    process.chdir(tmp) // no vendor/ above tmp
    // PATH without any lattice binary: point PATH at an empty dir.
    setEnv("PATH", tmp)
    expect(Lattice.resolveBin("definitely-not-a-binary-xyz")).toBe(null)
  })
})

describe("Lattice.verify + formatVerifyNote", () => {
  test("parses the engine report shape via a stub engine", async () => {
    const stub = path.join(tmp, "stub-lattice")
    fs.writeFileSync(
      stub,
      `#!/usr/bin/env bash
# find the --out argument and write a canned report
out=""
prev=""
for a in "$@"; do [ "$prev" = "--out" ] && out="$a"; prev="$a"; done
printf '{"verdict": "regressed", "regressions": ["src/foo.ts: broken symbol bar"], "broken_by_removal": [], "new_unresolved_imports": ["src/foo.ts: missing helper"], "new_error_diagnostics": [], "removed_public_api": [], "error_diagnostics": [], "added_vertices": ["v1"], "removed_vertices": ["v2"]}' > "$out"
exit 1
`,
    )
    fs.chmodSync(stub, 0o755)
    const report = await Lattice.verify(tmp, { bin: stub, lang: "ts" })
    expect(report).not.toBeNull()
    expect(report!.verdict).toBe("regressed")
    expect(report!.regressions).toEqual(["src/foo.ts: broken symbol bar"])
    expect(report!.newUnresolvedImports).toEqual(["src/foo.ts: missing helper"])
    expect(report!.addedVertices).toBe(1)
    const note = Lattice.formatVerifyNote(path.join(tmp, "src", "foo.ts"), report!)
    expect(note).toContain("LATTICE verify vs HEAD")
    expect(note).toContain("broken symbol bar")
  })

  test("clean verdict formats to null", () => {
    const report: Lattice.VerifyReport = {
      verdict: "clean", regressions: [], brokenByRemoval: [], newUnresolvedImports: [],
      newErrorDiagnostics: [], removedPublicAPI: [], errorDiagnostics: [], addedVertices: 0, removedVertices: 0,
    }
    expect(Lattice.formatVerifyNote("src/foo.ts", report)).toBe(null)
  })

  test("unverifiable verdict surfaces diagnostics", () => {
    const report: Lattice.VerifyReport = {
      verdict: "unverifiable", regressions: [], brokenByRemoval: [], newUnresolvedImports: [],
      newErrorDiagnostics: [], removedPublicAPI: [], errorDiagnostics: ["py: no toolchain"], addedVertices: 0, removedVertices: 0,
    }
    const note = Lattice.formatVerifyNote("src/foo.ts", report)
    expect(note).toContain("UNVERIFIABLE")
    expect(note).toContain("no toolchain")
  })
})

describe("Lattice.guardWrittenFile", () => {
  test("non-source files are skipped", async () => {
    expect(await Lattice.guardWrittenFile("assets/logo.png")).toBe(null)
  })

  test("engine missing → one-time bootstrap hint, then silent cooldown", async () => {
    setEnv("OPENHACK_LATTICE_BIN", undefined)
    setEnv("PATH", tmp) // no engine anywhere
    const file = path.join(tmp, "src", "app.ts")
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, "export const a = 1\n")
    const first = await Lattice.guardWrittenFile(file)
    expect(first).toContain("not bootstrapped")
    expect(first).toContain("vendor/lattice/bootstrap.sh")
    // Second write inside the cooldown → null (and the hint is not repeated).
    expect(await Lattice.guardWrittenFile(file)).toBe(null)
    expect(Lattice.status().engineMissingNoted).toBe(true)
  })

  test("engine failure is surfaced with the recorded error", async () => {
    // Engine exits 3 without writing a report — a contract violation that must
    // be surfaced (never treated as a clean verdict, never swallowed).
    const stub = path.join(tmp, "stub-lattice")
    fs.writeFileSync(stub, "#!/usr/bin/env bash\necho boom >&2\nexit 3\n")
    fs.chmodSync(stub, 0o755)
    setEnv("OPENHACK_LATTICE_BIN", stub)
    const file = path.join(tmp, "src", "app.py")
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, "x = 1\n")
    const note = await Lattice.guardWrittenFile(file)
    expect(note).toContain("structural check failed")
    expect(note).toContain("vendor/lattice/bootstrap.sh")
    expect(Lattice.status().failures).toBeGreaterThan(0)
    expect(Lattice.status().lastError).toContain("no parsable report")
  })
})

describe("Lattice.annotateRead", () => {
  test("surfaces known findings from the latest codeaudit report", async () => {
    const audit = path.join(tmp, ".openhack", "codeaudit", "site-latest")
    fs.mkdirSync(audit, { recursive: true })
    fs.writeFileSync(
      path.join(audit, "ts-hunt.json"),
      JSON.stringify([{ kind: "dead_branch", severity: "medium", symbol: "src/app.ts:42", detail: "branch can never execute" }]),
    )
    const file = path.join(tmp, "src", "app.ts")
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, "export const a = 1\n")
    const note = await Lattice.annotateRead(file)
    expect(note).toContain("LATTICE known findings")
    expect(note).toContain("dead_branch")
  })

  test("no report → null (nothing to say, not an error)", async () => {
    const file = path.join(tmp, "src", "app.ts")
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, "export const a = 1\n")
    expect(await Lattice.annotateRead(file)).toBe(null)
  })
})

describe("Lattice.status", () => {
  test("reports resolution + counters", () => {
    setEnv("OPENHACK_LATTICE_BIN", undefined)
    const st = Lattice.status()
    expect(st.runs).toBe(0)
    expect(st.resolvedBin === null || st.resolvedBin.length > 0).toBe(true)
  })
})
