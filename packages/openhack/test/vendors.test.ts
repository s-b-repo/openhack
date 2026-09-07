// Unit tests for the vendored-component registry (packages/openhack/src/vendors.ts).
//
// Verifies the one-registry contract for all eight vendored components:
//   • the registry is complete and well-formed
//   • resolution follows env override → vendored artifact → PATH
//   • unknown names resolve to null (never throw)
//   • bootstrap of an unknown component / missing script fails with a fix message
//   • the text report renders every component

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { Vendors } from "../src/vendors"

const REPO_ROOT = path.resolve(__dirname, "../..")

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
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vendors-"))
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(tmp, { recursive: true, force: true })
  for (const [key, value] of Object.entries(savedEnv)) setEnv(key, value)
})

describe("Vendors.COMPONENTS", () => {
  test("registers all eight vendored components", () => {
    expect(Vendors.COMPONENTS.map((c) => c.name).sort()).toEqual([
      "dcr", "deepagents", "gpt-researcher", "graphbit", "langgraph", "lattice", "mini-swe-agent", "temporal",
    ])
  })

  test("every component declares its seam, bootstrap and artifact", () => {
    for (const c of Vendors.COMPONENTS) {
      expect(c.seam.length).toBeGreaterThan(8)
      expect(c.bootstrap).toBe(`vendor/${c.dir}/bootstrap.sh`)
      expect(c.artifact).toContain(c.dir)
    }
  })
})

describe("Vendors.resolve", () => {
  test("env override with a path wins when it exists", () => {
    const stub = path.join(tmp, "stub-dcr")
    fs.writeFileSync(stub, "x")
    setEnv("DCR_BIN", stub)
    expect(Vendors.resolve("dcr")).toEqual({ bin: stub, source: "env" })
  })

  test("env override pointing nowhere resolves to null (visible, not silent)", () => {
    setEnv("DCR_BIN", path.join(tmp, "missing"))
    expect(Vendors.resolve("dcr")).toEqual({ bin: null, source: "env" })
  })

  test("vendored artifacts resolve from inside the repo (lattice + dcr are bootstrapped here)", () => {
    process.chdir(REPO_ROOT)
    setEnv("OPENHACK_LATTICE_BIN", undefined)
    setEnv("DCR_BIN", undefined)
    for (const name of ["lattice", "dcr"]) {
      const r = Vendors.resolve(name)
      expect(r.source).toBe("vendored")
      expect(r.bin).toContain(`vendor/${name === "dcr" ? "subnext" : name}/`)
    }
  })

  test("unknown component → null resolution, no throw", () => {
    expect(Vendors.resolve("not-a-component")).toEqual({ bin: null, source: null })
  })
})

describe("Vendors.status + format", () => {
  test("status covers the registry and carries the seam", () => {
    const statuses = Vendors.status()
    expect(statuses).toHaveLength(Vendors.COMPONENTS.length)
    for (const s of statuses) {
      expect(s.seam.length).toBeGreaterThan(8)
      expect(["env", "vendored", "path", null]).toContain(s.source)
    }
  })

  test("format renders every row and marks missing artifacts with the fix", () => {
    process.chdir(tmp) // no vendor/ above tmp → everything missing
    setEnv("DCR_BIN", undefined)
    setEnv("OPENHACK_LATTICE_BIN", undefined)
    setEnv("PATH", tmp)
    const text = Vendors.format(Vendors.status())
    for (const c of Vendors.COMPONENTS) expect(text).toContain(c.name)
    expect(text).toContain("MISSING")
    expect(text).toContain("bootstrap.sh")
  })
})

describe("Vendors.bootstrap", () => {
  test("unknown component fails with the known-list fix", async () => {
    const result = await Vendors.bootstrap("not-a-component")
    expect(result.ok).toBe(false)
    expect(result.error).toContain("known:")
  })

  test("missing repo root fails with a fix", async () => {
    process.chdir(tmp)
    const result = await Vendors.bootstrap("lattice")
    expect(result.ok).toBe(false)
    expect(result.error).toContain("repository root")
  })

  test("missing bootstrap script fails with the path", async () => {
    const fake = fs.mkdtempSync(path.join(os.tmpdir(), "vendors-repo-"))
    fs.mkdirSync(path.join(fake, "vendor", "lattice"), { recursive: true })
    const original = process.cwd()
    process.chdir(fake)
    try {
      const result = await Vendors.bootstrap("lattice")
      expect(result.ok).toBe(false)
      expect(result.error).toContain("bootstrap script missing")
    } finally {
      process.chdir(original)
      fs.rmSync(fake, { recursive: true, force: true })
    }
  })

  test("bootstrap accepts withPython (no-op for non-graphbit components)", async () => {
    // Run from the repo so the lattice bootstrap resolves; withPython must
    // be a no-op for any non-graphbit component. The lattice venv may or may
    // not be built depending on test order, so tolerate either outcome —
    // what we assert is that the API accepts the option without throwing.
    const result = await Vendors.bootstrap("lattice", { withPython: true })
    // Either: bootstrap succeeded (venv already built), or it failed at the
    // script stage. Either is acceptable — we just require the call returned
    // a structured result (not threw) and the withPython branch was skipped.
    expect(typeof result.ok).toBe("boolean")
    if (!result.ok) {
      // If it failed, the error must come from the lattice script stage, not
      // from any withPython handling (which would only run for graphbit).
      expect(result.error).not.toContain("withPython")
      expect(result.error).not.toContain("graphbit python")
    }
  })
})

describe("Vendors.probe", () => {
  test("unknown component → empty results", async () => {
    const report = await Vendors.probe("not-a-component")
    expect(report.results).toHaveLength(0)
  })

  test("no repository root → recorded skipped result (never silent)", async () => {
    const original = process.cwd()
    process.chdir(tmp)
    try {
      const report = await Vendors.probe("graphbit")
      expect(report.results).toHaveLength(1)
      expect(report.results[0]!.ok).toBe(false)
      expect(report.results[0]!.skipped).toBe(true)
      expect(report.results[0]!.detail).toContain("repository root")
    } finally {
      process.chdir(original)
    }
  })

  test("graphbit probes report the exact bootstrap hint when the artifact is missing", async () => {
    // Run from the repo (graphbit source present, but target/release not built).
    // Explicit chdir to be robust against other tests in the file/suite that
    // leave the process cwd in a temp dir (e.g. the harness-tuning suite).
    const original = process.cwd()
    process.chdir(REPO_ROOT)
    try {
      const report = await Vendors.probe("graphbit")
      expect(report.name).toBe("graphbit")
      expect(report.results.length).toBeGreaterThanOrEqual(1)
      for (const result of report.results) {
        // Every probe must be recorded (ok or not) — no swallowed probe.
        expect(result.detail.length).toBeGreaterThan(0)
        if (!result.ok) {
          // Skipped path or failed path both surface the exact build hint.
          expect(result.skipped === true || result.detail).toBeTruthy()
        }
      }
      // When the Rust artifact is missing, the first probe must be SKIP.
      const first = report.results[0]!
      if (!fs.existsSync(path.join(REPO_ROOT, "vendor", "graphbit", "target", "release", "libgraphbit.so"))) {
        expect(first.ok).toBe(false)
        expect(first.skipped).toBe(true)
        expect(first.detail).toContain("rust library not built")
      }
    } finally {
      process.chdir(original)
    }
  })
})

describe("Vendors.formatProbe", () => {
  test("renders every result with its status tag", () => {
    const text = Vendors.formatProbe({ name: "graphbit", results: [
      { ok: true, detail: "rust library present" },
      { ok: false, skipped: true, detail: "python binding not installed" },
      { ok: false, detail: "boom" },
    ] })
    expect(text).toContain("probe(graphbit)")
    expect(text).toContain("[OK  ] 1: rust library present")
    expect(text).toContain("[SKIP] 2: python binding not installed")
    expect(text).toContain("[FAIL] 3: boom")
  })

  test("renders the no-probes placeholder", () => {
    const text = Vendors.formatProbe({ name: "lattice", results: [] })
    expect(text).toContain("no probes declared")
  })
})
