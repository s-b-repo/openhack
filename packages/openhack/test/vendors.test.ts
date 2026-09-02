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
    process.chdir(fake)
    const result = await Vendors.bootstrap("lattice")
    expect(result.ok).toBe(false)
    expect(result.error).toContain("bootstrap script missing")
    fs.rmSync(fake, { recursive: true, force: true })
  })
})
