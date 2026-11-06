import { describe, expect, test } from "bun:test"
import * as os from "node:os"
import * as path from "node:path"
import {
  TOOLS, getTool, toolDir, workDir, toolStatus, buildArgv, runArgv, updateArgv, groups,
} from "../src/tools"

describe("registry", () => {
  test("has the expected tools and groups", () => {
    expect(TOOLS.length).toBe(15)
    expect(getTool("cau")?.lang).toBe("Go")
    expect(groups()).toContain("Integrations")
  })

  test("path resolution: base vs absolute (dcr-mcp)", () => {
    const base = "/tmp/base"
    expect(toolDir(base, getTool("cau")!)).toBe("/tmp/base/cau")
    expect(workDir(base, getTool("rustforce")!)).toBe("/tmp/base/rustforce/force/ftp")
    const dcr = getTool("dcr-mcp")!
    expect(toolDir(base, dcr)).toBe(path.join(os.homedir(), "Projects", "dcr-mcp"))
  })

  test("status is 'not cloned' when the dir is absent", () => {
    const s = toolStatus("/no/such/base", getTool("cau")!)
    expect(s.state).toBe("missing")
  })

  test("argv builders", () => {
    const base = "/tmp/base"
    const cau = getTool("cau")!
    const b = buildArgv(base, cau)!
    expect(b[b.length - 1]).toContain("go build -o cau")
    expect(b[b.length - 1]).toContain("/tmp/base/cau")

    // openhack run uses a hard cap (MemoryMax + swap off) when systemd-run exists
    const oh = runArgv(base, getTool("openhack")!)!
    const joined = oh.join(" ")
    expect(joined).toContain("bun run packages/openhack-cli/src/index.ts")

    // docs tools have no build/run
    expect(buildArgv(base, getTool("cardsz")!)).toBeNull()
    expect(runArgv(base, getTool("cardsz")!)).toBeNull()

    // dcr-mcp is noGit -> no update
    expect(updateArgv(base, getTool("dcr-mcp")!)).toBeNull()
    expect(updateArgv(base, getTool("cau")!)![2]).toContain("git pull --ff-only")
  })
})
