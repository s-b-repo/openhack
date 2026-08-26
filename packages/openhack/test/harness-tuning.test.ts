// Harness self-tuning pickup — `bench:tune` persists the measured winner to
// `.openhack/harness-tuning.json` and automode adopts it as the default
// frontier width. Verify:
//
//   • Valid file → recommended.frontier_k returned (clamped to [1, 20]).
//   • Missing / corrupt file → undefined (explicit flags and config win).
//   • Out-of-range values clamp; garbage types → undefined.

import { describe, expect, test, beforeEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { tunedFrontierK } from "../../openhack-cli/src/cli/cmd/openhack.automode"

let tmpdir: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), "tuning-test-"))
  process.chdir(tmpdir)
  return () => process.chdir(origCwd)
})

function writeTuning(doc: unknown): void {
  fs.mkdirSync(".openhack", { recursive: true })
  fs.writeFileSync(path.join(".openhack", "harness-tuning.json"), JSON.stringify(doc))
}

describe("tunedFrontierK", () => {
  test("no tuning file → undefined", () => {
    expect(tunedFrontierK()).toBeUndefined()
  })

  test("valid recommendation is returned", () => {
    writeTuning({ target: "example.com", recommended: { frontier_k: 4, instances: 1 } })
    expect(tunedFrontierK()).toBe(4)
  })

  test("values above the 20 cap clamp down", () => {
    writeTuning({ recommended: { frontier_k: 500 } })
    expect(tunedFrontierK()).toBe(20)
  })

  test("zero / negative / non-numeric recommendations are ignored", () => {
    writeTuning({ recommended: { frontier_k: 0 } })
    expect(tunedFrontierK()).toBeUndefined()
    writeTuning({ recommended: { frontier_k: -3 } })
    expect(tunedFrontierK()).toBeUndefined()
    writeTuning({ recommended: { frontier_k: "wide" } })
    expect(tunedFrontierK()).toBeUndefined()
  })

  test("corrupt JSON → undefined, never throws", () => {
    fs.mkdirSync(".openhack", { recursive: true })
    fs.writeFileSync(path.join(".openhack", "harness-tuning.json"), "{not json")
    expect(tunedFrontierK()).toBeUndefined()
  })

  test("missing recommended block → undefined", () => {
    writeTuning({ target: "example.com", grid: [] })
    expect(tunedFrontierK()).toBeUndefined()
  })
})
