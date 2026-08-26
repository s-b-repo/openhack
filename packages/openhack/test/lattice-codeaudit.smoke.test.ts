// Smoke test for the Lattice code-audit bridge (.openhack/tool/lattice-codeaudit.sh).
//
// Runs the real bridge script against a tiny fixture with a STUB lattice
// engine ($OPENHACK_LATTICE_BIN) so no venv/LSP/network is needed. Verifies:
//   • engine resolution: override wins; nothing resolvable → exit 2 with hint
//   • per-leg invocation shape: ingest --lang auto, then hunt/secaudit/diagnose/triage
//   • severity rollup across legs drives the exit code (0 clean / 1 crit-high)
//   • report.md + LATTICE_CODEAUDIT summary line are produced

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { spawnSync } from "node:child_process"

const REPO_ROOT = path.resolve(__dirname, "../../..")
const BRIDGE = path.join(REPO_ROOT, ".openhack", "tool", "lattice-codeaudit.sh")

let tmp: string
let origCwd: string

beforeEach(() => {
  origCwd = process.cwd()
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lattice-bridge-"))
  process.chdir(tmp)
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(tmp, { recursive: true, force: true })
})

/**
 * Stub engine: logs every invocation to $STUB_LOG, emits canned JSON per leg.
 * Finding severities come from $STUB_SEVERITY ("clean" → all low), so the
 * bridge's rollup — not the stub's exit codes — decides the final status.
 */
function makeStub(): string {
  const bin = path.join(tmp, "stub-lattice")
  const script = `#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
leg="$1"
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--out" ]; then out="$a"; fi
  prev="$a"
done
case "$leg" in
  ingest)
    echo '{"nodes": 3}'
    ;;
  hunt|secaudit|diagnose)
    if [ -n "$out" ]; then
      if [ "$STUB_SEVERITY" = "clean" ]; then
        echo '[{"severity": "low", "title": "minor"}]' > "$out"
      else
        printf '[{"severity": "%s", "title": "stub finding"}]' "$STUB_SEVERITY" > "$out"
      fi
    fi
    exit 0
    ;;
  triage)
    if [ -n "$out" ]; then echo '[{"symbol": "run", "rank": 1}]' > "$out"; fi
    exit 0
    ;;
esac
exit 0
`
  fs.writeFileSync(bin, script)
  fs.chmodSync(bin, 0o755)
  return bin
}

function makeFixture(name = "target"): string {
  const dir = path.join(tmp, name)
  fs.mkdirSync(dir)
  fs.writeFileSync(path.join(dir, "app.py"), "def run(cmd):\n    return cmd\n")
  return dir
}

function runBridge(target: string, extraEnv: Record<string, string>) {
  return spawnSync("bash", [BRIDGE, target, "--quiet"], {
    cwd: tmp,
    encoding: "utf-8",
    env: { ...process.env, ...extraEnv },
  })
}

describe("lattice-codeaudit bridge", () => {
  test("exit 2 when the explicit engine override is not executable", () => {
    const p = runBridge(makeFixture(), { OPENHACK_LATTICE_BIN: path.join(tmp, "nope") })
    expect(p.status).toBe(2)
    expect(p.stderr).toMatch(/OPENHACK_LATTICE_BIN is set but not executable/)
  })

  test("override engine runs all four legs; critical findings → exit 1 + report", () => {
    const log = path.join(tmp, "calls.log")
    const stub = makeStub()
    const p = runBridge(makeFixture(), { OPENHACK_LATTICE_BIN: stub, STUB_LOG: log, STUB_SEVERITY: "critical" })
    expect(p.status).toBe(1)
    const calls = fs.readFileSync(log, "utf-8")
    expect(calls).toMatch(/ingest \S+ --lang auto/)
    for (const leg of ["hunt", "secaudit", "diagnose", "triage"]) {
      expect(calls).toMatch(new RegExp(`^${leg} \\S+ --lang auto`, "m"))
    }
    expect(p.stdout).toMatch(/LATTICE_CODEAUDIT .*critical=3.*engine=\S*stub-lattice/)
    const outDir = path.join(tmp, ".openhack", "codeaudit")
    expect(fs.existsSync(path.join(outDir, "target-latest"))).toBe(true)
    const report = fs.readFileSync(path.join(outDir, "target-latest", "report.md"), "utf-8")
    expect(report).toMatch(/# Lattice code-audit — target/)
    expect(report).toMatch(/### secaudit/)
    expect(report).toMatch(/\*\*Engine:\*\*/)
  })

  test("clean stub rollup exits 0", () => {
    const stub = makeStub()
    const p = runBridge(makeFixture("cleantgt"), { OPENHACK_LATTICE_BIN: stub, STUB_LOG: path.join(tmp, "c2.log"), STUB_SEVERITY: "low" })
    expect(p.status).toBe(0)
    expect(p.stdout).toMatch(/critical=0 high=0 medium=0 low=3/) // 3 rolled-up legs × 1 low
  })

  test("non-directory target exits 2 before any engine lookup", () => {
    const p = spawnSync("bash", [BRIDGE, path.join(tmp, "missing"), "--quiet"], {
      cwd: tmp,
      encoding: "utf-8",
      env: { ...process.env, PATH: "/usr/bin:/bin" },
    })
    expect(p.status).toBe(2)
    expect(p.stderr).toMatch(/not a directory/)
  })
})
