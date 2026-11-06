/**
 * @openhack-ai/tools — a registry + actions for the open-source security tools
 * cloned under a base directory (default ~/Projects/store-tools).
 *
 * Native TypeScript port of the Tool Manager, for OpenHack. This module is the
 * pure logic (registry, path resolution, status, command building, memory-cap
 * wrapping); the `openhack tools` CLI command drives the actual process spawning.
 *
 * Memory note: this box is RAM-constrained. When systemd-run + cgroup v2 are
 * present, builds run under a soft MemoryHigh throttle and OpenHack runs under a
 * hard MemoryMax with swap disabled, so a runaway can't freeze the machine.
 */
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { execSync } from "node:child_process"

export type Lang = "Rust" | "Go" | "Python" | "Bun/TS" | "PowerShell" | "Docs"
export type StatusState = "ok" | "warn" | "none" | "missing"

export interface Tool {
  key: string
  name: string
  lang: Lang
  group: string
  desc: string
  repo?: string
  absDir?: string // absolute location (overrides base/key)
  subdir?: string // crate/run dir within the repo
  noGit?: boolean
  buildCap?: string // MemoryHigh for the build
  build?: string // shell snippet (run in workDir)
  run?: string // shell snippet (run in workDir); interactive ok
  runHardCap?: string // if set, run under MemoryMax=<cap> + swap off
  status: (dir: string) => { text: string; state: StatusState }
}

export function defaultBase(): string {
  return path.join(os.homedir(), "Projects", "store-tools")
}

export function hasSystemdRun(): boolean {
  try {
    execSync("command -v systemd-run", { stdio: "ignore" })
    return true
  } catch {
    return false
  }
}

export function toolDir(base: string, t: Tool): string {
  if (t.absDir) return t.absDir.replace(/^~(?=$|\/)/, os.homedir())
  return path.join(base, t.key)
}
export function workDir(base: string, t: Tool): string {
  const d = toolDir(base, t)
  return t.subdir ? path.join(d, t.subdir) : d
}

const exists = (p: string) => fs.existsSync(p)
const built = (p: string) => (exists(p) ? { text: "built", state: "ok" as const } : { text: "needs build", state: "warn" as const })

export const TOOLS: Tool[] = [
  // ---- offensive & recon ----
  {
    key: "Quicmap", name: "Quicmap", lang: "Python", group: "Offensive & recon",
    desc: "QUIC / HTTP-3 port scanner with banner grabbing.",
    repo: "https://github.com/s-b-repo/Quicmap",
    build: "python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt",
    run: "./.venv/bin/python qmap.py --help; echo; echo 'Example: ./.venv/bin/python qmap.py <host> -p 443,8443 -v'; exec bash",
    status: (d) => (exists(path.join(d, ".venv")) ? { text: "venv ready", state: "ok" } : { text: "needs build (venv)", state: "warn" }),
  },
  {
    key: "rustsploit", name: "Rustsploit", lang: "Rust", group: "Offensive & recon",
    desc: "Modular exploitation framework for embedded / IoT targets.",
    repo: "https://github.com/s-b-repo/rustsploit", build: "cargo build --release", buildCap: "5G",
    run: "./target/release/rustsploit --help; echo; exec bash",
    status: (d) => built(path.join(d, "target/release/rustsploit")),
  },
  {
    key: "rustforce", name: "Rustforce", lang: "Rust", group: "Offensive & recon",
    desc: "Credential-testing toolkit (FTP/SSH/Telnet); FTP binary = dftp.",
    repo: "https://github.com/s-b-repo/rustforce", subdir: "force/ftp", build: "cargo build --release",
    run: "echo 'dftp enters scan mode immediately (no --help). See HOW TO USE.txt'; ls; exec bash",
    status: (d) => built(path.join(d, "force/ftp/target/release/dftp")),
  },
  {
    key: "openhack", name: "OpenHack", lang: "Bun/TS", group: "Offensive & recon",
    desc: "AI-powered security-assessment agent (this project). Run under a hard memory cap.",
    repo: "https://github.com/s-b-repo/openhack", build: "bun install", buildCap: "3G",
    run: "bun run packages/openhack-cli/src/index.ts", runHardCap: "3G",
    status: (d) => (exists(path.join(d, "node_modules")) ? { text: "deps installed", state: "ok" } : { text: "needs build (bun install)", state: "warn" }),
  },
  // ---- command & control ----
  {
    key: "arcticfox-c3", name: "ArcticFox-C3", lang: "Rust", group: "Command & control",
    desc: "Command-and-control framework (agent / API / c3 dashboard).",
    repo: "https://github.com/s-b-repo/arcticfox-c3", build: "cargo build --release", buildCap: "5G",
    run: "./target/release/c3 --help 2>&1 | head -40; echo; exec bash",
    status: (d) => built(path.join(d, "target/release/c3")),
  },
  // ---- blue team & detection ----
  {
    key: "cau", name: "CAU", lang: "Go", group: "Blue team & detection",
    desc: "Transparent malware-detection engine (14 detectors, ATT&CK).",
    repo: "https://github.com/s-b-repo/cau", build: "go build -o cau .",
    run: "./cau --help; echo; echo '— press Enter to close —'; read",
    status: (d) => built(path.join(d, "cau")),
  },
  {
    key: "elastacat", name: "Elastacat", lang: "Python", group: "Blue team & detection",
    desc: "Elastic + TheHive/Cortex installer (Debian 12, root).",
    repo: "https://github.com/s-b-repo/elastacat",
    run: "echo 'Installer for Debian 12, run as root — review first.'; echo 'Run: sudo python3 elscat.py'; exec bash",
    status: () => ({ text: "installer", state: "none" }),
  },
  {
    key: "docker-wazuh-installer-py", name: "Wazuh Installer", lang: "Python", group: "Blue team & detection",
    desc: "Dockerised Wazuh installer (Debian/Ubuntu, root + Docker).",
    repo: "https://github.com/s-b-repo/docker-wazuh-installer-py",
    run: "echo 'Needs root + Docker on Debian/Ubuntu.'; echo 'Run: sudo python3 debian_install_wazuh.py'; exec bash",
    status: () => ({ text: "installer", state: "none" }),
  },
  {
    key: "p2soc", name: "p2soc", lang: "Python", group: "Blue team & detection",
    desc: "Raspberry Pi 5 SOC video wall. Interactive setup wizard.",
    repo: "https://github.com/s-b-repo/p2soc",
    run: "echo 'SOC video wall. Reference target: Raspberry Pi 5 (GTK + display).'; python3 setup.py --help; echo; exec bash",
    status: () => ({ text: "wizard", state: "none" }),
  },
  {
    key: "windows-hardening", name: "Windows Hardening", lang: "PowerShell", group: "Blue team & detection",
    desc: "Windows hardening baseline (harden.ps1). Windows-only.",
    repo: "https://github.com/s-b-repo/windows-hardening",
    status: () => ({ text: "Windows-only", state: "none" }),
  },
  // ---- infrastructure & integration ----
  {
    key: "peregrine", name: "Peregrine", lang: "Rust", group: "Infrastructure & integration",
    desc: "Rust MoE inference engine (CPU default; CUDA optional).",
    repo: "https://github.com/s-b-repo/peregrine", build: "cargo build --release", buildCap: "5G",
    run: "./target/release/peregrine --help 2>&1 | head -40; echo; echo '— press Enter to close —'; read",
    status: (d) => built(path.join(d, "target/release/peregrine")),
  },
  {
    key: "onlyoffice-mcp-server", name: "OnlyOffice MCP", lang: "Python", group: "Infrastructure & integration",
    desc: "MCP server for Office docs (stdio). Pinned to mcp<2.",
    repo: "https://github.com/s-b-repo/onlyoffice-mcp-server",
    build: "python3 -m venv .venv && ./.venv/bin/pip install -e . 'mcp<2'",
    run: "echo 'stdio MCP server: starts and waits on stdin. Ctrl-C to stop.'; ./.venv/bin/onlyoffice-mcp; exec bash",
    status: (d) => (exists(path.join(d, ".venv")) ? { text: "venv ready", state: "ok" } : { text: "needs build (venv)", state: "warn" }),
  },
  // ---- reference guides ----
  {
    key: "cardsz", name: "Cardsz", lang: "Docs", group: "Reference guides",
    desc: "RFID/NFC assessment methodology (Proxmark3). Documentation.",
    repo: "https://github.com/s-b-repo/cardsz", status: () => ({ text: "guide", state: "none" }),
  },
  {
    key: "advanced-shodan-requests", name: "Advanced Shodan", lang: "Docs", group: "Reference guides",
    desc: "Curated Shodan attack-surface queries. Documentation.",
    repo: "https://github.com/s-b-repo/advanced-shodan-requests", status: () => ({ text: "reference", state: "none" }),
  },
  // ---- integrations ----
  {
    key: "dcr-mcp", name: "DCR Memory Bridge (dcr-mcp)", lang: "Python", group: "Integrations",
    desc: "MCP↔DCR bridge: long-term memory for OpenHack backed by subnext/DCR. Build=venv; Run=start dcr serve (needs subnext built).",
    absDir: path.join(os.homedir(), "Projects", "dcr-mcp"), noGit: true,
    build: "python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt",
    run: "echo 'Starting the DCR backend (dcr serve). Leave running; wire into OpenHack via openhack.dcr.jsonc.'; ./serve-dcr.sh; echo; echo '— dcr serve exited —'; read",
    status: (d) => (exists(path.join(d, ".venv")) ? { text: "venv ready", state: "ok" } : { text: "needs build (venv)", state: "warn" }),
  },
]

export function getTool(key: string): Tool | undefined {
  return TOOLS.find((t) => t.key === key || t.name === key)
}

export function toolStatus(base: string, t: Tool): { text: string; state: StatusState } {
  const d = toolDir(base, t)
  if (!exists(d)) return { text: "not cloned", state: "missing" }
  return t.status(d)
}

/** Wrap a `bash -lc` command string with a systemd-run cgroup memory cap. */
export function cappedArgv(bashCmd: string, opts: { high?: string; max?: string; noswap?: boolean }): string[] {
  if (hasSystemdRun() && (opts.high || opts.max)) {
    const pre = ["systemd-run", "--user", "--scope", "-q"]
    if (opts.high) pre.push("-p", `MemoryHigh=${opts.high}`)
    if (opts.max) pre.push("-p", `MemoryMax=${opts.max}`)
    if (opts.noswap) pre.push("-p", "MemorySwapMax=0")
    return [...pre, "--", "bash", "-lc", bashCmd]
  }
  return ["bash", "-lc", bashCmd]
}

/** argv for building a tool (soft MemoryHigh throttle). */
export function buildArgv(base: string, t: Tool): string[] | null {
  if (!t.build) return null
  const d = workDir(base, t)
  const cmd = `cd ${shq(d)} && ${t.build}`
  return cappedArgv(cmd, { high: t.buildCap || "4G" })
}

/** argv for running a tool (hard cap if runHardCap set). */
export function runArgv(base: string, t: Tool): string[] | null {
  if (!t.run) return null
  const d = workDir(base, t)
  const cmd = `cd ${shq(d)}; ${t.run}`
  if (t.runHardCap) return cappedArgv(`cd ${shq(d)} && ${t.run}`, { max: t.runHardCap, noswap: true })
  return ["bash", "-lc", cmd]
}

export function updateArgv(base: string, t: Tool): string[] | null {
  if (t.noGit) return null
  const d = toolDir(base, t)
  return ["bash", "-lc", `cd ${shq(d)} && git pull --ff-only`]
}

function shq(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'"
}

export function groups(): string[] {
  const seen: string[] = []
  for (const t of TOOLS) if (!seen.includes(t.group)) seen.push(t.group)
  return seen
}
