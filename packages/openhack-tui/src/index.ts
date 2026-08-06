// OpenHack TUI dashboard — live view of the loop.
//
// Zero-dependency terminal renderer (ANSI escapes only, no blessed / ink / etc.).
// Reads engagement state directly from `.openhack/` and refreshes every 500 ms:
//
//   ┌── golecloud.co.za · signed ROE · main model = deepseek/deepseek-v4 ─┐
//   │  ┌─ Rounds ─────────────┐  ┌─ Frontier ─────────┐  ┌─ Findings ─┐ │
//   │  │  round 3 / 10        │  │  queued:  6         │  │  4 total   │ │
//   │  │  cost   $0.42        │  │  dispatched: 12     │  │  2 critical│ │
//   │  │  RSS    78 MB        │  │  blocked:  1        │  │  1 high    │ │
//   │  └──────────────────────┘  └─────────────────────┘  └────────────┘ │
//   │  ┌─ Combinatorial checklist ─────────────────────────────────────┐ │
//   │  │  universe 1899 · satisfied 24 · open 1875 (98%)               │ │
//   │  │  methods 12 · payloads 4 · chains 20 · per-finding 4 findings │ │
//   │  └────────────────────────────────────────────────────────────────┘ │
//   │  ┌─ Recent rounds (tail .openhack/rounds/*.jsonl) ────────────────┐│
//   │  │ r3 22:14:03  +2f (+1h) $0.10 cov 4.2%  frontier 6              ││
//   │  │ r2 22:13:41  +1f (+0h) $0.11 cov 3.5%  frontier 8              ││
//   │  │ r1 22:13:19  +2f (+2h) $0.15 cov 2.1%  frontier 12             ││
//   │  └────────────────────────────────────────────────────────────────┘│
//   │  q quit · r redraw · t change target · press any key ...           │
//   └──────────────────────────────────────────────────────────────────────┘
//
// Usage:
//   openhack-tui                                # auto-detects the first target
//   openhack-tui --target golecloud.co.za       # explicit
//   openhack-tui --engagement-dir /path         # honour engagement dir

import * as fs from "node:fs"
import * as path from "node:path"

// ─── colors ──────────────────────────────────────────────────────────────
const GRAY = "\x1b[90m", BOLD = "\x1b[1m", CYAN = "\x1b[36m", GREEN = "\x1b[32m", YELLOW = "\x1b[33m", RED = "\x1b[31m", DIM = "\x1b[2m", RESET = "\x1b[0m"
const CLEAR = "\x1b[2J\x1b[H"
const HIDE_CURSOR = "\x1b[?25l"
const SHOW_CURSOR = "\x1b[?25h"

// ─── argv ────────────────────────────────────────────────────────────────
function argVal(k: string, dflt?: string): string | undefined {
  const i = process.argv.indexOf(`--${k}`)
  return i >= 0 ? process.argv[i + 1] : dflt
}
const ENGAGEMENT_DIR = path.resolve(argVal("engagement-dir") ?? process.cwd())
let TARGET = argVal("target")
const REFRESH_MS = Number(argVal("refresh-ms", "500"))
const MAX_RECENT_ROUNDS = 10

// ─── autoloaders ─────────────────────────────────────────────────────────
function safeReadJson<T>(p: string, dflt: T): T {
  try { return JSON.parse(fs.readFileSync(p, "utf-8")) as T } catch { return dflt }
}

function autodetectTarget(): string | undefined {
  const dir = path.join(ENGAGEMENT_DIR, ".openhack", "rounds")
  try {
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".jsonl"))
    if (files.length) return files[0]!.replace(/\.jsonl$/, "")
  } catch {}
  try {
    const dir2 = path.join(ENGAGEMENT_DIR, ".openhack", "findings")
    const files = fs.readdirSync(dir2).filter((f) => f.endsWith(".json") && !f.startsWith("."))
    if (files.length) return files[0]!.replace(/\.json$/, "")
  } catch {}
  return undefined
}

function loadRounds(target: string): any[] {
  const fp = path.join(ENGAGEMENT_DIR, ".openhack", "rounds", `${target.replace(/[^a-zA-Z0-9.-]/g, "_")}.jsonl`)
  try {
    return fs.readFileSync(fp, "utf-8").trim().split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean)
  } catch { return [] }
}

function loadFindings(target: string): { total: number; bySeverity: Record<string, number>; byStatus: Record<string, number> } {
  const fp = path.join(ENGAGEMENT_DIR, ".openhack", "findings", `${target.replace(/[^a-zA-Z0-9.-]/g, "_")}.json`)
  const store = safeReadJson<any>(fp, { totalCount: 0, bySeverity: {}, byStatus: {} })
  return { total: store.totalCount ?? 0, bySeverity: store.bySeverity ?? {}, byStatus: store.byStatus ?? {} }
}

function loadROE(): any | null {
  return safeReadJson(path.join(ENGAGEMENT_DIR, ".openhack", "roe", "active.roe.json"), null)
}

function loadModels(): any {
  return safeReadJson(path.join(ENGAGEMENT_DIR, ".openhack", "models.json"), { main: "(default)" })
}

function loadGraph(target: string): { nodes: number; queued: number; dispatched: number; blocked: number; done: number } {
  const fp = path.join(ENGAGEMENT_DIR, ".openhack", "graph", `${target.replace(/[^a-zA-Z0-9.-]/g, "_")}.json`)
  const snap = safeReadJson<any>(fp, { nodes: {} })
  const nodes = Object.values(snap.nodes ?? {})
  const actions = nodes.filter((n: any) => typeof n?.objective === "string")
  const count = (s: string) => actions.filter((a: any) => a.status === s).length
  return { nodes: nodes.length, queued: count("queued"), dispatched: count("dispatched"), blocked: count("blocked"), done: count("done") }
}

function loadCombos(target: string): { open: number; universe: number; satisfied: number; methods: number; payloads: number; chains: number; perFinding: number } | null {
  // Combos live in the checklist artefact under .openhack/checklists/<target>.md, but that's
  // rendered on demand. Easier: read the last round's telemetry which snapshots combos.
  const rounds = loadRounds(target)
  const last = rounds[rounds.length - 1]
  if (!last) return null
  return {
    open: last.combos?.open ?? 0,
    universe: last.combos?.universeSize ?? 0,
    satisfied: last.combos?.satisfiedSize ?? 0,
    methods: 0, payloads: 0, chains: 0, perFinding: 0,
  }
}

// ─── rendering helpers ───────────────────────────────────────────────────
function pad(s: string, w: number): string {
  // Strip ANSI to measure visible width.
  const visible = s.replace(/\x1b\[[0-9;]*m/g, "").length
  if (visible >= w) return s
  return s + " ".repeat(w - visible)
}

function box(title: string, lines: string[], width: number): string[] {
  const top = `${GRAY}┌─ ${BOLD}${title}${RESET}${GRAY} ${"─".repeat(Math.max(1, width - title.length - 4))}┐${RESET}`
  const bot = `${GRAY}└${"─".repeat(width - 2)}┘${RESET}`
  const body = lines.map((l) => `${GRAY}│${RESET} ${pad(l, width - 4)} ${GRAY}│${RESET}`)
  return [top, ...body, bot]
}

function h3(label: string, val: string): string { return `${GRAY}${label}${RESET}  ${BOLD}${val}${RESET}` }

function severityBadge(sev: string, n: number): string {
  const color = sev === "critical" ? RED : sev === "high" ? YELLOW : sev === "medium" ? CYAN : GRAY
  return `${color}${sev.padEnd(9)}${RESET} ${BOLD}${n}${RESET}`
}

// ─── one frame ───────────────────────────────────────────────────────────
function render(): string {
  const target = TARGET ?? autodetectTarget()
  const width = Math.min(process.stdout.columns ?? 100, 110)
  if (!target) {
    return `${CLEAR}${YELLOW}No engagement target detected in ${ENGAGEMENT_DIR}/.openhack/.\n\n` +
      `Try:  ${BOLD}openhack-tui --target <name>${RESET}\n` +
      `Or run ${BOLD}openhack automode --target <t> --loop${RESET} first, then reopen this dashboard.\n`
  }
  const roe = loadROE()
  const models = loadModels()
  const rounds = loadRounds(target)
  const graph = loadGraph(target)
  const findings = loadFindings(target)
  const combos = loadCombos(target)
  const last = rounds[rounds.length - 1]
  const lastRss = last?.rssMb ?? 0
  const totalCost = last?.totalCostUsd ?? 0
  const nowRound = last?.round ?? 0

  const out: string[] = []
  out.push(CLEAR)
  const banner = `${BOLD}${CYAN}openhack-tui${RESET} ${GRAY}·${RESET} ${BOLD}${target}${RESET}` +
    ` ${GRAY}·${RESET} ${roe ? (roe.status === "signed" ? `${GREEN}ROE signed${RESET}` : `${YELLOW}ROE ${roe.status}${RESET}`) : `${YELLOW}no ROE${RESET}`}` +
    ` ${GRAY}·${RESET} model=${models.custom ?? models.main}`
  out.push(banner)
  out.push("")

  // Top row — three side-by-side stat blocks.
  const roundsBlock = box("Rounds", [
    h3("round ", `${nowRound}`),
    h3("cost  ", `$${Number(totalCost).toFixed(3)}`),
    h3("RSS   ", `${lastRss} MB`),
    h3("last  ", last?.at ? String(last.at).slice(11, 19) : "n/a"),
  ], Math.floor((width - 6) / 3))
  const frontierBlock = box("Frontier", [
    h3("queued    ", `${graph.queued}`),
    h3("dispatched", `${graph.dispatched}`),
    h3("blocked   ", `${graph.blocked}`),
    h3("done      ", `${graph.done}`),
  ], Math.floor((width - 6) / 3))
  const findingsBlock = box("Findings", [
    h3("total  ", `${findings.total}`),
    severityBadge("critical", findings.bySeverity.critical ?? 0),
    severityBadge("high", findings.bySeverity.high ?? 0),
    severityBadge("verified", findings.byStatus.verified ?? 0),
  ], Math.floor((width - 6) / 3))
  const rows = Math.max(roundsBlock.length, frontierBlock.length, findingsBlock.length)
  for (let i = 0; i < rows; i++) {
    out.push(`  ${roundsBlock[i] ?? ""}  ${frontierBlock[i] ?? ""}  ${findingsBlock[i] ?? ""}`)
  }
  out.push("")

  // Combinatorial checklist
  if (combos && combos.universe > 0) {
    const pct = combos.universe ? Math.round((combos.open / combos.universe) * 100) : 0
    const bar = renderBar(1 - combos.open / (combos.universe || 1), width - 30)
    out.push(...box("Combinatorial checklist", [
      `universe ${BOLD}${combos.universe}${RESET} · satisfied ${GREEN}${combos.satisfied}${RESET} · open ${YELLOW}${combos.open}${RESET} (${pct}%)`,
      `${bar}  ${GRAY}(closed)${RESET}`,
    ], width - 4))
    out.push("")
  }

  // Recent rounds tail
  const recent = rounds.slice(-MAX_RECENT_ROUNDS)
  const recentLines = recent.length ? recent.map((r: any) => {
    const t = String(r.at ?? "").slice(11, 19)
    const nf = r.newFindings ?? 0, nh = r.newHigh ?? 0
    return `r${String(r.round).padStart(2)} ${GRAY}${t}${RESET} ${nf >= 0 ? "+" : ""}${nf}f (+${nh}h) $${Number(r.roundCostUsd ?? 0).toFixed(3)}  cov ${r.coverage?.percent ?? 0}%  frontier ${r.frontierSize}`
  }) : [`${DIM}(no rounds recorded yet — start the loop with ${BOLD}openhack automode --target ${target} --loop --graph${RESET})${RESET}`]
  out.push(...box("Recent rounds (tail .openhack/rounds/*.jsonl)", recentLines, width - 4))
  out.push("")

  out.push(`  ${DIM}refresh ${REFRESH_MS}ms · q quit · r redraw · engagement ${ENGAGEMENT_DIR}${RESET}`)
  return out.join("\n")
}

function renderBar(fraction: number, width: number): string {
  const filled = Math.max(0, Math.min(width, Math.round(width * fraction)))
  return `${GREEN}${"█".repeat(filled)}${GRAY}${"░".repeat(width - filled)}${RESET}`
}

// ─── main loop ───────────────────────────────────────────────────────────
async function main(): Promise<void> {
  process.stdout.write(HIDE_CURSOR)
  const draw = () => process.stdout.write(render())
  draw()
  const timer = setInterval(draw, REFRESH_MS)

  // Raw-mode keys for q / r.
  const stdin: any = process.stdin
  if (stdin.isTTY) {
    stdin.setRawMode(true)
    stdin.resume()
    stdin.setEncoding("utf-8")
    stdin.on("data", (key: string) => {
      if (key === "q" || key === "") {
        clearInterval(timer)
        process.stdout.write(SHOW_CURSOR + "\n")
        process.exit(0)
      }
      if (key === "r") draw()
    })
  }
  const cleanup = () => { clearInterval(timer); process.stdout.write(SHOW_CURSOR + "\n"); process.exit(0) }
  process.on("SIGINT", cleanup)
  process.on("SIGTERM", cleanup)
}

main().catch((e) => { process.stdout.write(SHOW_CURSOR); console.error(e); process.exit(1) })
