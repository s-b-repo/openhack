// Opt-in knowledge refresh — rebuilds packages/openhack/knowledge/*.json from
// upstream sources. Never runs at boot. Invoke with:
//
//   bun run packages/openhack/script/ingest-knowledge.ts
//
// PayloadsAllTheThings: shallow-clones the repo to a scratch dir, walks the top
// level, and updates the payloadsallthethings-index.json version string. It does
// NOT auto-generate family entries — those are curated by hand for signal
// quality (Swissky's directory layout is *categories* of payloads, not families).
// The script emits a diff report showing which top-level categories exist
// upstream vs. what our index covers, so the maintainer can see what needs
// backfilling in one glance.
//
// HackTricks: URLs are curated by hand. This script only refreshes the
// hacktricks-index.json version field. book.hacktricks.wiki's ToC is dynamic
// and blindly scraping it is brittle.
//
// WSTG: same. Curated by hand.
//
// Exits non-zero if the network / git isn't available, so CI can gate on it.
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"

const KNOWLEDGE_DIR = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "..", "knowledge")
const PAT_INDEX = path.join(KNOWLEDGE_DIR, "payloadsallthethings-index.json")
const HT_INDEX = path.join(KNOWLEDGE_DIR, "hacktricks-index.json")
const WSTG_INDEX = path.join(KNOWLEDGE_DIR, "wstg-index.json")

const today = new Date().toISOString().slice(0, 10)

function log(msg: string) { process.stdout.write(msg + os.EOL) }
function warn(msg: string) { process.stderr.write(`! ${msg}` + os.EOL) }

function shallowClone(url: string, dest: string): boolean {
  const r = spawnSync("git", ["clone", "--depth=1", url, dest], { stdio: "pipe", encoding: "utf-8" })
  if (r.status !== 0) {
    warn(`git clone failed for ${url}: ${r.stderr?.trim()}`)
    return false
  }
  return true
}

function readIndex(fp: string): any {
  return JSON.parse(fs.readFileSync(fp, "utf-8"))
}

function writeIndex(fp: string, obj: any): void {
  fs.writeFileSync(fp, JSON.stringify(obj, null, 2) + "\n", "utf-8")
}

// ── PayloadsAllTheThings ──────────────────────────────────────────────────

function refreshPayloadsAllTheThings(): boolean {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "openhack-pat-"))
  try {
    log(`▶ Cloning swisskyrepo/PayloadsAllTheThings → ${scratch}`)
    if (!shallowClone("https://github.com/swisskyrepo/PayloadsAllTheThings.git", scratch)) return false
    // Top-level upstream categories are directory names.
    const upstreamCategories = fs.readdirSync(scratch, { withFileTypes: true })
      .filter((d) => d.isDirectory() && !d.name.startsWith("."))
      .map((d) => d.name)
      .sort()

    const idx = readIndex(PAT_INDEX)
    idx.version = today
    writeIndex(PAT_INDEX, idx)

    // Diff report — help the maintainer see what upstream categories aren't
    // represented in the taxonomy yet.
    log(`\n▶ PayloadsAllTheThings — upstream categories vs. our taxonomy`)
    const ourPaths = new Set<string>()
    for (const arr of Object.values<any[]>(idx.byClass)) {
      for (const f of arr) ourPaths.add(String(f.upstreamPath).split("/")[0]!)
    }
    let missing = 0
    for (const cat of upstreamCategories) {
      const hit = ourPaths.has(cat)
      if (!hit) missing++
      log(`  ${hit ? "✓" : " "} ${cat}`)
    }
    if (missing) log(`\n  ${missing} upstream categor${missing === 1 ? "y" : "ies"} not yet mapped — consider curating.`)
    log(`▶ Updated ${PAT_INDEX} version → ${today}`)
    return true
  } finally {
    try { fs.rmSync(scratch, { recursive: true, force: true }) } catch {}
  }
}

// ── HackTricks (version bump only) ─────────────────────────────────────────

function refreshHacktricks(): boolean {
  const idx = readIndex(HT_INDEX)
  idx.version = today
  writeIndex(HT_INDEX, idx)
  log(`▶ Updated ${HT_INDEX} version → ${today} (curated URLs unchanged — audit by hand)`)
  return true
}

// ── WSTG (version bump only) ───────────────────────────────────────────────

function refreshWstg(): boolean {
  const idx = readIndex(WSTG_INDEX)
  idx.version = today
  writeIndex(WSTG_INDEX, idx)
  log(`▶ Updated ${WSTG_INDEX} version → ${today} (curated ids unchanged — audit by hand)`)
  return true
}

// ── main ──────────────────────────────────────────────────────────────────

let ok = true
if (!refreshPayloadsAllTheThings()) ok = false
if (!refreshHacktricks()) ok = false
if (!refreshWstg()) ok = false

if (!ok) {
  warn("One or more knowledge indexes could not be refreshed.")
  process.exit(1)
}
log(`\n▶ Knowledge indexes refreshed successfully.`)
