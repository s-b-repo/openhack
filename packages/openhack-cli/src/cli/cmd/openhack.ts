import { cmd } from "./cmd"
import { EOL } from "node:os"
import * as fs from "node:fs"
import { execSync } from "node:child_process"
import * as crypto from "node:crypto"
import { Orchestrator } from "../../../../openhack/src/orchestrator"
import { Advisor } from "../../../../openhack/src/advisor"
import { MOERouter } from "../../../../openhack/src/moe-router"
import { GlobalConfig } from "../../../../openhack/src/global-config"
import { ROE } from "../../../../openhack/src/roe"
import { Findings } from "../../../../openhack/src/findings"
import { ConfigStore } from "../../../../openhack/src/config-store"
import { Checklist } from "../../../../openhack/src/checklist"
import { Coverage } from "../../../../openhack/src/coverage"
import { Combinations } from "../../../../openhack/src/combinations"
import { RoundBudget } from "../../../../openhack/src/round-budget"
import { Scores } from "../../../../openhack-orchestration/src"
import { Knowledge } from "../../../../openhack/src/knowledge"
import { Presets } from "../../../../openhack/src/presets"
import { McpRecommend } from "../../../../openhack/src/mcp-recommend"
import { Vendors } from "../../../../openhack/src/vendors"

function log(msg: string) { process.stdout.write(msg + EOL) }
function ok(msg: string) { process.stdout.write(`\x1b[32m✓\x1b[0m ${msg}` + EOL) }
function warn(msg: string) { process.stdout.write(`\x1b[33m!\x1b[0m ${msg}` + EOL) }

function readScopeFile(): any {
  const p = ".openhack/scope.json"
  if (!fs.existsSync(p)) return { enabled: false, targets: [], exclusions: [], max_port_range: "1-65535", allowed_tools: [], disallowed_tools: [], require_confirmation_for: [] }
  return JSON.parse(fs.readFileSync(p, "utf8"))
}
function writeScopeFile(c: any) {
  fs.mkdirSync(".openhack", { recursive: true })
  fs.writeFileSync(".openhack/scope.json", JSON.stringify(c, null, 2))
}

export const OpenHackCommand = cmd({
  command: "openhack",
  describe: "OpenHack security assessment commands",
  builder: (yargs) =>
    yargs
      .command("safety", "show safety harness status", () => {}, () => {
        log("OpenHack Safety Harness: ACTIVE")
        log("Blocks: rm -rf, dd, mkfs, fork bombs, curl|sh, wget|sh, shutdown")
        log("Use /danger to bypass for current session")
      })
      .command("status", "one-shot engagement health summary (ROE / models / MCPs / coverage / combos / findings / cost)", (y: any) => y
        .option("target", { type: "string", describe: "optional; else picks the first target with recorded state" })
        .option("json", { type: "boolean", describe: "emit machine-readable JSON instead of formatted text" }), (argv: any) => {
        try {
          // Auto-detect target from .openhack/rounds/ or .openhack/findings/ when unset.
          const roundsDir = ".openhack/rounds"
          const findingsDir = ".openhack/findings"
          let target = argv.target as string | undefined
          if (!target) {
            const pick = (dir: string, ext: string): string | undefined => {
              try { const f = fs.readdirSync(dir).filter((x) => x.endsWith(ext) && !x.startsWith(".")); if (f.length) return f[0]!.slice(0, -ext.length) } catch {}
              return undefined
            }
            target = pick(roundsDir, ".jsonl") ?? pick(findingsDir, ".json")
          }

          // Read every source of truth.
          const readJson = <T>(p: string, d: T): T => { try { return JSON.parse(fs.readFileSync(p, "utf-8")) as T } catch { return d } }
          const roe = readJson<any>(".openhack/roe/active.roe.json", null)
          const models = readJson<any>(".openhack/models.json", null)
          const scope = readJson<any>(".openhack/scope.json", null)
          const config = ConfigStore.load()
          const enabledMcps = Object.entries(config.mcp ?? {}).filter(([_, v]: [string, any]) => v?.enabled).map(([k]) => k)

          const findings = target
            ? readJson<any>(`${findingsDir}/${target.replace(/[^a-zA-Z0-9.-]/g, "_")}.json`, { totalCount: 0, bySeverity: {}, byStatus: {} })
            : { totalCount: 0, bySeverity: {}, byStatus: {} }
          const rounds = target
            ? (() => { try { return fs.readFileSync(`${roundsDir}/${target.replace(/[^a-zA-Z0-9.-]/g, "_")}.jsonl`, "utf-8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) } catch { return [] } })()
            : []
          const lastRound = rounds[rounds.length - 1]
          const covSummary = target ? (() => { try { return Coverage.summary(Coverage.load(target)) } catch { return null } })() : null
          const combos = target ? (() => { try { return Combinations.checklist(target) } catch { return null } })() : null

          const now = Date.now()
          const daysRemaining = roe?.expires_at ? Math.floor((new Date(roe.expires_at).getTime() - now) / 86400_000) : null

          const bundle = {
            engagement_dir: process.cwd(),
            target: target ?? null,
            roe: roe ? { id: roe.id, status: roe.status, targets: roe.targets, tools: roe.authorized_tools, models: roe.authorized_models, expires_at: roe.expires_at, days_remaining: daysRemaining } : null,
            model: models?.custom ?? models?.main ?? "(default)",
            scope: scope ? { enabled: scope.enabled, targets: scope.targets, exclusions: scope.exclusions } : null,
            mcp_enabled: enabledMcps,
            coverage: covSummary,
            combos: combos ? { open: combos.methods.length + combos.payloads.length + combos.chains.length, universe: combos.universeSize, satisfied: combos.satisfiedSize } : null,
            findings: { total: findings.totalCount ?? 0, by_severity: findings.bySeverity ?? {}, by_status: findings.byStatus ?? {} },
            rounds_run: rounds.length,
            last_round: lastRound ? { round: lastRound.round, at: lastRound.at, cost_usd: lastRound.totalCostUsd, rss_mb: lastRound.rssMb, frontier: lastRound.frontierSize } : null,
            total_cost_usd: lastRound?.totalCostUsd ?? 0,
          }

          if (argv.json) { log(JSON.stringify(bundle, null, 2)); return }

          log("")
          if (!target) { warn("No engagement target detected. Try: openhack status --target <name>"); return }
          log(`\x1b[1m▸ Engagement:\x1b[0m ${target}`)
          log(`  dir:   ${bundle.engagement_dir}`)
          log(`  model: ${bundle.model}`)
          log(`  mcps:  ${enabledMcps.length ? enabledMcps.join(", ") : "(none enabled)"}`)
          log("")
          const roeIcon = bundle.roe?.status === "signed" ? "\x1b[32m✓\x1b[0m" : bundle.roe ? "\x1b[33m!\x1b[0m" : "\x1b[31m✗\x1b[0m"
          log(`\x1b[1m▸ ROE:\x1b[0m ${roeIcon} ${bundle.roe ? `${bundle.roe.status} · ${(bundle.roe.targets ?? []).join(", ")} · ${bundle.roe.days_remaining} days remaining` : "not loaded"}`)
          if (bundle.roe?.tools) log(`  tools:  ${(bundle.roe.tools as string[]).slice(0, 8).join(", ")}${(bundle.roe.tools as string[]).length > 8 ? ` (+${(bundle.roe.tools as string[]).length - 8})` : ""}`)
          if (bundle.roe?.models) log(`  models: ${(bundle.roe.models as string[]).join(", ")}`)
          log("")
          if (bundle.coverage) log(`\x1b[1m▸ Coverage:\x1b[0m ${bundle.coverage.tested}/${bundle.coverage.cells} cells (${bundle.coverage.percent}%) · ${bundle.coverage.vulnerable} vulnerable`)
          if (bundle.combos) log(`\x1b[1m▸ Combos:\x1b[0m ${bundle.combos.satisfied}/${bundle.combos.universe} satisfied · ${bundle.combos.open} open`)
          log("")
          const sev = bundle.findings.by_severity
          log(`\x1b[1m▸ Findings:\x1b[0m ${bundle.findings.total} total`)
          log(`  \x1b[31mcritical\x1b[0m ${(sev as any).critical ?? 0}  \x1b[33mhigh\x1b[0m ${(sev as any).high ?? 0}  \x1b[36mmedium\x1b[0m ${(sev as any).medium ?? 0}  low ${(sev as any).low ?? 0}  info ${(sev as any).info ?? 0}`)
          log(`  verified ${bundle.findings.by_status.verified ?? 0} · uncertain ${bundle.findings.by_status.uncertain ?? 0} · false_positive ${bundle.findings.by_status.false_positive ?? 0}`)
          log("")
          log(`\x1b[1m▸ Rounds:\x1b[0m ${bundle.rounds_run} recorded · total cost \x1b[1m$${Number(bundle.total_cost_usd).toFixed(3)}\x1b[0m`)
          if (bundle.last_round) log(`  last: r${bundle.last_round.round} at ${String(bundle.last_round.at).slice(11, 19)} · frontier ${bundle.last_round.frontier} · RSS ${bundle.last_round.rss_mb} MB`)
          try {
            if (target) {
              const m = RoundBudget.metrics(target)
              if (m.rounds > 0) {
                log(`  convergence: +${m.avgFindingsPerRound} findings/round · -${m.avgCombosClosedPerRound} combos/round · dry-streak=${m.lastDryStreak}`)
              }
              // Score-store summary — a top-3 / bottom-3 view of what's producing.
              const scoreStore = Scores.load(target)
              const s = Scores.summary(scoreStore, 3)
              if (s.top.length) {
                log(`  scores: top=${s.top.map((r) => `${r.kind}(${r.prior})`).join(",")}${s.bottom.length ? ` · bottom=${s.bottom.map((r) => `${r.kind}(${r.prior})`).join(",")}` : ""}`)
              }
            }
          } catch {}
          log("")
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("scope", "show engagement scope", () => {}, () => {
        try {
          const c = readScopeFile()
          if (!c.enabled) { warn("Scope enforcement: DISABLED"); return }
          log(`Enabled: ${c.enabled}`)
          log(`Targets: ${c.targets?.join(", ") || "none"}`)
          log(`Exclusions: ${c.exclusions?.join(", ") || "none"}`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("scope-add", "add target to scope", (y: any) => y.option("target", { type: "string", demandOption: true }), (argv: any) => {
        try {
          const c = readScopeFile()
          c.targets.push(argv.target); c.enabled = true
          writeScopeFile(c)
          ok(`Added ${argv.target}. ${c.targets.length} in scope.`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("scope-enable", "enable scope enforcement", () => {}, () => {
        try {
          const c = readScopeFile()
          if (!c.enabled) { c.enabled = true; writeScopeFile(c) }
          ok("Scope ENABLED")
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("findings", "list findings for target", (y: any) => y.option("target", { type: "string", demandOption: true }), (argv: any) => {
        try {
          const dir = ".openhack/findings"
          if (!fs.existsSync(dir)) { log("No findings yet"); return }
          const f = `${dir}/${argv.target.replace(/[^a-zA-Z0-9.-]/g, "_")}.json`
          if (!fs.existsSync(f)) { log(`No findings for ${argv.target}`); return }
          const store = JSON.parse(fs.readFileSync(f, "utf8"))
          log(`${argv.target}: ${store.totalCount || 0} findings`)
          for (const fi of (store.findings || [])) {
            const icon = fi.status === "verified" ? "+" : fi.status === "false_positive" ? "-" : "?"
            log(`  [${icon}] ${(fi.severity || "info").padEnd(8)} ${fi.title}`)
          }
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("finding-verify", "verify a finding (requires PoC + on-disk evidence)", (y: any) => y
        .option("target", { type: "string", demandOption: true })
        .option("id", { type: "string", demandOption: true, describe: "finding id" })
        .option("poc", { type: "string", demandOption: true, describe: "reproducible proof-of-concept" })
        .option("evidence", { type: "string", demandOption: true, describe: "comma-separated evidence file paths" })
        .option("oracle", { type: "string", default: "operator", describe: "who is verifying" }),
        (argv: any) => {
          try {
            const store = Findings.load(argv.target)
            const before = store.findings.find((f: any) => f.id === argv.id)
            if (!before) { warn(`No finding ${argv.id} for ${argv.target}`); return }
            const evidenceFiles = String(argv.evidence).split(",").map((s: string) => s.trim()).filter(Boolean)
            Findings.markVerified(store, argv.id, argv.oracle, { poc: argv.poc, evidenceFiles })
            const after = Findings.load(argv.target).findings.find((f: any) => f.id === argv.id)
            if (after?.status === "verified") ok(`${argv.id} verified by ${argv.oracle} (${evidenceFiles.length} evidence file(s)).`)
            else warn(`${argv.id} NOT verified — kept ${after?.status}. Needs a non-empty PoC and at least one existing evidence file.`)
          } catch (e: any) { log(`Error: ${e.message}`) }
        })
      .command("config", "get/set/list any OpenHack setting (.openhack/openhack.jsonc)", (y: any) => y
        .command("get", "get a dotted key", (yy: any) => yy.option("key", { type: "string", demandOption: true }), (argv: any) => {
          const v = ConfigStore.get(argv.key)
          log(v === undefined ? `(unset) ${argv.key}` : `${argv.key} = ${JSON.stringify(v)}`)
        })
        .command("set", "set a dotted key (value is JSON-coerced: 3, true, [..], else string)", (yy: any) => yy
          .option("key", { type: "string", demandOption: true })
          .option("value", { type: "string", demandOption: true }), (argv: any) => {
          try {
            const v = ConfigStore.set(argv.key, ConfigStore.coerce(String(argv.value)))
            ok(`${argv.key} = ${JSON.stringify(v)}`)
          } catch (e: any) { log(`Error: ${e.message}`) }
        })
        .command("list", "list every configured key", () => {}, () => {
          const items = ConfigStore.flatten()
          if (!items.length) { log("(empty — no .openhack/openhack.jsonc)"); return }
          for (const { key, value } of items) log(`${key} = ${JSON.stringify(value)}`)
        })
        .demandCommand(1, "Use: openhack config get|set|list"), () => {})
      .command("checklist", "show the built-in testing methodology (PortSwigger/HackTricks/WSTG)", (y: any) => y
        .option("class", { type: "string", describe: "show techniques for one class id" }), (argv: any) => {
        try {
          if (argv.class) {
            const c = Checklist.get(argv.class)
            if (!c) { warn(`No class '${argv.class}'. Ids: ${Checklist.ids().join(", ")}`); return }
            log(`${c.id}  —  ${c.name}  [${c.category}]`)
            log(`methods: ${c.methods.join(", ")}   refs: ${c.refs.join(" | ")}`)
            for (const t of c.techniques) log(`  - ${t.id.padEnd(18)} ${t.name}`)
            return
          }
          log(`${Checklist.all().length} classes, ${Checklist.techniqueCount()} techniques:`)
          for (const c of Checklist.all()) log(`  ${c.id.padEnd(20)} ${String(c.techniques.length).padStart(2)} tech  [${c.category}]  ${c.name}`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("coverage", "show test-coverage matrix for a target", (y: any) => y
        .option("target", { type: "string", demandOption: true })
        .option("gaps", { type: "boolean", describe: "list untested endpoint × class cells" }), (argv: any) => {
        try {
          const store = Coverage.load(argv.target)
          const s = Coverage.summary(store)
          log(`${argv.target}: ${s.endpoints} endpoints, ${s.tested}/${s.cells} cells tested (${s.percent}%), ${s.vulnerable} vulnerable`)
          if (argv.gaps) {
            const g = Coverage.gaps(store)
            if (!g.length) { log(g === undefined ? "" : "  (no gaps — or no endpoints registered yet)"); return }
            for (const c of g.slice(0, 200)) log(`  [ ] ${c.method.padEnd(6)} ${c.endpoint}  ::  ${c.className}`)
            if (g.length > 200) log(`  … +${g.length - 200} more`)
          }
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("combos", "combinatorial-coverage checklist (methods × payload-families × chains)", (y: any) => y
        .option("target", { type: "string", demandOption: true })
        .option("gaps", { type: "boolean", describe: "print all three axes (default true if no other flag)" })
        .option("methods", { type: "boolean", describe: "print only method-tuple gaps" })
        .option("payloads", { type: "boolean", describe: "print only payload-family gaps" })
        .option("chains", { type: "boolean", describe: "print only chain-pair gaps" })
        .option("per-finding", { type: "boolean", describe: "print per-finding missing-combo breakdown" })
        .option("report", { type: "boolean", describe: "also write .openhack/checklists/<target>.md" })
        .option("version-info", { type: "boolean", describe: "print vendored knowledge index versions and exit" }), (argv: any) => {
        try {
          if (argv["version-info"]) {
            const v = Knowledge.versions()
            log(`PayloadsAllTheThings: ${v.payloads}`)
            log(`HackTricks:           ${v.hacktricks}`)
            log(`WSTG:                 ${v.wstg}`)
            return
          }
          const report = Combinations.checklist(argv.target)
          const only = Boolean(argv.methods || argv.payloads || argv.chains || argv["per-finding"])
          const show = {
            methods: !only || argv.methods,
            payloads: !only || argv.payloads,
            chains: !only || argv.chains,
            perFinding: !only || argv["per-finding"],
          }
          const total = Combinations.totalGaps(report)
          const openMath = Combinations.openComboCount(report)
          log(`${argv.target}: ${report.methods.length} method gaps, ${report.payloads.length} payload gaps, ${report.chains.length} chain gaps  (total ${total})`)
          log(`  mathematical universe: ${report.universeSize} combos, ${report.satisfiedSize} satisfied, ${openMath} open`)
          if (show.methods) {
            log(`\n▶ Method-tuple gaps`)
            if (!report.methods.length) log(`  (all endpoints exercise every applicable method)`)
            for (const g of report.methods.slice(0, 100)) log(`  [ ] ${g.endpoint.padEnd(40)}  tested [${g.testedMethods.join(",")}]  missing [${g.missingMethods.join(",")}]`)
            if (report.methods.length > 100) log(`  … +${report.methods.length - 100} more`)
          }
          if (show.payloads) {
            log(`\n▶ Payload-family gaps (PayloadsAllTheThings)`)
            if (!report.payloads.length) log(`  (every engaged cell exercises its full family universe)`)
            for (const g of report.payloads.slice(0, 100)) log(`  [ ] ${g.method.padEnd(6)} ${g.endpoint.padEnd(30)} × ${g.className}  missing [${g.missingFamilies.join(",")}]`)
            if (report.payloads.length > 100) log(`  … +${report.payloads.length - 100} more`)
          }
          if (show.chains) {
            log(`\n▶ Chain-pair gaps`)
            if (!report.chains.length) log(`  (every vulnerable finding's chain hints have been exercised)`)
            for (const g of report.chains.slice(0, 100)) log(`  [ ] ${g.classA} @ ${g.methodA} ${g.endpointA} (vulnerable)  →  ${g.classB} @ ${g.methodB} ${g.endpointB} (${g.whyB})`)
            if (report.chains.length > 100) log(`  … +${report.chains.length - 100} more`)
          }
          if (show.perFinding) {
            log(`\n▶ Per-relevant-finding combinations`)
            if (!report.perFinding.length) log(`  (no findings recorded yet)`)
            for (const pf of report.perFinding) {
              log(`  ● [${pf.severity}] ${pf.title}` + (pf.classId ? `  (class=${pf.classId})` : ""))
              if (pf.chainHints.length) log(`    chains-with: ${pf.chainHints.join(", ")}`)
              if (pf.affectedComponent) log(`    affected: ${pf.affectedComponent}`)
              const groups = new Map<string, string[]>()
              for (const c of pf.missingCombos) {
                const k = `${c.method} ${c.endpoint} × ${c.classId}`
                const bucket = groups.get(k) ?? []
                if (c.payloadFamilyId) bucket.push(c.payloadFamilyId)
                groups.set(k, bucket)
              }
              log(`    missing combos: ${pf.missingCombos.length} across ${groups.size} (endpoint,method,class) groups`)
              for (const [k, fams] of Array.from(groups.entries()).slice(0, 30)) {
                log(`      [ ] ${k}${fams.length ? "  families=[" + fams.join(",") + "]" : ""}`)
              }
              if (groups.size > 30) log(`      … +${groups.size - 30} more groups`)
            }
          }
          if (argv.report) {
            const fp = Combinations.writeMarkdown(report)
            ok(`Wrote checklist → ${fp}`)
          }
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("combos-snapshot", "capture a combinatorial-coverage snapshot for later diff", (y: any) => y
        .option("target", { type: "string", demandOption: true })
        .option("label", { type: "string", demandOption: true }), (argv: any) => {
        try {
          const fp = Coverage.snapshot(argv.target, argv.label)
          ok(`Snapshot saved → ${fp}`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("combos-diff", "combos closed / newly opened since a snapshot", (y: any) => y
        .option("target", { type: "string", demandOption: true })
        .option("since", { type: "string", demandOption: true, describe: "snapshot label (see openhack combos-snapshot)" }), (argv: any) => {
        try {
          const d = Combinations.diffSince(argv.target, argv.since)
          if (!d) { warn(`No snapshot '${argv.since}' for ${argv.target}. Take one first with 'openhack combos-snapshot'.`); return }
          log(`${argv.target}: since '${argv.since}' — closed ${d.closed.length}, newly opened ${d.opened.length}, still open ${d.stillOpen}, still satisfied ${d.stillSatisfied}`)
          if (d.closed.length) {
            log(`\n✓ Closed since '${argv.since}' (${d.closed.length})`)
            for (const c of d.closed.slice(0, 200)) log(`  ${c.method.padEnd(6)} ${c.endpoint.padEnd(30)} × ${c.classId}${c.payloadFamilyId ? ` [${c.payloadFamilyId}]` : ""}`)
            if (d.closed.length > 200) log(`  … +${d.closed.length - 200} more`)
          }
          if (d.opened.length) {
            log(`\n! Newly opened since '${argv.since}' (${d.opened.length})`)
            for (const c of d.opened.slice(0, 200)) log(`  ${c.method.padEnd(6)} ${c.endpoint.padEnd(30)} × ${c.classId}${c.payloadFamilyId ? ` [${c.payloadFamilyId}]` : ""}`)
            if (d.opened.length > 200) log(`  … +${d.opened.length - 200} more`)
          }
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("combos-satisfy", "mark a combo satisfied from the shell (closes it in the coverage store)", (y: any) => y
        .option("target", { type: "string", demandOption: true })
        .option("endpoint", { type: "string", demandOption: true })
        .option("method", { type: "string", demandOption: true })
        .option("class", { type: "string", demandOption: true })
        .option("family", { type: "string", describe: "payload family id (omit for class-level satisfy)" })
        .option("result", { type: "string", default: "safe", choices: ["safe", "vulnerable", "inconclusive", "blocked"] as const })
        .option("technique", { type: "string", describe: "technique id from Checklist to record" })
        .option("notes", { type: "string" }), (argv: any) => {
        try {
          const store = Coverage.load(argv.target)
          Coverage.mark(store, {
            endpoint: argv.endpoint,
            method: String(argv.method).toUpperCase(),
            classId: argv.class,
            result: argv.result as any,
            technique: argv.technique,
            notes: argv.notes,
            payloadFamilies: argv.family ? [argv.family] : undefined,
          })
          ok(`Marked ${argv.method.toUpperCase()} ${argv.endpoint} × ${argv.class}${argv.family ? " [" + argv.family + "]" : ""} = ${argv.result}`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("preset", "expand a Kali-tool preset (nmap/ffuf/nuclei/sqlmap/...)", (y: any) => y
        .option("name", { type: "string", describe: "preset id (omit to list)" })
        .option("target", { type: "string", describe: "target/URL appended to the command" }), (argv: any) => {
        try {
          if (!argv.name) {
            log(`${Presets.all().length} presets:`)
            for (const p of Presets.all()) log(`  ${p.id.padEnd(18)} ${p.tool.padEnd(11)} ${p.description}`)
            log("\nUse: openhack preset --name <id> --target <host/URL>")
            return
          }
          const p = Presets.get(argv.name)
          if (!p) { warn(`No preset '${argv.name}'`); return }
          log(Presets.expand(p, argv.target))
          if (!argv.target && p.target_hint) log(`# append target: ${p.target_hint}`)
          if (p.timeout_ms) log(`# suggested timeout: ${Math.round(p.timeout_ms / 1000)}s`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("mcp-recommend", "suggest MCP servers relevant to a task", (y: any) => y
        .option("prompt", { type: "string", demandOption: true, describe: "task description" }), (argv: any) => {
        try {
          const hits = McpRecommend.recommend(String(argv.prompt))
          if (!hits.length) { log("No MCP recommendation for that task."); return }
          log(McpRecommend.format(hits))
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("cmd", "run any OpenHack slash-command macro from the shell (council/triage/audit/cleanup/...)", (y: any) => y
        .option("name", { type: "string", describe: "macro name (omit with --list to see all)" })
        .option("args", { type: "string", default: "", describe: "arguments passed to the macro" })
        .option("list", { type: "boolean", describe: "list available macros" })
        .option("model", { type: "string", describe: "model override" }), async (argv: any) => {
        try {
          const m = await import("./openhack.automode")
          if (argv.list || !argv.name) {
            log("macros: " + m.listMacros().join(", "))
            if (!argv.name) log("run one with: openhack cmd --name <macro> [--args \"...\"]")
            return
          }
          log(`running /${argv.name} ${argv.args}…`)
          const r = await m.runCommandMacro(String(argv.name), String(argv.args || ""), { model: argv.model })
          log(r.output)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("council", "run the council QA review (macro) from the shell", (y: any) => y
        .option("target", { type: "string", default: "", describe: "target/args for the review" })
        .option("model", { type: "string" }), async (argv: any) => {
        try {
          const m = await import("./openhack.automode")
          log("running /council…")
          const r = await m.runCommandMacro("council", String(argv.target || ""), { model: argv.model })
          log(r.output)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("triage", "run the code + coverage triage (macro) from the shell", (y: any) => y
        .option("path", { type: "string", default: "framework", describe: "path/'framework'/'engagement' to triage" })
        .option("model", { type: "string" }), async (argv: any) => {
        try {
          const m = await import("./openhack.automode")
          log("running /triage…")
          const r = await m.runCommandMacro("triage", String(argv.path || "framework"), { model: argv.model })
          log(r.output)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("workflow-list", "list active workflows", () => {}, () => {
        try {
          const dir = ".openhack/workflows"
          if (!fs.existsSync(dir)) { log("No workflows"); return }
          const files = fs.readdirSync(dir).filter((f: string) => f.endsWith(".json"))
          for (const f of files) {
            const wf = JSON.parse(fs.readFileSync(`${dir}/${f}`, "utf8"))
            log(`[${wf.status}] ${wf.id}: ${wf.config?.description || "—"}`)
          }
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("automode", "run the pentest orchestration for real (subagents + iterate-until-goal)", (y: any) => y
        .option("batch", { type: "string", describe: "path to batch.json (task list)" })
        .option("prompts", { type: "string", describe: "path to tasks.txt (task list)" })
        .option("output", { type: "string", describe: "output dir" })
        .option("target", { type: "string", describe: "target name" })
        .option("orchestrate", { type: "boolean", describe: "use the specialized pentest orchestrator objectives for --target" })
        .option("objectives", { type: "string", describe: "comma-separated orchestrator ids (default: all)" })
        .option("execute", { type: "boolean", describe: "actually run (spawns real subagent sessions); without it, plan/dry-run only" })
        .option("loop", { type: "boolean", describe: "iterate-until-goal: re-run rounds until convergence/budget/ROE (implies orchestrate+execute)" })
        .option("max-rounds", { type: "number", default: 3, describe: "hard cap on loop rounds" })
        .option("cost-cap", { type: "number", describe: "batch budget ceiling in USD" })
        .option("instances", { type: "number", describe: "parallel instances per objective (default 3)" })
        .option("parallel", { type: "boolean", default: true, describe: "run same-priority objectives concurrently" })
        .option("coverage-target", { type: "number", describe: "stop when methodology coverage reaches this %" })
        .option("council", { type: "boolean", default: true, describe: "run council QA review after every round (--no-council to disable)" })
        .option("plan", { type: "boolean", default: true, describe: "run a planning step before executing (--no-plan to disable)" })
        .option("model", { type: "string", describe: "model override (provider/model)" })
        .option("timeout", { type: "number", describe: "per-objective timeout in seconds (default 1800)" })
        .option("graph", { type: "boolean", describe: "enable the AI-driven attack-graph controller (round 1 warm-start, rounds 2+ dispatch top-k frontier)" })
        .option("frontier-k", { type: "number", describe: "frontier width per round when graph is active (default 6)" })
        .option("resume", { type: "boolean", describe: "resume an interrupted loop: continue after the last round recorded in .openhack/rounds/<target>.jsonl" }),
        async (argv: any) => {
          try {
            const { runAutomodeCli } = await import("./openhack.automode")
            await runAutomodeCli(argv)
          } catch (e: any) { log(`Error: ${e.message}`) }
        })
      .command("mcp-status", "show MCP container status", () => {}, () => {
        try {
          const out = execSync("docker ps --filter name=openhack --format 'table {{.Names}}\t{{.Status}}\t{{.Networks}}' 2>/dev/null || echo 'Docker not running'", { encoding: "utf8", timeout: 5000 })
          log(out.trim())
        } catch { warn("Docker not running or no containers found") }
      })
      .command("mcp-start", "start all MCP containers", () => {}, () => {
        try {
          const out = execSync("docker start openhack-hexstrike openhack-pentestai openhack-rustsploit openhack-arcticfox openhack-sysreptor 2>&1 || true", { encoding: "utf8", timeout: 30000 })
          log(out.trim() || "All containers started")
          ok("MCP containers started")
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("mcp-stop", "stop all MCP containers", () => {}, () => {
        try {
          const out = execSync("docker stop openhack-hexstrike openhack-pentestai openhack-rustsploit openhack-arcticfox openhack-sysreptor 2>&1 || true", { encoding: "utf8", timeout: 30000 })
          log(out.trim() || "All containers stopped")
          ok("MCP containers stopped")
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("mcp-net", "show MCP network info", () => {}, () => {
        try {
          const out = execSync("docker network inspect openhack-net --format '{{range .IPAM.Config}}{{.Subnet}} → Gateway: {{.Gateway}}{{end}}' 2>/dev/null || echo 'Network not found'", { encoding: "utf8", timeout: 5000 })
          log(out.trim())
          const containers = execSync("docker ps --filter network=openhack-net --format '{{.Names}}: {{.Networks}}' 2>/dev/null || true", { encoding: "utf8", timeout: 5000 })
          log(containers.trim() || "No containers on openhack-net")
        } catch { warn("Docker not running") }
      })
      .command("mcp-setup", "run MCP deployment setup script", () => {}, () => {
        try {
          log("Running OpenHack MCP setup...")
          const out = execSync("bash openhack-setup.sh", { encoding: "utf8", stdio: "inherit", timeout: 600000 })
        } catch (e: any) {
          warn(`Setup failed: ${e.message}`)
          warn("Run manually: bash openhack-setup.sh")
        }
      })
      .command("roe", "show current ROE status", () => {}, () => {
        try {
          const roeDir = ".openhack/roe/active.roe.json"
          if (!fs.existsSync(roeDir)) { warn("No ROE loaded. Create one: openhack roe-create"); return }
          const roe = JSON.parse(fs.readFileSync(roeDir, "utf8"))
          const icon = roe.status === "signed" ? "+" : roe.status === "expired" ? "!" : "?"
          log(`[${icon}] ROE ${roe.id}: ${roe.status.toUpperCase()}`)
          log(`  Company: ${roe.company} | Client: ${roe.client}`)
          log(`  Targets: ${roe.targets.join(", ")}`)
          log(`  Dates: ${roe.date_start} → ${roe.date_end}`)
          log(`  Tools: ${roe.authorized_tools.join(", ")}`)
          if (roe.signature) log(`  Signed: ${roe.signer_key} (${roe.signed_at})`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("roe-create", "create new ROE from template", (y: any) => y
        .option("company", { type: "string", describe: "assessment company name" })
        .option("client", { type: "string", describe: "client name" })
        .option("targets", { type: "string", describe: "comma-separated targets" })
        .option("tools", { type: "string", describe: "comma-separated tools (* = all)" }),
        (argv: any) => {
          try {
            const roeDir = ".openhack/roe"
            if (!fs.existsSync(roeDir)) fs.mkdirSync(roeDir, { recursive: true })
            const id = `ROE-${new Date().toISOString().slice(0,10)}-${crypto.randomBytes(3).toString("hex")}`
            const roe: any = {
              id, company: argv.company || "COMPANY", client: argv.client || argv.company || "CLIENT",
              targets: argv.targets ? argv.targets.split(",").map((t: string) => t.trim()) : ["example.com"],
              exclusions: [], authorized_tools: argv.tools ? argv.tools.split(",").map((t: string) => t.trim()) : ["*"],
              restricted_tools: [], date_start: new Date().toISOString().slice(0,10),
              date_end: new Date(Date.now() + 14*86400000).toISOString().slice(0,10),
              authorized_personnel: [process.env.USER || "operator"],
              notes: "", expires_at: new Date(Date.now() + 14*86400000).toISOString(), status: "draft",
            }
            fs.writeFileSync(`${roeDir}/active.roe.json`, JSON.stringify(roe, null, 2))
            ok(`ROE ${id} created — ${roe.targets.length} targets, status: draft`)
            log("Sign with: openhack roe-sign")
          } catch (e: any) { log(`Error: ${e.message}`) }
        })
      .command("roe-sign", "sign the current ROE", () => {}, () => {
        try {
          const roe = ROE.load()
          if (!roe) { warn("No ROE found. Create one: openhack roe-create"); return }
          if (roe.status === "signed") { warn("Already signed"); return }
          // ROE.sign covers every authorization-relevant field and is the same
          // signature the runtime plugin verifies before allowing tool calls.
          const signed = ROE.sign(roe)
          ok(`ROE ${signed.id} signed by ${signed.signer_key}`)
          log("Runtime enforcement will now allow in-scope, authorized operations")
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("roe-revoke", "revoke current ROE", () => {}, () => {
        try {
          const roe = ROE.load()
          if (!roe) { warn("No ROE loaded"); return }
          // Revoke (not delete) so the runtime plugin actively blocks further
          // testing until a new ROE is created and signed.
          ROE.revoke(roe)
          ok(`ROE ${roe.id} revoked`)
          warn("All target operations are now blocked until a new ROE is created and signed")
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("orch", "show orchestrator routing table", () => {}, () => {
        try {
          const { rules, scores } = Orchestrator.getRoutingTable()
          log(`Orchestrator: ${rules.length} categories, ${scores.length} scored tools`)
          for (const r of rules.slice(0, 5)) {
            log(`  ${r.category.padEnd(16)} → ${r.primary} (fallback: ${r.fallback || "none"})`)
          }
          if (rules.length > 5) log(`  ... and ${rules.length - 5} more categories`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("advise", "toggle command advisor", () => {}, () => {
        try {
          const enabled = Advisor.toggle()
          log(`Command advisor: ${enabled ? "ON" : "OFF"}`)
          log(`Verbosity: ${Advisor.getVerbosity()}/3`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("advise-level", "set advisor verbosity (1-3)", (y: any) => y.option("level", { type: "number", demandOption: true }), (argv: any) => {
        try {
          Advisor.setVerbosity(argv.level || 2)
          log(`Advisor verbosity: ${Advisor.getVerbosity()}/3`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("advise-test", "test advisor on a command", (y: any) => y.option("cmd", { type: "string", demandOption: true }), (argv: any) => {
        try {
          const advice = Advisor.analyze(argv.cmd)
          if (advice.length === 0) { ok("No advice — command looks good"); return }
          for (const a of advice) {
            const icons: Record<string, string> = { tip: "\x1b[36m💡\x1b[0m", warn: "\x1b[33m⚠\x1b[0m", error: "\x1b[31m✗\x1b[0m", alt: "\x1b[35m🔄\x1b[0m" }
            log(`  ${icons[a.level] || "—"} ${a.message}`)
          }
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("moe", "show MoE expert routing", () => {}, () => {
        try {
          const stats = MOERouter.getStats()
          log(`MoE Router: ${stats.experts.length} experts, ${stats.total} routings`)
          for (const e of stats.experts.filter(x => x.useCount > 0)) {
            log(`  ${e.name.padEnd(18)} → ${e.agent.padEnd(12)} | ${e.model.split("/")[1].padEnd(18)} | ${e.useCount} calls`)
          }
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("moe-route", "test MoE routing on a prompt", (y: any) => y.option("prompt", { type: "string", demandOption: true }), (argv: any) => {
        try {
          const { expert, confidence } = MOERouter.route(argv.prompt)
          const cost = MOERouter.getCostEstimate(argv.prompt)
          const model = MOERouter.getModelForTask(argv.prompt)
          log(`Prompt: ${argv.prompt.slice(0, 80)}`)
          log(`Expert: ${expert.name} (${expert.description})`)
          log(`Model: ${model.split("/")[1]} | Agent: ${expert.targetAgent}`)
          log(`Confidence: ${(confidence*100).toFixed(0)}% | Est. cost: ${cost.estimatedCost}`)
        } catch (e: any) { log(`Error: ${e.message}`) }
      })
      .command("model", "show or set global model", (y: any) => y
        .option("set", { type: "string", describe: "set all models to use this (e.g. deepseek/deepseek-v4)" })
        .option("reset", { type: "boolean", describe: "reset to defaults" }),
        (argv: any) => {
          try {
            if (argv.reset) { GlobalConfig.reset(); ok("Models reset to defaults"); }
            else if (argv.set) { GlobalConfig.useCustomModel(argv.set); ok(`All models set to: ${argv.set}`); }
            log(GlobalConfig.getStatus())
          } catch (e: any) { log(`Error: ${e.message}`) }
        })
      .command("vendors", "status of every vendored framework component (vendor/)", (y: any) => y
        .option("json", { type: "boolean", describe: "emit machine-readable JSON" })
        .option("bootstrap", { type: "string", describe: "bootstrap one component by name (e.g. lattice) before reporting" }),
        async (argv: any) => {
          try {
            if (argv.bootstrap) {
              log(`bootstrapping ${argv.bootstrap} (bounded; output streams to the end)…`)
              const result = await Vendors.bootstrap(String(argv.bootstrap))
              if (result.ok) ok(`bootstrap ${result.name}: ok`)
              else warn(`bootstrap ${result.name} failed: ${result.error}`)
              if (result.output.trim()) log(result.output.trim().split("\n").slice(-12).join("\n"))
            }
            const statuses = Vendors.status(argv.bootstrap ? String(argv.bootstrap) : undefined)
            if (argv.json) { log(JSON.stringify(statuses, null, 2)); return }
            log("")
            log("\x1b[1m▸ Vendored framework components:\x1b[0m")
            log(Vendors.format(statuses))
            const missing = statuses.filter((s) => !s.bin)
            if (missing.length)
              log(`\n  ${missing.length} missing — bootstrap with: bash vendor/<dir>/bootstrap.sh  ·  or: openhack vendors --bootstrap <name>`)
          } catch (e: any) { log(`Error: ${e.message}`) }
        })
      .demandCommand(),
  async handler() {},
})
