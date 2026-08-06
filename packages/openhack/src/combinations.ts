import * as fs from "node:fs"
import * as path from "node:path"
import { Coverage } from "./coverage"
import { Checklist } from "./checklist"
import { Knowledge } from "./knowledge"
import { Findings } from "./findings"
import { ROE } from "./roe"

/**
 * Combinatorial-coverage checklist.
 *
 * Three axes, each solved as a set-difference over an obligation graph
 * (see the plan file's "Graph algorithm" section for the shape). All functions
 * are pure over `Coverage.Store` + `Knowledge` + `Checklist` — no mutation,
 * no disk writes (except `writeMarkdown()`, which is explicit).
 *
 *   • MethodGap  — endpoint tested against too few HTTP methods.
 *   • PayloadGap — an engaged (endpoint,method,classId) cell missing payload families.
 *   • ChainGap   — a vulnerable A-cell whose B-cell (per Checklist.chainHints) is not
 *                  yet vulnerable-tested. Emitted as a candidate combination.
 *
 * Runtime: O(endpoints × classes + vulnerableCells × avgChainHints × classCells).
 * On the largest fixture (200 endpoints × 6 classes = 1200 cells) this is < 1 ms.
 */
export namespace Combinations {
  export const METHOD_UNIVERSE = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

  export interface MethodGap {
    endpoint: string
    testedMethods: string[]
    missingMethods: string[]
  }

  export interface PayloadGap {
    endpoint: string
    method: string
    classId: string
    className: string
    testedFamilies: string[]
    missingFamilies: string[]
  }

  export interface ChainGap {
    endpointA: string
    methodA: string
    classA: string
    endpointB: string
    methodB: string
    classB: string
    whyA: "vulnerable"
    whyB: "untested" | "safe" | "inconclusive"
  }

  /**
   * A single point in the (endpoint × method × class × payloadFamily) universe.
   * `payloadFamilyId === ""` denotes "class-level coverage without a family axis"
   * (used for classes with no vendored family taxonomy — sec-headers, etc.).
   */
  export interface Combo {
    endpoint: string
    method: string
    classId: string
    payloadFamilyId: string
  }

  /** Per-finding view: the finding + every combo that still needs testing "around" it. */
  export interface PerFindingCombos {
    findingId: string
    title: string
    /** Full finding description, so the checklist stands alone as a report artefact. */
    description: string
    severity: string
    status: string
    classId?: string
    affectedComponent?: string
    /** Endpoint inferred from affected_component — populated iff the parse landed. */
    inferredEndpoint?: string
    /** Promotion / audit chain from Findings, so a chained finding's lineage is visible. */
    promotionChain: Array<{ councilId: string; action: string; rationale: string; timestamp: string }>
    evidenceFiles: string[]
    /** Every not-yet-satisfied combo on the same endpoint / same class / chain-related class. */
    missingCombos: Combo[]
    /** Class ids from `Checklist.chainHints[classOf(finding)]` — the "combine with what?" hints. */
    chainHints: string[]
  }

  export interface CombinationReport {
    target: string
    generatedAt: string
    methods: MethodGap[]
    payloads: PayloadGap[]
    chains: ChainGap[]
    /** Cartesian universe size — the mathematical ceiling of what could ever be tested. */
    universeSize: number
    /** How many of the universe combos are already satisfied. */
    satisfiedSize: number
    /** Findings-anchored view: every finding × its missing combos. */
    perFinding: PerFindingCombos[]
  }

  // ── Axis M: method-tuple per endpoint ────────────────────────────────────

  /**
   * ROE-aware method universe for a target. When a signed ROE restricts the
   * method-verb (typed as a "tool" in ROE's authorized/restricted list), the
   * checklist never emits it as a gap. Callers that pass `null` bypass the
   * filter (used from bench and unit tests where ROE isn't set up).
   */
  export function allowedMethodsFor(target: string | null): string[] {
    if (!target) return METHOD_UNIVERSE
    let roe: ROE.ROEDocument | null = null
    try { roe = ROE.load() } catch {}
    if (!roe) return METHOD_UNIVERSE
    return METHOD_UNIVERSE.filter((m) => {
      try { return !ROE.enforce(roe, target, m).blocked } catch { return true }
    })
  }

  /**
   * For each distinct endpoint (path, ignoring method), the tested method set
   * versus the applicable method universe. Endpoint discovery happens through
   * `Coverage.Store.endpoints[]` — an endpoint only enters this axis after at
   * least one of its methods was registered. When `roeTarget` is set, methods
   * the ROE forbids are excluded from `missingMethods` so the checklist
   * doesn't ask for testing that would be blocked at the tool call.
   */
  export function methodGaps(store: Coverage.Store, roeTarget: string | null = store.target): MethodGap[] {
    const universe = allowedMethodsFor(roeTarget)
    // Collect tested-methods per endpoint path.
    const byPath = new Map<string, Set<string>>()
    for (const ep of store.endpoints) {
      const bucket = byPath.get(ep.endpoint) ?? new Set<string>()
      bucket.add(ep.method.toUpperCase())
      byPath.set(ep.endpoint, bucket)
    }
    const gaps: MethodGap[] = []
    for (const [endpoint, tested] of byPath) {
      const missing = universe.filter((m) => !tested.has(m))
      if (missing.length === 0) continue
      gaps.push({ endpoint, testedMethods: [...tested].sort(), missingMethods: missing })
    }
    return gaps
  }

  // ── Axis P: payload-family per engaged cell ──────────────────────────────

  /**
   * For each cell whose result is NOT "untested" (untested cells are still
   * handled by the existing `Coverage.gaps` single-cell path — no double
   * emission), diff the known payload family universe against
   * `Cell.payloadFamiliesTested`. Cells whose class has no vendored families
   * are skipped (nothing to check).
   */
  export function payloadFamilyGaps(store: Coverage.Store): PayloadGap[] {
    const gaps: PayloadGap[] = []
    for (const ep of store.endpoints) {
      for (const cell of Object.values(ep.cells)) {
        if (cell.result === "untested") continue
        const families = Knowledge.payloadFamilies(cell.classId)
        if (families.length === 0) continue
        const tested = new Set(cell.payloadFamiliesTested ?? [])
        const missing = families.filter((f) => !tested.has(f.id)).map((f) => f.id)
        if (missing.length === 0) continue
        const cls = Checklist.get(cell.classId)
        gaps.push({
          endpoint: ep.endpoint,
          method: ep.method,
          classId: cell.classId,
          className: cls?.name ?? cell.classId,
          testedFamilies: [...tested].sort(),
          missingFamilies: missing,
        })
      }
    }
    return gaps
  }

  // ── Axis C: chain-pair per vulnerable A-cell ─────────────────────────────

  /**
   * Enumerate `(vulnerable A-cell) × (Checklist.chainHints[A]) × (candidate B-cell)`.
   * A candidate B-cell is any coverage cell for classId=B whose result is NOT
   * yet "vulnerable" — those are gaps worth investigating. Never emits self-pairs
   * (A === B on the same endpoint+method).
   *
   * If B has no matching coverage cell at all, we still emit one gap per
   * discovered endpoint × method-that-supports-B, so the operator sees "you
   * proved A on /x — you never tried the chained B anywhere on the surface".
   */
  export function chainGaps(store: Coverage.Store): ChainGap[] {
    const gaps: ChainGap[] = []
    // Index cells by classId → array of {endpoint, method, cell} for fast lookup.
    const byClass = new Map<string, Array<{ endpoint: string; method: string; result: Coverage.Result }>>()
    for (const ep of store.endpoints) {
      for (const cell of Object.values(ep.cells)) {
        const bucket = byClass.get(cell.classId) ?? []
        bucket.push({ endpoint: ep.endpoint, method: ep.method, result: cell.result })
        byClass.set(cell.classId, bucket)
      }
    }

    const seenPair = new Set<string>()
    const emit = (g: ChainGap) => {
      const key = `${g.endpointA}|${g.methodA}|${g.classA}||${g.endpointB}|${g.methodB}|${g.classB}`
      if (seenPair.has(key)) return
      seenPair.add(key)
      gaps.push(g)
    }

    for (const ep of store.endpoints) {
      for (const cellA of Object.values(ep.cells)) {
        if (cellA.result !== "vulnerable") continue
        const cls = Checklist.get(cellA.classId)
        if (!cls?.chainHints?.length) continue
        for (const classB of cls.chainHints) {
          const cellsB = byClass.get(classB) ?? []
          // Case 1: B has coverage cells — emit each non-vulnerable one.
          if (cellsB.length) {
            for (const b of cellsB) {
              if (b.endpoint === ep.endpoint && b.method === ep.method && classB === cellA.classId) continue
              if (b.result === "vulnerable") continue
              emit({
                endpointA: ep.endpoint, methodA: ep.method, classA: cellA.classId,
                endpointB: b.endpoint, methodB: b.method, classB,
                whyA: "vulnerable",
                whyB: b.result === "untested" ? "untested" : b.result === "safe" ? "safe" : "inconclusive",
              })
            }
          } else {
            // Case 2: B has NO coverage anywhere — emit a virtual gap so the
            // operator sees "try B somewhere on the surface". Anchored to A's
            // endpoint so the report groups sensibly.
            emit({
              endpointA: ep.endpoint, methodA: ep.method, classA: cellA.classId,
              endpointB: ep.endpoint, methodB: ep.method, classB,
              whyA: "vulnerable", whyB: "untested",
            })
          }
        }
      }
    }
    return gaps
  }

  // ── Axis MATH: complete Cartesian enumerator + set-difference ────────────

  /** The full set of discovered endpoint PATHS (a path may appear under >1 method). */
  function discoveredEndpoints(store: Coverage.Store): string[] {
    return Array.from(new Set(store.endpoints.map((e) => e.endpoint))).sort()
  }

  /**
   * Complete Cartesian universe of `Combo` for the discovered endpoints:
   *   endpoints × METHOD_UNIVERSE × applicable-class-for-method × payload-families(class)
   *
   * A class with NO vendored families still contributes one combo per (endpoint,
   * method, class) with `payloadFamilyId = ""` — that way the mathematical iteration
   * covers those classes too (e.g. sec-headers, clickjacking) instead of silently
   * dropping them.
   *
   * This is the ground-truth "every possible combo" the checklist has to walk.
   * Runtime: O(endpoints × 7 methods × applicableClasses × avgFamilies).
   */
  export function enumerateAllCombos(store: Coverage.Store, roeTarget: string | null = store.target): Combo[] {
    const universe = allowedMethodsFor(roeTarget)
    const out: Combo[] = []
    for (const endpoint of discoveredEndpoints(store)) {
      for (const method of universe) {
        for (const cls of Checklist.forMethod(method)) {
          const fams = Knowledge.payloadFamilies(cls.id)
          if (fams.length === 0) {
            out.push({ endpoint, method, classId: cls.id, payloadFamilyId: "" })
          } else {
            for (const f of fams) out.push({ endpoint, method, classId: cls.id, payloadFamilyId: f.id })
          }
        }
      }
    }
    return out
  }

  /** The subset of `enumerateAllCombos(store)` that has been actually exercised. */
  export function combosSatisfied(store: Coverage.Store): Combo[] {
    const out: Combo[] = []
    for (const ep of store.endpoints) {
      for (const cell of Object.values(ep.cells)) {
        if (cell.result === "untested") continue // still open
        const fams = Knowledge.payloadFamilies(cell.classId)
        if (fams.length === 0) {
          out.push({ endpoint: ep.endpoint, method: ep.method, classId: cell.classId, payloadFamilyId: "" })
        } else {
          for (const fid of cell.payloadFamiliesTested ?? []) {
            out.push({ endpoint: ep.endpoint, method: ep.method, classId: cell.classId, payloadFamilyId: fid })
          }
        }
      }
    }
    return out
  }

  /**
   * The set-difference `allCombos \ satisfied` — the mathematically-complete
   * list of every open combo. This is the ground-truth checking algorithm:
   * exhaustive, no heuristic sampling, no priority weighting. `methodGaps`,
   * `payloadFamilyGaps`, and `chainGaps` above are three domain-friendly
   * projections of *this* set for reporting; the loop's frontier does not
   * need to look at all of it at once (that would flood the LLM).
   */
  export function combosMissing(store: Coverage.Store, roeTarget: string | null = store.target): Combo[] {
    const universe = enumerateAllCombos(store, roeTarget)
    const satKey = new Set(combosSatisfied(store).map(comboKey))
    return universe.filter((c) => !satKey.has(comboKey(c)))
  }

  function comboKey(c: Combo): string {
    return `${c.endpoint}||${c.method}||${c.classId}||${c.payloadFamilyId}`
  }

  // ── Per-finding view — walks findings and computes their local frontier ──

  /**
   * For each real Finding in the engagement, enumerate every combo still open
   * "around" it — three concentric layers:
   *   L1  same (endpoint, class) — every method/family missing there
   *   L2  same endpoint, chain-hint classes — every method/family missing
   *   L3  same class, different endpoints — every method/family missing
   *
   * This is the user-facing "checking algorithm per relevant findings": the
   * output tells the operator exactly which combos to test to close the
   * finding's neighbourhood mathematically.
   */
  export function perFindingCombos(target: string, store?: Coverage.Store): PerFindingCombos[] {
    const cov = store ?? Coverage.load(target)
    let findings: Findings.Finding[]
    try { findings = Findings.load(target).findings ?? [] } catch { findings = [] }
    const universeKeys = new Set(combosMissing(cov).map(comboKey))
    const universeCombos = combosMissing(cov)

    const out: PerFindingCombos[] = []
    for (const f of findings) {
      const classId = inferClassIdFromFinding(f)
      const endpoint = inferEndpointFromFinding(f)
      const chainHints = classId ? Checklist.get(classId)?.chainHints ?? [] : []
      const missing: Combo[] = []
      for (const c of universeCombos) {
        // L1 — same endpoint + same class
        const sameEndpoint = endpoint && c.endpoint === endpoint
        const sameClass = classId && c.classId === classId
        // L2 — same endpoint + chain-hint class
        const chainClass = classId && chainHints.includes(c.classId)
        // L3 — same class, different endpoint
        const l3 = sameClass && (!endpoint || c.endpoint !== endpoint)
        if ((sameEndpoint && (sameClass || chainClass)) || l3) missing.push(c)
      }
      out.push({
        findingId: f.id,
        title: f.title,
        description: f.description ?? "",
        severity: f.severity,
        status: f.status,
        classId,
        affectedComponent: f.affected_component,
        inferredEndpoint: endpoint,
        promotionChain: (f.promotionChain ?? []).map((r) => ({ councilId: r.councilId, action: r.action, rationale: r.rationale, timestamp: r.timestamp })),
        evidenceFiles: [...(f.evidence_files ?? [])],
        missingCombos: missing,
        chainHints,
      })
    }
    // Sort by severity so critical findings surface first.
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    return out.sort((a, b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5))
  }

  /**
   * Cheap heuristic: derive a Checklist class-id from a Finding by scanning
   * title/description/tags for known ids and matching keywords. Never guesses
   * — returns undefined when nothing matches so the per-finding view stays
   * accurate rather than misleading.
   */
  export function inferClassIdFromFinding(f: Findings.Finding): string | undefined {
    const ids = Checklist.ids()
    const hay = `${f.title} ${f.description} ${(f.tags ?? []).join(" ")}`.toLowerCase()
    for (const id of ids) {
      if (hay.includes(id)) return id
    }
    // Keyword shortcuts for common wordings.
    const kw: Array<[RegExp, string]> = [
      [/\bsql( injection)?\b/, "sqli"], [/\bnosql\b/, "nosqli"],
      [/\bxss\b|cross[- ]site scripting/, "xss"],
      [/\bcsrf\b|cross[- ]site request forgery/, "csrf"],
      [/\bssrf\b|server[- ]side request forgery/, "ssrf"],
      [/\bxxe\b|external entity/, "xxe"],
      [/\bcommand injection|\brce\b|remote code execution/, "cmdi"],
      [/\bpath traversal|\blfi\b|\brfi\b/, "traversal-lfi"],
      [/\bidor\b|\bbola\b/, "access-control"],
      [/\bauth(entication)? bypass|weak (auth|creds|credentials)/, "auth"],
      [/\bopen redirect/, "open-redirect"],
      [/\bclickjack/, "clickjacking"],
      [/\bcors\b/, "cors"],
      [/\bssti\b|template injection/, "ssti"],
      [/\bcache poisoning|cache deception/, "cache"],
      [/\brace condition|toctou/, "race"],
      [/\bdeserialization|serialize|pickle|ysoserial/, "deserialization"],
      [/\bfile upload|webshell/, "upload"],
    ]
    for (const [re, id] of kw) if (re.test(hay)) return id
    return undefined
  }

  function inferEndpointFromFinding(f: Findings.Finding): string | undefined {
    const c = f.affected_component
    if (!c) return undefined
    // Common shapes: "https://host/path" or "GET /path" or "/path".
    const urlMatch = /^https?:\/\/[^/]+(\/[^\s?#]*)/i.exec(c)
    if (urlMatch) return urlMatch[1]
    const methodPathMatch = /^(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/\S*)/i.exec(c)
    if (methodPathMatch) return methodPathMatch[1]
    if (c.startsWith("/")) return c.split(/[?#\s]/)[0]
    return undefined
  }

  // ── Assembly ─────────────────────────────────────────────────────────────

  export function checklist(target: string): CombinationReport {
    const store = Coverage.load(target)
    const universe = enumerateAllCombos(store)
    const satisfied = combosSatisfied(store)
    return {
      target,
      generatedAt: new Date().toISOString(),
      methods: methodGaps(store),
      payloads: payloadFamilyGaps(store),
      chains: chainGaps(store),
      universeSize: universe.length,
      satisfiedSize: satisfied.length,
      perFinding: perFindingCombos(target, store),
    }
  }

  /** Total gap count — cheap terminator input for the loop driver. */
  export function totalGaps(report: CombinationReport): number {
    return report.methods.length + report.payloads.length + report.chains.length
  }

  /**
   * Diff view: combos that were open at snapshot `sinceLabel` and are now
   * satisfied (i.e., closed since then), and combos that are newly open.
   * Requires a snapshot at `sinceLabel` — call `Coverage.snapshot(target, label)`
   * to create one.
   */
  export interface ComboDiff {
    target: string
    sinceLabel: string
    generatedAt: string
    closed: Combo[]     // open at snapshot, satisfied now
    opened: Combo[]     // not-in-snapshot-universe or satisfied then, open now
    stillOpen: number
    stillSatisfied: number
  }

  export function diffSince(target: string, sinceLabel: string): ComboDiff | null {
    const snap = Coverage.loadSnapshot(target, sinceLabel)
    if (!snap) return null
    const now = Coverage.load(target)
    const snapMissing = new Set(combosMissing(snap, null).map(comboKey))
    const snapSatisfied = new Set(combosSatisfied(snap).map(comboKey))
    const nowMissing = new Set(combosMissing(now, null).map(comboKey))
    const nowSatisfied = new Set(combosSatisfied(now).map(comboKey))
    // Reconstruct combos from keys via the current universe.
    const nowUniverse = new Map(enumerateAllCombos(now, null).map((c) => [comboKey(c), c]))
    const closed: Combo[] = []
    const opened: Combo[] = []
    for (const k of snapMissing) {
      if (nowSatisfied.has(k)) closed.push(nowUniverse.get(k) ?? decodeComboKey(k))
    }
    for (const k of nowMissing) {
      if (!snapMissing.has(k)) opened.push(nowUniverse.get(k) ?? decodeComboKey(k))
    }
    let stillOpen = 0, stillSat = 0
    for (const k of nowMissing) if (snapMissing.has(k)) stillOpen++
    for (const k of nowSatisfied) if (snapSatisfied.has(k)) stillSat++
    return {
      target, sinceLabel,
      generatedAt: new Date().toISOString(),
      closed, opened, stillOpen, stillSatisfied: stillSat,
    }
  }

  function decodeComboKey(k: string): Combo {
    const [endpoint = "", method = "", classId = "", payloadFamilyId = ""] = k.split("||")
    return { endpoint, method, classId, payloadFamilyId }
  }

  /** Mathematically-open combo count — universe minus satisfied. Distinct from
   *  `totalGaps`, which is a report-friendly projection. Loop terminator can use
   *  either; this one is exhaustive. */
  export function openComboCount(report: CombinationReport): number {
    return Math.max(0, report.universeSize - report.satisfiedSize)
  }

  /**
   * Split a finding's `missingCombos` into its three concentric shells. Exposed
   * so the renderer can print each shell separately with counts.
   *
   *   L1  same endpoint + same class (right around the finding)
   *   L2  same endpoint + chain-hint class (chained impact on the same surface)
   *   L3  same class + other endpoints (same weakness elsewhere)
   */
  export function shellsFor(pf: PerFindingCombos): { L1: Combo[]; L2: Combo[]; L3: Combo[] } {
    const L1: Combo[] = []
    const L2: Combo[] = []
    const L3: Combo[] = []
    const ep = pf.inferredEndpoint
    for (const c of pf.missingCombos) {
      const sameEp = ep ? c.endpoint === ep : false
      const sameCls = pf.classId ? c.classId === pf.classId : false
      const chainCls = pf.classId ? pf.chainHints.includes(c.classId) : false
      if (sameEp && sameCls) L1.push(c)
      else if (sameEp && chainCls) L2.push(c)
      else if (sameCls && !sameEp) L3.push(c)
    }
    return { L1, L2, L3 }
  }

  /** Group any Combo[] by (endpoint, method, classId) → list of payload family ids. */
  export function groupCombos(combos: Combo[]): Array<{ endpoint: string; method: string; classId: string; families: string[] }> {
    const grouped = new Map<string, { endpoint: string; method: string; classId: string; families: string[] }>()
    for (const c of combos) {
      const k = `${c.endpoint}||${c.method}||${c.classId}`
      const bucket = grouped.get(k) ?? { endpoint: c.endpoint, method: c.method, classId: c.classId, families: [] }
      if (c.payloadFamilyId) bucket.families.push(c.payloadFamilyId)
      grouped.set(k, bucket)
    }
    return Array.from(grouped.values()).sort((a, b) => {
      if (a.endpoint !== b.endpoint) return a.endpoint.localeCompare(b.endpoint)
      if (a.method !== b.method) return a.method.localeCompare(b.method)
      return a.classId.localeCompare(b.classId)
    })
  }

  /** Rich cross-reference bundle for a class, ready to inline in the markdown. */
  export interface ClassRef {
    classId: string
    className: string
    category?: string
    chainHints: string[]
    wstgId?: string
    hacktricks?: { title: string; url: string }
    payloadFamilies: Knowledge.PayloadFamily[]
    techniques: Array<{ id: string; name: string }>
  }

  /** Build the full ClassRef for a class id (Checklist + Knowledge merged). */
  export function classRef(classId: string): ClassRef | undefined {
    const cls = Checklist.get(classId)
    if (!cls) return undefined
    return {
      classId,
      className: cls.name,
      category: cls.category,
      chainHints: cls.chainHints ?? [],
      wstgId: cls.wstgId ?? Knowledge.wstgId(classId),
      hacktricks: Knowledge.hacktricks(classId),
      payloadFamilies: Knowledge.payloadFamilies(classId),
      techniques: cls.techniques.map((t) => ({ id: t.id, name: t.name })),
    }
  }

  // ── Markdown checklist artefact ──────────────────────────────────────────

  const CHECKLIST_DIR = path.join(".openhack", "checklists")

  /**
   * Write an operator-facing markdown checklist under `.openhack/checklists/<target>.md`.
   * Regenerated on every call; safe to attach directly to a pentest report.
   */
  export function writeMarkdown(report: CombinationReport): string {
    fs.mkdirSync(CHECKLIST_DIR, { recursive: true })
    const safe = report.target.replace(/[^a-zA-Z0-9.-]/g, "_")
    const fp = path.join(CHECKLIST_DIR, `${safe}.md`)
    fs.writeFileSync(fp, renderMarkdown(report), { encoding: "utf-8", mode: 0o600 })
    return fp
  }

  /**
   * Full, exhaustive markdown checklist — every combination in detail, every
   * cross-reference expanded, nothing truncated. Deliberately verbose: this is
   * the deliverable operators attach to a pentest report, not a terminal
   * display. The CLI stays terminal-friendly with its own caps; this
   * artefact never truncates.
   */
  export function renderMarkdown(report: CombinationReport): string {
    const lines: string[] = []
    const open = openComboCount(report)
    const pctOpen = report.universeSize > 0 ? Math.round((open / report.universeSize) * 100) : 0

    // ── Header + overview
    lines.push(`# Combinatorial coverage checklist — ${report.target}`)
    lines.push("")
    lines.push(`_Generated ${report.generatedAt}._`)
    lines.push("")
    lines.push(`## Overview`)
    lines.push("")
    lines.push(`| Metric | Value |`)
    lines.push(`|---|---|`)
    lines.push(`| Method-tuple gaps | ${report.methods.length} |`)
    lines.push(`| Payload-family gaps | ${report.payloads.length} |`)
    lines.push(`| Chain-pair gaps | ${report.chains.length} |`)
    lines.push(`| Findings inspected | ${report.perFinding.length} |`)
    lines.push(`| Mathematical universe | ${report.universeSize} combos |`)
    lines.push(`| Combos satisfied | ${report.satisfiedSize} |`)
    lines.push(`| Combos open | ${open} (${pctOpen}%) |`)
    lines.push("")
    lines.push(`> The **mathematical universe** is the full Cartesian product of ` +
               `\`discovered-endpoints × METHOD_UNIVERSE × applicable-classes × payload-families(class)\`. ` +
               `A combo is _satisfied_ when the corresponding \`(endpoint, method, class, family)\` tuple ` +
               `has been recorded in the coverage store; otherwise it is _open_. This checklist enumerates ` +
               `every open combo in detail — see §5 for the raw universe walk.`)
    lines.push("")

    // ── Table of contents (helpful once the artefact grows past a screen)
    lines.push(`## Table of contents`)
    lines.push("")
    lines.push(`1. [Method-tuple coverage](#1-method-tuple-coverage)`)
    lines.push(`2. [Payload-family coverage (PayloadsAllTheThings)](#2-payload-family-coverage-payloadsallthethings)`)
    lines.push(`3. [Chain-pair coverage](#3-chain-pair-coverage)`)
    lines.push(`4. [Per-relevant-finding combinations](#4-per-relevant-finding-combinations)`)
    lines.push(`5. [Mathematical universe walk](#5-mathematical-universe-walk)`)
    lines.push(`6. [Legend & references](#6-legend--references)`)
    lines.push(`7. [Attributions](#7-attributions)`)
    lines.push("")

    // ── §1 Method-tuple coverage
    lines.push(`## 1. Method-tuple coverage`)
    lines.push("")
    lines.push(`_For each discovered endpoint, every HTTP method in the universe that has not been sent yet._`)
    lines.push("")
    if (report.methods.length === 0) {
      lines.push(`_✓ All discovered endpoints have been tested against every applicable HTTP method._`)
    } else {
      for (const g of report.methods) {
        lines.push(`### \`${g.endpoint}\``)
        lines.push("")
        lines.push(`- Tested methods: ${g.testedMethods.length ? g.testedMethods.map((m) => `\`${m}\``).join(", ") : "_none_"}`)
        lines.push(`- Missing methods:`)
        for (const m of g.missingMethods) {
          // For each missing method, enumerate the applicable classes (with their references)
          // so the operator sees what testing is expected AFTER sending that method.
          const applicable = Checklist.forMethod(m)
          lines.push(`  - [ ] **\`${m}\`** — after sending this method, exercise every applicable vulnerability class:`)
          for (const cls of applicable) {
            const ref = classRef(cls.id)
            const parts: string[] = []
            if (ref?.wstgId) parts.push(`[${ref.wstgId}]`)
            if (ref?.hacktricks) parts.push(`[HackTricks](${ref.hacktricks.url})`)
            const suffix = parts.length ? ` (${parts.join(" · ")})` : ""
            lines.push(`    - [ ] ${cls.name} (\`${cls.id}\`)${suffix}`)
          }
        }
        lines.push("")
      }
    }
    lines.push("")

    // ── §2 Payload-family coverage
    lines.push(`## 2. Payload-family coverage (PayloadsAllTheThings)`)
    lines.push("")
    lines.push(`_For each engaged \`(endpoint, method, class)\` cell, every PayloadsAllTheThings payload family that has not been exercised yet. Upstream directory paths link to the source under \`swisskyrepo/PayloadsAllTheThings\`._`)
    lines.push("")
    if (report.payloads.length === 0) {
      lines.push(`_✓ Every engaged cell has been exercised against its full payload-family universe._`)
    } else {
      for (const g of report.payloads) {
        const ref = classRef(g.classId)
        lines.push(`### \`${g.method} ${g.endpoint}\` × **${g.className}** (\`${g.classId}\`)`)
        lines.push("")
        if (ref) {
          const refBits: string[] = []
          if (ref.wstgId) refBits.push(`WSTG \`${ref.wstgId}\``)
          if (ref.hacktricks) refBits.push(`[HackTricks: ${ref.hacktricks.title}](${ref.hacktricks.url})`)
          if (ref.chainHints.length) refBits.push(`chains with: ${ref.chainHints.map((c) => `\`${c}\``).join(", ")}`)
          if (refBits.length) lines.push(`- References: ${refBits.join(" · ")}`)
        }
        lines.push(`- Tested families: ${g.testedFamilies.length ? g.testedFamilies.map((f) => `\`${f}\``).join(", ") : "_none_"}`)
        lines.push(`- Missing families (send at least one representative payload per family):`)
        const famIndex = new Map(ref?.payloadFamilies.map((f) => [f.id, f]))
        for (const fid of g.missingFamilies) {
          const f = famIndex.get(fid)
          if (f) lines.push(`  - [ ] \`${fid}\` — ${f.hint} · upstream: \`${f.upstreamPath}\``)
          else lines.push(`  - [ ] \`${fid}\``)
        }
        if (ref?.techniques.length) {
          lines.push(`- Techniques from the built-in Checklist for this class (every technique should also be attempted):`)
          for (const t of ref.techniques) lines.push(`  - [ ] \`${t.id}\` — ${t.name}`)
        }
        lines.push("")
      }
    }
    lines.push("")

    // ── §3 Chain-pair coverage
    lines.push(`## 3. Chain-pair coverage`)
    lines.push("")
    lines.push(`_For each vulnerable \`A\`-cell, every \`B\`-cell for a chain-hinted class that has not yet been proven vulnerable. Chain the two together non-destructively._`)
    lines.push("")
    if (report.chains.length === 0) {
      lines.push(`_✓ Every vulnerable finding's chain hints have already been exercised (or exhaustively closed)._`)
    } else {
      for (const g of report.chains) {
        const refA = classRef(g.classA)
        const refB = classRef(g.classB)
        const hLinks = [refA?.hacktricks, refB?.hacktricks].filter(Boolean).map((h) => `[${h!.title}](${h!.url})`)
        lines.push(`- [ ] **${refA?.className ?? g.classA}** on \`${g.methodA} ${g.endpointA}\` (vulnerable) → **${refB?.className ?? g.classB}** on \`${g.methodB} ${g.endpointB}\` (${g.whyB})`)
        if (refA?.wstgId || refB?.wstgId) {
          const parts: string[] = []
          if (refA?.wstgId) parts.push(`A: WSTG \`${refA.wstgId}\``)
          if (refB?.wstgId) parts.push(`B: WSTG \`${refB.wstgId}\``)
          lines.push(`  - ${parts.join(" · ")}`)
        }
        if (hLinks.length) lines.push(`  - HackTricks: ${hLinks.join(" · ")}`)
      }
    }
    lines.push("")

    // ── §4 Per-relevant-finding combinations (three concentric shells, each enumerated)
    lines.push(`## 4. Per-relevant-finding combinations`)
    lines.push("")
    lines.push(`_For every recorded finding, the missing combos in its neighbourhood are split into three concentric shells:_`)
    lines.push(`- **L1** — same endpoint × same class (right around the finding)`)
    lines.push(`- **L2** — same endpoint × chain-hint class (chained impact on the same surface)`)
    lines.push(`- **L3** — same class × other endpoints (same weakness elsewhere)`)
    lines.push("")
    if (report.perFinding.length === 0) {
      lines.push(`_No findings recorded — per-finding combinations skipped._`)
    } else {
      for (const pf of report.perFinding) {
        const sevIcon = pf.severity === "critical" ? "🔴" : pf.severity === "high" ? "🟠" : pf.severity === "medium" ? "🟡" : pf.severity === "low" ? "🔵" : "⚪"
        lines.push(`### ${sevIcon} ${pf.severity.toUpperCase()} — ${pf.title}`)
        lines.push("")
        lines.push(`- Finding id: \`${pf.findingId}\`  ·  status: \`${pf.status}\``)
        if (pf.classId) {
          const ref = classRef(pf.classId)
          const parts: string[] = [`class: **${pf.classId}**`]
          if (ref?.wstgId) parts.push(`WSTG \`${ref.wstgId}\``)
          if (ref?.hacktricks) parts.push(`[HackTricks: ${ref.hacktricks.title}](${ref.hacktricks.url})`)
          if (pf.chainHints.length) parts.push(`chains with: ${pf.chainHints.map((c) => `\`${c}\``).join(", ")}`)
          lines.push(`- ${parts.join("  ·  ")}`)
        }
        if (pf.affectedComponent) lines.push(`- Affected: \`${pf.affectedComponent}\``)
        if (pf.inferredEndpoint) lines.push(`- Inferred endpoint: \`${pf.inferredEndpoint}\``)
        if (pf.evidenceFiles.length) lines.push(`- Evidence: ${pf.evidenceFiles.map((p) => `\`${p}\``).join(", ")}`)
        if (pf.description) lines.push(`- Description: ${pf.description.split("\n")[0]}${pf.description.length > 240 ? " …" : ""}`)
        if (pf.promotionChain.length) {
          lines.push(`- Promotion chain:`)
          for (const p of pf.promotionChain) lines.push(`  - \`${p.action}\` by \`${p.councilId}\` at \`${p.timestamp}\` — ${p.rationale}`)
        }
        const shells = shellsFor(pf)
        lines.push(`- Missing combos in neighbourhood: **${pf.missingCombos.length}** ` +
                   `(L1 ${shells.L1.length} · L2 ${shells.L2.length} · L3 ${shells.L3.length})`)
        renderShell(lines, "L1 — same endpoint × same class", shells.L1)
        renderShell(lines, "L2 — same endpoint × chain-hint class", shells.L2)
        renderShell(lines, "L3 — same class × other endpoints", shells.L3)
        lines.push("")
      }
    }

    // ── §5 Mathematical universe walk (full enumeration)
    lines.push(`## 5. Mathematical universe walk`)
    lines.push("")
    lines.push(`_The complete list of every \`(endpoint, method, class, payloadFamily)\` combo the algorithm iterates, grouped by endpoint × method × class. Combos marked ✓ have been exercised; combos marked \`[ ]\` are open._`)
    lines.push("")
    const cov = Coverage.load(report.target)
    const universe = enumerateAllCombos(cov)
    const satisfied = new Set(combosSatisfied(cov).map((c) => `${c.endpoint}||${c.method}||${c.classId}||${c.payloadFamilyId}`))
    // Group by (endpoint, method, classId) so the walk reads as one line per cell + its families.
    const walkGroups = new Map<string, { endpoint: string; method: string; classId: string; combos: Combo[] }>()
    for (const c of universe) {
      const k = `${c.endpoint}||${c.method}||${c.classId}`
      const bucket = walkGroups.get(k) ?? { endpoint: c.endpoint, method: c.method, classId: c.classId, combos: [] }
      bucket.combos.push(c)
      walkGroups.set(k, bucket)
    }
    const sortedWalk = Array.from(walkGroups.values()).sort((a, b) => {
      if (a.endpoint !== b.endpoint) return a.endpoint.localeCompare(b.endpoint)
      if (a.method !== b.method) return a.method.localeCompare(b.method)
      return a.classId.localeCompare(b.classId)
    })
    if (!sortedWalk.length) {
      lines.push(`_No endpoints discovered yet — the universe is empty._`)
    } else {
      for (const g of sortedWalk) {
        const ref = classRef(g.classId)
        lines.push(`### \`${g.method} ${g.endpoint}\` × **${ref?.className ?? g.classId}** (\`${g.classId}\`)`)
        lines.push("")
        if (ref) {
          const refBits: string[] = []
          if (ref.wstgId) refBits.push(`WSTG \`${ref.wstgId}\``)
          if (ref.hacktricks) refBits.push(`[HackTricks](${ref.hacktricks.url})`)
          if (refBits.length) lines.push(`- ${refBits.join(" · ")}`)
        }
        for (const c of g.combos) {
          const key = `${c.endpoint}||${c.method}||${c.classId}||${c.payloadFamilyId}`
          const done = satisfied.has(key) ? "✓" : "[ ]"
          const label = c.payloadFamilyId ? `family \`${c.payloadFamilyId}\`` : `_class-level (no vendored family taxonomy)_`
          lines.push(`- ${done} ${label}`)
        }
        lines.push("")
      }
    }
    lines.push("")

    // ── §6 Legend & references
    lines.push(`## 6. Legend & references`)
    lines.push("")
    lines.push(`- \`✓\`  combo satisfied (exercised at least once and recorded in the coverage store)`)
    lines.push(`- \`[ ]\`  combo open (still needs testing)`)
    lines.push(`- **L1 / L2 / L3**  concentric shells around a recorded finding (see §4 header)`)
    lines.push(`- **METHOD_UNIVERSE**  ${METHOD_UNIVERSE.map((m) => `\`${m}\``).join(", ")}`)
    lines.push(`- **Applicable classes** for a method come from \`Checklist.forMethod\`.`)
    lines.push(`- **Payload families** for a class come from \`packages/openhack/knowledge/payloadsallthethings-index.json\`.`)
    lines.push(`- **Chain hints** come from the \`chainHints\` field on \`Checklist.VulnClass\`.`)
    lines.push("")

    // ── §7 Attributions + versions
    const v = Knowledge.versions()
    lines.push(`## 7. Attributions`)
    lines.push("")
    lines.push(`- **PayloadsAllTheThings** by Swissky and contributors (MIT) — https://github.com/swisskyrepo/PayloadsAllTheThings`)
    lines.push(`- **HackTricks** by Carlos Polop and contributors (CC-BY-4.0) — https://book.hacktricks.wiki`)
    lines.push(`- **OWASP Web Security Testing Guide** by the OWASP Foundation (CC-BY-SA-4.0) — https://owasp.org/www-project-web-security-testing-guide/`)
    lines.push("")
    lines.push(`_Vendored index versions: PayloadsAllTheThings ${v.payloads} · HackTricks ${v.hacktricks} · WSTG ${v.wstg}. Refresh with \`bun run --cwd packages/openhack refresh:knowledge\`._`)
    return lines.join("\n")
  }

  /** Emit one shell's grouped combos. Never truncates. */
  function renderShell(lines: string[], heading: string, combos: Combo[]): void {
    lines.push(`- **${heading}** (${combos.length}${combos.length === 0 ? " — nothing open" : ""})`)
    if (!combos.length) return
    for (const g of groupCombos(combos)) {
      const ref = classRef(g.classId)
      const refBits: string[] = []
      if (ref?.wstgId) refBits.push(`WSTG \`${ref.wstgId}\``)
      if (ref?.hacktricks) refBits.push(`[HackTricks](${ref.hacktricks.url})`)
      const refSuffix = refBits.length ? `  (${refBits.join(" · ")})` : ""
      if (g.families.length) {
        lines.push(`  - [ ] \`${g.method} ${g.endpoint}\` × \`${g.classId}\`${refSuffix}`)
        for (const fid of g.families) {
          const fam = ref?.payloadFamilies.find((f) => f.id === fid)
          if (fam) lines.push(`    - [ ] family \`${fid}\` — ${fam.hint} · upstream: \`${fam.upstreamPath}\``)
          else lines.push(`    - [ ] family \`${fid}\``)
        }
      } else {
        lines.push(`  - [ ] \`${g.method} ${g.endpoint}\` × \`${g.classId}\` — class-level (no family taxonomy)${refSuffix}`)
      }
    }
  }
}
