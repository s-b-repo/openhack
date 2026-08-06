import * as fs from "fs"
import * as path from "path"
import * as crypto from "crypto"

export namespace Findings {
  export interface AuditEntry {
    timestamp: string
    event: string
    agent: string
    details?: string
  }

  export interface PromotionRecord {
    councilId: string
    councilType: string
    action: "discovered" | "promoted" | "validated" | "challenged" | "confirmed_false_positive" | "escalated" | "missed_gap"
    agentId?: string
    confidence: number
    rationale: string
    timestamp: string
  }

  export interface Finding {
    id: string
    timestamp: string
    target: string
    title: string
    description: string
    severity: "critical" | "high" | "medium" | "low" | "info"
    status: "verified" | "uncertain" | "false_positive"
    cwe?: string
    cvss_score?: number
    cvss_vector?: string
    affected_component?: string
    proof_of_concept?: string
    remediation?: string
    source_agent: string
    source_session: string
    source_workflow?: string
    evidence_files: string[]
    manual_verify_required: boolean
    oracle_name?: string
    audit_trail: AuditEntry[]
    promotionChain: PromotionRecord[]
    sourceCouncilId?: string
    challengedByCouncils: string[]
    hash: string
    hmac: string
    tags: string[]
  }

  export interface FindingsStore {
    target: string
    sessionId: string
    findings: Finding[]
    lastUpdated: string
    totalCount: number
    bySeverity: Record<string, number>
    byStatus: Record<string, number>
  }

  const STORE_DIR = ".openhack/findings"

  function ensureDir(): void {
    if (!fs.existsSync(STORE_DIR)) {
      fs.mkdirSync(STORE_DIR, { recursive: true })
    }
  }

  function getStorePath(target: string): string {
    const safeName = target.replace(/[^a-zA-Z0-9.-]/g, "_")
    return path.join(STORE_DIR, `${safeName}.json`)
  }

  function computeHash(finding: Partial<Finding>): string {
    const content = [
      finding.target || "",
      finding.title || "",
      finding.cwe || "NONE",
      finding.affected_component || "NONE",
    ].join("|")
    return crypto.createHash("sha256").update(content).digest("hex").slice(0, 16)
  }

  function computeHMAC(finding: Finding, key: string): string {
    const content = JSON.stringify({
      id: finding.id,
      target: finding.target,
      title: finding.title,
      severity: finding.severity,
      status: finding.status,
      cwe: finding.cwe,
      cvss_score: finding.cvss_score,
      affected_component: finding.affected_component,
      source_agent: finding.source_agent,
      timestamp: finding.timestamp,
    })
    return crypto.createHmac("sha256", key).update(content).digest("hex")
  }

  let signingKey: string | null = null

  function getSigningKey(): string {
    if (signingKey) return signingKey
    const keyPath = path.join(STORE_DIR, ".signing_key")
    try {
      signingKey = fs.readFileSync(keyPath, "utf-8").trim()
    } catch {
      signingKey = crypto.randomBytes(32).toString("hex")
      ensureDir()
      fs.writeFileSync(keyPath, signingKey, { encoding: "utf-8", mode: 0o600 })
    }
    return signingKey
  }

  function verifyHMAC(finding: Finding): boolean {
    const key = getSigningKey()
    const computed = computeHMAC(finding, key)
    return computed === finding.hmac
  }

  export function load(target: string, sessionId?: string): FindingsStore {
    ensureDir()
    const filepath = getStorePath(target)
    if (fs.existsSync(filepath)) {
      try {
        const store: FindingsStore = JSON.parse(fs.readFileSync(filepath, "utf-8"))
        store.findings = store.findings.filter((f) => {
      const valid = verifyHMAC(f)
      if (!valid) console.error(`[findings] HMAC verification failed for finding ${f.id} — data may be tampered. Finding dropped.`)
      return valid
    })
        return store
      } catch {
        return emptyStore(target, sessionId)
      }
    }
    return emptyStore(target, sessionId)
  }

  export function save(store: FindingsStore): void {
    ensureDir()
    store.lastUpdated = new Date().toISOString()
    store.totalCount = store.findings.length
    store.bySeverity = {}
    store.byStatus = {}
    for (const f of store.findings) {
      store.bySeverity[f.severity] = (store.bySeverity[f.severity] || 0) + 1
      store.byStatus[f.status] = (store.byStatus[f.status] || 0) + 1
    }
    const filepath = getStorePath(store.target)
    fs.writeFileSync(filepath, JSON.stringify(store, null, 2), { encoding: "utf-8", mode: 0o600 })
  }

  /**
   * Cross-process advisory lock (atomic mkdir) around a store mutation, so parallel
   * agent subprocesses writing the same target's findings can't clobber each other.
   * Reclaims a stale lock after 10s; gives up waiting after ~15s and forces through.
   */
  function withLock<T>(target: string, fn: () => T): T {
    ensureDir()
    const lock = path.join(STORE_DIR, `.lock-${target.replace(/[^a-zA-Z0-9.-]/g, "_")}`)
    const start = Date.now()
    for (;;) {
      try {
        fs.mkdirSync(lock)
        break
      } catch {
        try {
          if (Date.now() - fs.statSync(lock).mtimeMs > 10_000) fs.rmSync(lock, { recursive: true, force: true })
        } catch {}
        if (Date.now() - start > 15_000) {
          try { fs.rmSync(lock, { recursive: true, force: true }) } catch {}
          continue
        }
        try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25) } catch {}
      }
    }
    try {
      return fn()
    } finally {
      try { fs.rmSync(lock, { recursive: true, force: true }) } catch {}
    }
  }

  export function emptyStore(target: string, sessionId?: string): FindingsStore {
    return {
      target,
      sessionId: sessionId || "unknown",
      findings: [],
      lastUpdated: new Date().toISOString(),
      totalCount: 0,
      bySeverity: {},
      byStatus: {},
    }
  }

  /**
   * A finding may only be stored as "verified" if it carries real proof: a
   * non-empty PoC and at least one evidence file that exists on disk. Anything
   * claiming "verified" without both is downgraded to "uncertain" so it must be
   * manually verified (via markVerified with evidence) before it counts.
   */
  function enforceEvidenceGate(finding: Finding): void {
    if (finding.status !== "verified") return
    const hasPoc = Boolean(finding.proof_of_concept && finding.proof_of_concept.trim())
    const hasEvidence = (finding.evidence_files ?? []).some((p) => p && fs.existsSync(p))
    if (hasPoc && hasEvidence) return
    finding.status = "uncertain"
    finding.manual_verify_required = true
    finding.audit_trail = finding.audit_trail ?? []
    finding.audit_trail.push({
      timestamp: new Date().toISOString(),
      event: "Verified status downgraded to uncertain",
      agent: finding.source_agent || "system",
      details: `Claimed "verified" without proof (${!hasPoc ? "no PoC" : "no on-disk evidence file"}); requires evidence-backed verification.`,
    })
  }

  export function add(store: FindingsStore, finding: Finding, sessionId?: string): FindingsStore {
    enforceEvidenceGate(finding)
    finding.hash = computeHash(finding)

    // Atomic under the target lock: reload the on-disk store so a concurrent writer's
    // findings aren't lost, merge this finding, persist, then reflect back into the
    // caller's in-memory store. (Safe for parallel agent subprocesses.)
    return withLock(store.target, () => {
      const disk = fs.existsSync(getStorePath(store.target)) ? load(store.target, sessionId) : store
      const result = addInto(disk, finding, sessionId)
      // reflect merged state into the caller's store reference
      store.findings = result.findings
      store.totalCount = result.totalCount
      store.bySeverity = result.bySeverity
      store.byStatus = result.byStatus
      store.lastUpdated = result.lastUpdated
      return store
    })
  }

  /** Non-locking merge of a finding into a store (the body of `add`, run under lock). */
  function addInto(store: FindingsStore, finding: Finding, sessionId?: string): FindingsStore {
    const existingIdx = store.findings.findIndex((f) => f.hash === finding.hash)
    if (existingIdx >= 0) {
      const existing = store.findings[existingIdx]
      // Verification is sticky: a re-detected or unproven duplicate must never
      // silently un-verify a finding that already has evidence. Only markFalsePositive
      // or an evidence-backed markVerified changes a verified finding's status.
      if (existing.status !== "verified") {
        existing.status = finding.status
        existing.manual_verify_required = finding.status !== "verified"
      }
      existing.severity = finding.severity
      existing.description = finding.description
      if (finding.proof_of_concept) existing.proof_of_concept = finding.proof_of_concept
      existing.source_agent = finding.source_agent || existing.source_agent
      existing.source_session = finding.source_session || existing.source_session
      existing.audit_trail.push({
        timestamp: new Date().toISOString(),
        event: `Updated by ${finding.source_agent}`,
        agent: finding.source_agent,
        details: "Deduplicated — existing finding updated with new data",
      })
      existing.hmac = computeHMAC(existing, getSigningKey())
      save(store)
      return store
    }

    finding.id = generateId()
    finding.manual_verify_required = finding.status !== "verified"
    finding.source_session = sessionId || finding.source_session || "unknown"
    finding.timestamp = finding.timestamp || new Date().toISOString()
    finding.promotionChain = finding.promotionChain || []
    finding.challengedByCouncils = finding.challengedByCouncils || []
    finding.hash = computeHash(finding)
    finding.hmac = computeHMAC(finding, getSigningKey())

    finding.audit_trail.push({
      timestamp: new Date().toISOString(),
      event: `Discovered by ${finding.source_agent}`,
      agent: finding.source_agent,
    })

    store.findings.push(finding)
    save(store)
    return store
  }

  export function getUncertain(store: FindingsStore): Finding[] {
    return store.findings.filter((f) => f.manual_verify_required)
  }

  export function getVerified(store: FindingsStore): Finding[] {
    return store.findings.filter((f) => f.status === "verified")
  }

  export interface VerificationEvidence {
    /** A reproducible proof-of-concept (command, request, or precise steps). */
    poc: string
    /** Paths to on-disk evidence artifacts (request/response captures, screenshots). */
    evidenceFiles: string[]
  }

  /**
   * Promote a finding to "verified" — but ONLY with real evidence. A finding is
   * verified when an oracle supplies a non-empty reproducible PoC AND at least one
   * evidence file that actually exists on disk. Without both, the finding stays
   * "uncertain" (manual_verify_required) and the rejection is recorded in the audit
   * trail. This closes the path where keyword detection or a bare claim marks a
   * finding "verified" with no proof.
   */
  export function markVerified(
    store: FindingsStore,
    id: string,
    oracle: string,
    evidence?: VerificationEvidence,
  ): FindingsStore {
    const finding = store.findings.find((f) => f.id === id)
    if (!finding) return store

    const poc = evidence?.poc?.trim()
    const files = (evidence?.evidenceFiles ?? []).filter((p) => p && p.trim())
    const existingFiles = files.filter((p) => fs.existsSync(p))
    const missingFiles = files.filter((p) => !fs.existsSync(p))

    if (!poc || existingFiles.length === 0) {
      const why = !poc
        ? "no reproducible PoC supplied"
        : `no evidence file exists on disk${missingFiles.length ? ` (missing: ${missingFiles.join(", ")})` : ""}`
      finding.audit_trail.push({
        timestamp: new Date().toISOString(),
        event: `Verification rejected by ${oracle}`,
        agent: "oracle",
        details: `Kept uncertain — ${why}. Verification requires a PoC + at least one on-disk evidence file.`,
      })
      finding.hmac = computeHMAC(finding, getSigningKey())
      save(store)
      return store
    }

    finding.status = "verified"
    finding.manual_verify_required = false
    finding.oracle_name = oracle
    finding.proof_of_concept = poc
    finding.evidence_files = Array.from(new Set([...(finding.evidence_files ?? []), ...existingFiles]))
    finding.audit_trail.push({
      timestamp: new Date().toISOString(),
      event: `Verified by ${oracle}`,
      agent: "oracle",
      details: `PoC recorded; evidence: ${existingFiles.join(", ")}`,
    })
    finding.hmac = computeHMAC(finding, getSigningKey())
    save(store)
    return store
  }

  export function markFalsePositive(store: FindingsStore, id: string, reason: string): FindingsStore {
    const finding = store.findings.find((f) => f.id === id)
    if (finding) {
      finding.status = "false_positive"
      finding.manual_verify_required = false
      finding.audit_trail.push({
        timestamp: new Date().toISOString(),
        event: `Marked false positive: ${reason}`,
        agent: "user",
      })
      finding.hmac = computeHMAC(finding, getSigningKey())
      save(store)
    }
    return store
  }

  export function deduplicate(store: FindingsStore): { removed: number; findings: Finding[] } {
    const seen = new Map<string, Finding>()
    const removed: Finding[] = []

    for (const finding of store.findings) {
      const existing = seen.get(finding.hash)
      if (existing) {
        if (finding.severity === "critical" && existing.severity !== "critical") {
          seen.set(finding.hash, finding)
          removed.push(existing)
        } else if (finding.status === "verified" && existing.status !== "verified") {
          seen.set(finding.hash, finding)
          removed.push(existing)
        } else {
          removed.push(finding)
        }
      } else {
        seen.set(finding.hash, finding)
      }
    }

    store.findings = Array.from(seen.values())
    save(store)

    return { removed: removed.length, findings: removed }
  }

  export function formatFindingsSummary(store: FindingsStore): string {
    let summary = `# Findings: ${store.target}\n\n`
    summary += `**Total**: ${store.totalCount} | `
    summary += `✓ Verified: ${store.byStatus["verified"] || 0} | `
    summary += `⚠ Uncertain: ${store.byStatus["uncertain"] || 0} | `
    summary += `✗ False: ${store.byStatus["false_positive"] || 0}\n\n`

    summary += `## By Severity\n`
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
      const count = store.bySeverity[sev] || 0
      if (count > 0) {
        summary += `- ${sev.toUpperCase()}: ${count}\n`
      }
    }

    summary += `\n## Findings\n\n`
    for (const f of store.findings) {
      const icon = f.status === "verified" ? "✓" : f.status === "false_positive" ? "✗" : "⚠"
      const verifyNote = f.manual_verify_required ? " **MANUAL VERIFY REQUIRED**" : ""
      summary += `### ${icon} ${f.title}\n`
      summary += `- **Severity**: ${f.severity.toUpperCase()}\n`
      summary += `- **Status**: ${f.status}${verifyNote}\n`
      if (f.oracle_name) summary += `- **Oracle**: ${f.oracle_name}\n`
      if (f.cwe) summary += `- **CWE**: ${f.cwe}\n`
      if (f.cvss_score) summary += `- **CVSS**: ${f.cvss_score}\n`
      if (f.affected_component) summary += `- **Component**: ${f.affected_component}\n`
      summary += `\n${f.description.slice(0, 200)}${f.description.length > 200 ? "..." : ""}\n\n`
    }

    return summary
  }

  export function generateId(): string {
    const ts = Date.now().toString(36)
    const rand = crypto.randomBytes(4).toString("hex")
    return `FIND-${ts}-${rand}`
  }

  export function getIntegrityViolations(store: FindingsStore): Finding[] {
    return store.findings.filter((f) => !verifyHMAC(f))
  }
}
