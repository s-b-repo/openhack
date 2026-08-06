import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"
import { Net } from "./net"

export namespace ROE {
  export interface ROEDocument {
    id: string
    company: string
    client: string
    targets: string[]
    exclusions: string[]
    authorized_tools: string[]
    restricted_tools: string[]
    /**
     * LLM models authorized for the engagement (e.g. "deepseek/deepseek-v4",
     * "anthropic/claude-haiku-4-5"). Optional — absent or `["*"]` means every
     * model resolved by the provider layer is authorized. The runtime plugin
     * consults this on any `task`-tool dispatch that carries an explicit model
     * arg, and refuses if the model isn't in the list.
     *
     * Kept optional (not `= []`) for back-compat with pre-0.3 ROE documents
     * on disk; older files load, sign, and enforce as before.
     */
    authorized_models?: string[]
    date_start: string
    date_end: string
    authorized_personnel: string[]
    notes: string
    signature?: string
    signer_key?: string
    signed_at?: string
    expires_at: string
    status: "draft" | "signed" | "expired" | "revoked"
  }

  export interface ROEValidation {
    valid: boolean
    targetInScope: boolean
    toolAllowed: boolean
    notExpired: boolean
    signed: boolean
    reason?: string
  }

  const ROE_DIR = ".openhack/roe"
  const ACTIVE_ROE = path.join(ROE_DIR, "active.roe.json")

  function ensureDir(): void {
    if (!fs.existsSync(ROE_DIR)) fs.mkdirSync(ROE_DIR, { recursive: true })
  }

  export function createTemplate(company?: string, client?: string): ROEDocument {
    const id = `ROE-${new Date().toISOString().slice(0, 10)}-${crypto.randomBytes(3).toString("hex")}`
    return {
      id,
      company: company || "COMPANY_NAME",
      client: client || company || "CLIENT_NAME",
      targets: ["example.com", "10.0.0.0/24"],
      exclusions: [],
      authorized_tools: ["*"],
      restricted_tools: [],
      date_start: new Date().toISOString().slice(0, 10),
      date_end: new Date(Date.now() + 14 * 86400000).toISOString().slice(0, 10),
      authorized_personnel: [process.env.USER || "operator"],
      notes: "",
      expires_at: new Date(Date.now() + 14 * 86400000).toISOString(),
      status: "draft",
    }
  }

  export function save(roe: ROEDocument): void {
    ensureDir()
    fs.writeFileSync(ACTIVE_ROE, JSON.stringify(roe, null, 2), { encoding: "utf-8", mode: 0o600 })
    // Bust cache: any future load() re-reads and refreshes mtime.
    cachedRoe = null
  }

  // mtime-keyed cache — engagement plugin calls ROE.load() on every tool.execute.
  // A 2 s TTL bounds the freshness gap without noticeable staleness for humans;
  // an explicit mtime match catches on-disk edits earlier than the TTL.
  const ROE_LOAD_TTL_MS = 2_000
  let cachedRoe: { at: number; mtimeMs: number; roe: ROEDocument | null } | null = null

  export function load(): ROEDocument | null {
    if (!fs.existsSync(ACTIVE_ROE)) {
      cachedRoe = null
      return null
    }
    let mtimeMs = 0
    try { mtimeMs = fs.statSync(ACTIVE_ROE).mtimeMs } catch {}
    const now = Date.now()
    if (cachedRoe && now - cachedRoe.at < ROE_LOAD_TTL_MS && cachedRoe.mtimeMs === mtimeMs) return cachedRoe.roe
    try {
      const roe: ROEDocument = JSON.parse(fs.readFileSync(ACTIVE_ROE, "utf-8"))
      // Time-based expiry does NOT override an explicit `revoked` status —
      // both are terminal but revocation carries the stronger operator intent
      // ("this engagement is over, not just past its scheduled end"), and
      // silently downgrading to "expired" would lose that distinction.
      if (roe.status !== "revoked" && new Date(roe.expires_at) < new Date()) {
        roe.status = "expired"
        save(roe) // recompute mtime; save() clears the cache below.
      }
      cachedRoe = { at: now, mtimeMs, roe }
      return roe
    } catch {
      cachedRoe = { at: now, mtimeMs, roe: null }
      return null
    }
  }

  /**
   * Canonical serialization covering every authorization-relevant field. The
   * signature must change if ANY of these are edited after signing (previously
   * only id/company/targets/dates were covered, so post-signature edits to
   * authorized_tools, exclusions, or the expiry went undetected).
   */
  function signablePayload(roe: ROEDocument): string {
    return JSON.stringify({
      id: roe.id,
      company: roe.company,
      client: roe.client,
      targets: [...roe.targets].sort(),
      exclusions: [...roe.exclusions].sort(),
      authorized_tools: [...roe.authorized_tools].sort(),
      restricted_tools: [...roe.restricted_tools].sort(),
      // Optional field: pre-0.3 ROE files that never had `authorized_models`
      // sign as `null` here so they still verify after this upgrade. Once a
      // draft is edited to include the field, that draft's signature covers it.
      authorized_models: roe.authorized_models ? [...roe.authorized_models].sort() : null,
      date_start: roe.date_start,
      date_end: roe.date_end,
      expires_at: roe.expires_at,
      authorized_personnel: [...roe.authorized_personnel].sort(),
    })
  }

  // Signatures are keyed HMAC-SHA256, not a bare hash: a bare hash over a public,
  // deterministic payload is trivially forgeable (anyone can recompute it after
  // editing the ROE), which would defeat tamper detection. The key is generated
  // once and stored 0o600, mirroring findings.ts's integrity key.
  const SIGNING_KEY_FILE = path.join(ROE_DIR, ".signing_key")
  let cachedSigningKey: string | null = null
  function getSigningKey(): string {
    if (cachedSigningKey) return cachedSigningKey
    ensureDir()
    try {
      cachedSigningKey = fs.readFileSync(SIGNING_KEY_FILE, "utf-8").trim()
    } catch {
      cachedSigningKey = crypto.randomBytes(32).toString("hex")
      fs.writeFileSync(SIGNING_KEY_FILE, cachedSigningKey, { encoding: "utf-8", mode: 0o600 })
    }
    return cachedSigningKey
  }

  function computeSignature(roe: ROEDocument): string {
    return crypto.createHmac("sha256", getSigningKey()).update(signablePayload(roe)).digest("hex")
  }

  export function sign(roe: ROEDocument): ROEDocument {
    roe.signature = computeSignature(roe)
    roe.signer_key = process.env.USER || "operator"
    roe.signed_at = new Date().toISOString()
    roe.status = "signed"
    save(roe)
    return roe
  }

  /** True if the ROE carries a valid HMAC over its authorization fields (constant-time). */
  export function verifySignature(roe: ROEDocument): boolean {
    if (!roe.signature) return false
    const expected = Buffer.from(computeSignature(roe), "hex")
    let provided: Buffer
    try {
      provided = Buffer.from(roe.signature, "hex")
    } catch {
      return false
    }
    return expected.length === provided.length && crypto.timingSafeEqual(expected, provided)
  }

  export function revoke(roe: ROEDocument): ROEDocument {
    roe.status = "revoked"
    roe.expires_at = new Date().toISOString()
    save(roe)
    return roe
  }

  export function validate(roe: ROEDocument | null, target: string, tool: string): ROEValidation {
    if (!roe) {
      return { valid: false, targetInScope: false, toolAllowed: false, notExpired: false, signed: false, reason: "No ROE loaded. Create one with /roe create" }
    }
    if (roe.status === "revoked") {
      return { valid: false, targetInScope: false, toolAllowed: false, notExpired: false, signed: false, reason: "ROE has been revoked" }
    }
    if (roe.status === "expired" || new Date(roe.expires_at) < new Date()) {
      return { valid: false, targetInScope: false, toolAllowed: false, notExpired: false, signed: true, reason: "ROE has expired — create new ROE" }
    }
    if (roe.status !== "signed") {
      return { valid: false, targetInScope: false, toolAllowed: false, notExpired: true, signed: false, reason: "ROE not signed — use /roe sign" }
    }

    const targetInScope = isTargetInScope(roe, target)
    const toolAllowed = isToolAllowed(roe, tool)
    const notExpired = new Date(roe.expires_at) > new Date()

    return {
      valid: targetInScope && toolAllowed && notExpired,
      targetInScope,
      toolAllowed,
      notExpired,
      signed: true,
      reason: !targetInScope ? `Target ${target} not in ROE scope: ${roe.targets.join(", ")}` :
               !toolAllowed ? `Tool ${tool} not authorized in ROE` : undefined,
    }
  }

  /**
   * Central enforcement decision for a single action. Unlike `validate`, this
   * treats a missing target (e.g. `ls`) and a draft/absent ROE as "allowed"
   * rather than blocking, and only hard-blocks revoked/expired ROEs or a signed
   * ROE's out-of-scope target / unauthorized tool. Used by the OpenHack plugin
   * and CLI so every path enforces the ROE identically.
   */
  export function enforce(
    roe: ROEDocument | null,
    target: string | null,
    tool: string,
  ): { blocked: boolean; reason?: string } {
    if (!roe) return { blocked: false }
    if (roe.status === "revoked")
      return { blocked: true, reason: `ROE ${roe.id} has been revoked — create a new ROE with /roe create` }
    if (roe.status === "expired" || new Date(roe.expires_at) < new Date())
      return { blocked: true, reason: `ROE ${roe.id} expired on ${roe.date_end} — create a new ROE with /roe create` }
    if (roe.status !== "signed") return { blocked: false } // draft — advisory only
    if (!verifySignature(roe))
      return {
        blocked: true,
        reason: `ROE ${roe.id} signature mismatch — it was modified after signing; re-sign with /roe sign`,
      }
    // The ROE governs testing activity against a target. A command with no
    // target (ls, cd, cat, git status, …) is not a pentest action, so neither
    // scope nor tool authorization applies to it.
    if (!target) return { blocked: false }
    if (!roe.targets.includes("*") && !isTargetInScope(roe, target))
      return { blocked: true, reason: `Target ${target} not in ROE scope (${roe.targets.join(", ")})` }
    if (!isToolAllowed(roe, tool))
      return { blocked: true, reason: `Tool '${tool}' not authorized in ROE (${roe.authorized_tools.join(", ")})` }
    return { blocked: false }
  }

  /**
   * Is `model` (e.g. "deepseek/deepseek-v4") authorized by this ROE?
   *
   *   • no ROE                       → allowed (nothing to enforce)
   *   • ROE without authorized_models → allowed (back-compat)
   *   • authorized_models=[*]        → allowed
   *   • model exact-match OR any wildcard entry (`anthropic/*`) matches → allowed
   */
  export function enforceModel(roe: ROEDocument | null, model: string): { blocked: boolean; reason?: string } {
    if (!roe) return { blocked: false }
    const list = roe.authorized_models
    if (!list || !list.length) return { blocked: false }
    if (list.includes("*")) return { blocked: false }
    if (list.includes(model)) return { blocked: false }
    for (const pattern of list) {
      if (Net.wildcardMatch(pattern, model)) return { blocked: false }
    }
    return {
      blocked: true,
      reason: `Model '${model}' not in ROE authorized_models (${list.join(", ")})`,
    }
  }

  function isTargetInScope(roe: ROEDocument, target: string): boolean {
    if (roe.targets.includes("*")) return true
    for (const exclusion of roe.exclusions) {
      if (Net.matchTarget(exclusion, target)) return false
    }
    return roe.targets.some((t) => Net.matchTarget(t, target))
  }

  function isToolAllowed(roe: ROEDocument, tool: string): boolean {
    if (roe.authorized_tools.includes("*")) return true
    if (roe.restricted_tools.includes(tool)) return false
    return roe.authorized_tools.some((allowed) => Net.wildcardMatch(allowed, tool))
  }

  export function generateMarkdown(roe: ROEDocument): string {
    return `# Rules of Engagement: ${roe.id}

## Parties
- **Assessment Company**: ${roe.company}
- **Client**: ${roe.client}

## Scope
- **Targets**: ${roe.targets.join("\n  - ")}
- **Exclusions**: ${roe.exclusions.length > 0 ? roe.exclusions.join("\n  - ") : "None"}

## Authorized Testing
- **Tools**: ${roe.authorized_tools.join(", ")}
- **Restricted**: ${roe.restricted_tools.length > 0 ? roe.restricted_tools.join(", ") : "None"}
- **Methods**: Penetration testing, vulnerability assessment, configuration review

## Timeline
- **Start**: ${roe.date_start}
- **End**: ${roe.date_end}

## Personnel
${roe.authorized_personnel.map((p) => `- ${p}`).join("\n")}

## Rules
1. Test only in-scope targets
2. Use only authorized tools
3. Stop testing if system instability is detected
4. Report critical findings immediately
5. Maintain confidentiality of all findings

## Signatures
${roe.signature ? `- Signed: ${roe.signer_key}\n- Date: ${roe.signed_at}\n- Signature: ${roe.signature}` : "- [UNSIGNED]"}
${roe.notes ? `\n## Notes\n${roe.notes}` : ""}
`
  }

  export function getStatusString(roe: ROEDocument | null): string {
    if (!roe) return "No ROE loaded"
    const icon = roe.status === "signed" ? "✓" : roe.status === "expired" ? "⏰" : roe.status === "revoked" ? "✗" : "📝"
    return `${icon} ROE ${roe.id}: ${roe.status.toUpperCase()} — ${roe.company} → ${roe.targets.length} targets — Expires: ${roe.date_end}`
  }

  export function extractTarget(command: string): string | null {
    return Net.firstTarget(command)
  }

  export function extractTool(command: string): string {
    return command.trim().split(/\s+/)[0]
  }
}
