/**
 * @openhack-ai/board — project-scoped agent config + a signed, verified message board.
 *
 * Native TypeScript port of the ai-board tool, for OpenHack.
 *
 * Per project (a folder), everything lives under `<project>/.aiboard/`:
 *   config.json          main-session + sub-agent provider/model/api-key (0600)
 *   keys/<agent>.key     per-agent Ed25519 private key, PKCS8 PEM (0600)
 *   board.jsonl          append-only, hash-chained, Ed25519-signed messages
 *
 * Security model for the board:
 *   - Each message is signed with the posting agent's Ed25519 private key.
 *   - Each message carries `prev` = SHA-256 of the previous entry, so the log is
 *     a hash chain: editing, reordering, inserting or deleting any message breaks
 *     verification from that point on.
 *   - The signature covers the canonical bytes of (seq, ts, author, body, prev,
 *     pubkey). Tampering with any field invalidates the signature.
 *   - Verification also checks a message's pubkey matches the author's registered
 *     identity, so a message cannot be forged "from recon" with another key.
 *
 * API keys may be a literal secret or an `env:VARNAME` reference (preferred — the
 * secret never touches disk). Files are written 0600.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"

export const GENESIS = "0".repeat(64)
export const CONFIG_VERSION = 1

export const PROVIDER_MODELS: Record<string, string[]> = {
  anthropic: ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"],
  openai: ["gpt-4o", "o3", "gpt-4o-mini"],
  google: ["gemini-2.5-pro", "gemini-2.5-flash"],
  deepseek: ["deepseek-v4", "deepseek-r1"],
  local: ["peregrine"],
}
export const PROVIDER_ENV: Record<string, string> = {
  anthropic: "ANTHROPIC_API_KEY",
  openai: "OPENAI_API_KEY",
  google: "GOOGLE_GENERATIVE_AI_API_KEY",
  deepseek: "DEEPSEEK_API_KEY",
  local: "",
}
export const DEFAULT_SUBAGENTS = ["recon", "exploit", "post-exploit", "c2", "report", "general"]

// Agent names become filesystem paths (keys/<agent>.key), so they must be a
// safe slug — otherwise "../../x" would write/read key files outside the project.
const AGENT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
export function assertAgentName(name: string): void {
  if (name === "main") return
  if (typeof name !== "string" || !AGENT_NAME_RE.test(name) || name.includes("..")) {
    throw new Error(`invalid agent name ${JSON.stringify(name)} (allowed: letters, digits, '.', '_', '-'; no '..')`)
  }
}

function sleepSync(ms: number): void {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
  } catch {
    /* SharedArrayBuffer unavailable — fall through (busy spin is bounded by deadline) */
  }
}

// --------------------------------------------------------------------------- fs
function writePrivate(file: string, data: string | Buffer): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  fs.writeFileSync(file, data, { mode: 0o600 })
  try {
    fs.chmodSync(file, 0o600)
  } catch {
    /* best effort (e.g. non-POSIX) */
  }
}

// --------------------------------------------------------------------------- crypto
export class Identity {
  constructor(public priv: KeyObject) {}

  static generate(): Identity {
    const { privateKey } = generateKeyPairSync("ed25519")
    return new Identity(privateKey)
  }
  static fromPem(pem: string): Identity {
    return new Identity(createPrivateKey(pem))
  }
  pem(): string {
    return this.priv.export({ type: "pkcs8", format: "pem" }).toString()
  }
  /** Self-contained public key: base64 of the SPKI DER. Verifiable anywhere. */
  pubSpki(): string {
    return createPublicKey(this.priv).export({ type: "spki", format: "der" }).toString("base64")
  }
  sign(data: Buffer): string {
    return edSign(null, data, this.priv).toString("hex")
  }
}

export function verifySig(pubSpkiB64: string, sigHex: string, data: Buffer): boolean {
  try {
    const pub = createPublicKey({
      key: Buffer.from(pubSpkiB64, "base64"),
      format: "der",
      type: "spki",
    })
    return edVerify(null, data, pub, Buffer.from(sigHex, "hex"))
  } catch {
    return false
  }
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex")
}

// --------------------------------------------------------------------------- types
export interface AgentConfig {
  name: string
  provider: string
  model: string
  apiKey: string // literal secret, or "env:VARNAME"
}

export function makeAgent(name: string, provider = "", model = "", apiKey = ""): AgentConfig {
  return { name, provider, model, apiKey }
}

export function resolvedKey(a: AgentConfig): string | null {
  if (!a.apiKey) return null
  if (a.apiKey.startsWith("env:")) return process.env[a.apiKey.slice(4)] || null
  return a.apiKey
}

export function keyDisplay(a: AgentConfig): string {
  if (!a.apiKey) return "— none —"
  if (a.apiKey.startsWith("env:")) {
    const v = a.apiKey.slice(4)
    return `env:${v} (${process.env[v] ? "set" : "UNSET"})`
  }
  return a.apiKey.length >= 4 ? `literal •••${a.apiKey.slice(-4)}` : "literal ••••"
}

export interface BoardMessage {
  seq: number
  ts: string
  author: string
  body: string
  prev: string
  pubkey: string
  sig: string
}

export interface VerifyResult {
  msg: BoardMessage
  ok: boolean
  reason: string
}

// canonical bytes the signature covers (fixed key order => deterministic)
function canonical(seq: number, ts: string, author: string, body: string, prev: string, pubkey: string): Buffer {
  return Buffer.from(JSON.stringify({ seq, ts, author, body, prev, pubkey }), "utf8")
}

function entryHash(m: BoardMessage): string {
  return sha256Hex(
    JSON.stringify({
      seq: m.seq, ts: m.ts, author: m.author, body: m.body,
      prev: m.prev, pubkey: m.pubkey, sig: m.sig,
    }),
  )
}

// --------------------------------------------------------------------------- project
export class Project {
  readonly root: string
  readonly dir: string
  readonly configPath: string
  readonly keysDir: string
  readonly boardPath: string
  main: AgentConfig = makeAgent("main")
  agents: Record<string, AgentConfig> = {}

  constructor(root: string) {
    this.root = path.resolve(root.replace(/^~(?=$|\/)/, os.homedir()))
    this.dir = path.join(this.root, ".aiboard")
    this.configPath = path.join(this.dir, "config.json")
    this.keysDir = path.join(this.dir, "keys")
    this.boardPath = path.join(this.dir, "board.jsonl")
  }

  exists(): boolean {
    return fs.existsSync(this.configPath)
  }

  load(): this {
    if (this.exists()) {
      const data = JSON.parse(fs.readFileSync(this.configPath, "utf8"))
      const m = data.main ?? {}
      this.main = makeAgent("main", m.provider ?? "", m.model ?? "", m.api_key ?? "")
      this.agents = {}
      for (const [name, a] of Object.entries<{ provider?: string; model?: string; api_key?: string }>(data.agents ?? {})) {
        this.agents[name] = makeAgent(name, a.provider ?? "", a.model ?? "", a.api_key ?? "")
      }
    }
    return this
  }

  initDefaults(): this {
    this.main = makeAgent("main", "anthropic", "claude-opus-5-5", "env:ANTHROPIC_API_KEY")
    this.agents = {}
    for (const n of DEFAULT_SUBAGENTS) this.agents[n] = makeAgent(n)
    this.save()
    return this
  }

  save(): void {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 })
    const toJson = (a: AgentConfig) => ({ provider: a.provider, model: a.model, api_key: a.apiKey })
    const data = {
      version: CONFIG_VERSION,
      main: toJson(this.main),
      agents: Object.fromEntries(Object.entries(this.agents).map(([n, a]) => [n, toJson(a)])),
    }
    writePrivate(this.configPath, JSON.stringify(data, null, 2) + "\n")
  }

  allAgents(): AgentConfig[] {
    return [this.main, ...Object.keys(this.agents).sort().map((n) => this.agents[n])]
  }
  getAgent(name: string): AgentConfig | undefined {
    return name === "main" ? this.main : this.agents[name]
  }
  addAgent(name: string): AgentConfig {
    name = name.trim()
    if (name === "main" || this.agents[name]) throw new Error("invalid or duplicate agent name")
    assertAgentName(name)
    const a = makeAgent(name)
    this.agents[name] = a
    this.save()
    return a
  }
  removeAgent(name: string): void {
    if (this.agents[name]) {
      delete this.agents[name]
      this.save()
    }
  }

  // ---- identities ----
  identity(agent: string): Identity {
    assertAgentName(agent) // defense in depth: never let a name escape keysDir
    const file = path.join(this.keysDir, `${agent}.key`)
    if (fs.existsSync(file)) return Identity.fromPem(fs.readFileSync(file, "utf8"))
    const id = Identity.generate()
    writePrivate(file, id.pem())
    return id
  }
  registeredPub(agent: string): string | null {
    // Called with the (attacker-controlled) author from a board entry during
    // verification, so an invalid name must fail safe (null), never throw.
    try {
      assertAgentName(agent)
    } catch {
      return null
    }
    const file = path.join(this.keysDir, `${agent}.key`)
    if (!fs.existsSync(file)) return null
    return this.identity(agent).pubSpki()
  }

  // ---- board ----
  /** Non-empty raw lines with 1-based line numbers (no parsing). */
  private rawEntries(): { text: string; lineNo: number }[] {
    if (!fs.existsSync(this.boardPath)) return []
    const out: { text: string; lineNo: number }[] = []
    const lines = fs.readFileSync(this.boardPath, "utf8").split("\n")
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim()
      if (t) out.push({ text: t, lineNo: i + 1 })
    }
    return out
  }

  /** Strict parse — throws on a corrupt line. Used when we need valid entries. */
  loadBoard(): BoardMessage[] {
    return this.rawEntries().map((e) => {
      try {
        return JSON.parse(e.text) as BoardMessage
      } catch {
        throw new Error(`board.jsonl is corrupt at line ${e.lineNo}`)
      }
    })
  }

  private withLock<T>(fn: () => T): T {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 })
    const lp = path.join(this.dir, "board.lock")
    const deadline = Date.now() + 5000
    let fd: number | undefined
    for (;;) {
      try {
        fd = fs.openSync(lp, "wx") // atomic create; fails EEXIST if held
        break
      } catch (e) {
        if ((e as NodeJS.ErrnoException)?.code !== "EEXIST") throw e
        try {
          // steal a stale lock left by a crashed writer
          if (Date.now() - fs.statSync(lp).mtimeMs > 30000) {
            fs.unlinkSync(lp)
            continue
          }
        } catch {
          /* lock vanished — retry */
        }
        if (Date.now() > deadline) throw new Error("timed out acquiring the board lock")
        sleepSync(25)
      }
    }
    try {
      return fn()
    } finally {
      try {
        if (fd !== undefined) fs.closeSync(fd)
      } catch {
        /* ignore */
      }
      try {
        fs.unlinkSync(lp)
      } catch {
        /* ignore */
      }
    }
  }

  post(author: string, body: string): BoardMessage {
    assertAgentName(author)
    const id = this.identity(author)
    const pubkey = id.pubSpki()
    // Lock the read-last-entry → append critical section so concurrent posters
    // (multiple agents) cannot both claim the same seq/prev and fork the chain.
    return this.withLock(() => {
      const board = this.loadBoard()
      const seq = board.length ? board[board.length - 1].seq + 1 : 0
      const prev = board.length ? entryHash(board[board.length - 1]) : GENESIS
      const ts = new Date().toISOString().replace(/\.\d+Z$/, "Z")
      const sig = id.sign(canonical(seq, ts, author, body, prev, pubkey))
      const msg: BoardMessage = { seq, ts, author, body, prev, pubkey, sig }
      fs.appendFileSync(this.boardPath, JSON.stringify(msg) + "\n")
      return msg
    })
  }

  verifyBoard(): VerifyResult[] {
    const entries = this.rawEntries()
    const results: VerifyResult[] = []
    let expectedPrev = GENESIS
    let expectedSeq = 0
    for (const { text, lineNo } of entries) {
      // A corrupt/garbage line is a verification FAILURE, never a crash — otherwise
      // appending junk to board.jsonl would evade `verify` (which must exit non-zero).
      let msg: BoardMessage | null = null
      try {
        const parsed = JSON.parse(text)
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) msg = parsed as BoardMessage
      } catch {
        msg = null
      }
      if (!msg) {
        const synthetic: BoardMessage = {
          seq: expectedSeq, ts: "", author: "?", body: `<unparseable line ${lineNo}>`, prev: "", pubkey: "", sig: "",
        }
        results.push({ msg: synthetic, ok: false, reason: "unparseable entry (corrupt or tampered)" })
        expectedPrev = `__corrupt_line_${lineNo}__` // guarantee the next entry chain-breaks
        expectedSeq = expectedSeq + 1
        continue
      }
      const reasons: string[] = []
      if (msg.prev !== expectedPrev) reasons.push("chain break (prev mismatch)")
      if (msg.seq !== expectedSeq) reasons.push(`seq gap (got ${msg.seq}, expected ${expectedSeq})`)
      const data = canonical(msg.seq, msg.ts ?? "", msg.author ?? "", msg.body ?? "", msg.prev ?? "", msg.pubkey ?? "")
      if (!verifySig(msg.pubkey ?? "", msg.sig ?? "", data)) reasons.push("bad signature")
      const reg = this.registeredPub(msg.author ?? "")
      if (reg !== null && reg !== msg.pubkey) reasons.push("pubkey != registered identity (forged author?)")
      const ok = reasons.length === 0
      results.push({ msg, ok, reason: ok ? "ok" : reasons.join("; ") })
      expectedPrev = entryHash(msg)
      expectedSeq = msg.seq + 1
    }
    return results
  }
}

// --------------------------------------------------------------- project registry
export function registryPath(): string {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config")
  return path.join(base, "openhack-board", "projects.json")
}
export function rememberProject(root: string): void {
  const p = registryPath()
  fs.mkdirSync(path.dirname(p), { recursive: true })
  let recent: string[] = []
  try {
    recent = JSON.parse(fs.readFileSync(p, "utf8"))
  } catch {
    recent = []
  }
  const s = path.resolve(root)
  recent = [s, ...recent.filter((r) => r !== s)].slice(0, 50)
  fs.writeFileSync(p, JSON.stringify(recent, null, 2))
}
