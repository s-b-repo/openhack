import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"

export namespace Secrets {
  interface SecretsStore {
    entries: Record<string, SecretEntry>
    salt: string
  }

  interface SecretEntry {
    id: string
    name: string
    value: string           // encrypted
    source: string          // how it was resolved
    created: string
    accessed: string
    accessed_by: string[]
  }

  const STORE_DIR = ".openhack/secrets"
  const STORE_FILE = "vault.age"

  let activeStore: SecretsStore | null = null
  let sessionKey: Buffer | null = null

  export function init(key?: string): boolean {
    if (!fs.existsSync(STORE_DIR)) {
      fs.mkdirSync(STORE_DIR, { recursive: true, mode: 0o700 })
    }

    if (!sessionKey) {
      const keyPath = path.join(STORE_DIR, ".key")
      if (fs.existsSync(keyPath)) {
        sessionKey = Buffer.from(fs.readFileSync(keyPath, "utf-8").trim(), "hex")
      } else if (key) {
        sessionKey = Buffer.from(key, "utf8")
        fs.writeFileSync(keyPath, sessionKey.toString("hex"), { mode: 0o600 })
      } else {
        sessionKey = crypto.randomBytes(32)
        fs.writeFileSync(keyPath, sessionKey.toString("hex"), { mode: 0o600 })
      }
    }

    const storePath = path.join(STORE_DIR, STORE_FILE)
    if (fs.existsSync(storePath) && sessionKey) {
      try {
        const encrypted = fs.readFileSync(storePath, "utf-8")
        activeStore = JSON.parse(decrypt(encrypted, sessionKey))
        return true
      } catch {
        activeStore = { entries: {}, salt: Buffer.from(Date.now().toString()).toString("base64") }
      }
    } else {
      activeStore = { entries: {}, salt: Buffer.from(Date.now().toString()).toString("base64") }
    }

    return !!activeStore
  }

  function persist(): void {
    if (!activeStore || !sessionKey) return
    const storePath = path.join(STORE_DIR, STORE_FILE)
    const data = JSON.stringify(activeStore)
    const encrypted = encrypt(data, sessionKey)
    fs.writeFileSync(storePath, encrypted, { encoding: "utf-8", mode: 0o600 })
  }

  // Authenticated encryption (AES-256-GCM) for the vault. The 32-byte content
  // key is derived from the session key so a passphrase of any length works, and
  // the auth tag makes tampering detectable. Format: base64(iv[12] | tag[16] | ct).
  function encrypt(data: string, key: Buffer): string {
    const ekey = crypto.createHash("sha256").update(key).digest()
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv("aes-256-gcm", ekey, iv)
    const ct = Buffer.concat([cipher.update(data, "utf8"), cipher.final()])
    const tag = cipher.getAuthTag()
    return Buffer.concat([iv, tag, ct]).toString("base64")
  }

  function decrypt(blob: string, key: Buffer): string {
    const ekey = crypto.createHash("sha256").update(key).digest()
    const raw = Buffer.from(blob, "base64")
    const iv = raw.subarray(0, 12)
    const tag = raw.subarray(12, 28)
    const ct = raw.subarray(28)
    const decipher = crypto.createDecipheriv("aes-256-gcm", ekey, iv)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8")
  }

  export function resolve(value: string): string {
    if (value.startsWith("{env:") && value.endsWith("}")) {
      const varName = value.slice(5, -1)
      return process.env[varName] || value
    }

    if (value.startsWith("{pass:") && value.endsWith("}")) {
      return value
    }

    if (value.startsWith("{keyring:") && value.endsWith("}")) {
      return value
    }

    if (value.startsWith("{op://")) {
      return value
    }

    if (value.startsWith("{vault:") && value.endsWith("}")) {
      return value
    }

    if (value.startsWith("{aws:") && value.endsWith("}")) {
      return value
    }

    return value
  }

  export function store(name: string, value: string, source: string): string {
    if (!activeStore) init()
    const id = `sec-${Date.now().toString(36)}`

    activeStore!.entries[id] = {
      id,
      name,
      value,
      source,
      created: new Date().toISOString(),
      accessed: new Date().toISOString(),
      accessed_by: [],
    }

    persist()
    return id
  }

  export function get(id: string, agent: string): string | null {
    if (!activeStore) init()

    const entry = activeStore!.entries[id]
    if (!entry) return null

    entry.accessed = new Date().toISOString()
    if (!entry.accessed_by.includes(agent)) {
      entry.accessed_by.push(agent)
    }

    persist()
    return entry.value
  }

  export function remove(id: string): boolean {
    if (!activeStore) return false
    if (!activeStore.entries[id]) return false
    delete activeStore.entries[id]
    persist()
    return true
  }

  export function purge(): void {
    activeStore = { entries: {}, salt: Buffer.from(Date.now().toString()).toString("base64") }
    persist()
  }

  export function list(): Array<{ id: string; name: string; source: string; created: string }> {
    if (!activeStore) init()
    return Object.values(activeStore!.entries).map((e) => ({
      id: e.id,
      name: e.name,
      source: e.source,
      created: e.created,
    }))
  }

  export function sanitizeOutput(text: string): string {
    let result = text

    result = result.replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/g, "Bearer [REDACTED]")
    result = result.replace(/Authorization:\s*[^\n]+/gi, "Authorization: [REDACTED]")
    result = result.replace(/password[=:]\s*\S+/gi, "password=[REDACTED]")
    result = result.replace(/passwd[=:]\s*\S+/gi, "passwd=[REDACTED]")
    result = result.replace(/--pass\s+\S+/g, "--pass [REDACTED]")
    result = result.replace(/api[_-]?key[=:]\s*\S+/gi, "api_key=[REDACTED]")
    result = result.replace(/token[=:]\s*\S+/gi, "token=[REDACTED]")
    result = result.replace(/secret[=:]\s*\S+/gi, "secret=[REDACTED]")

    result = result.replace(
      /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----[^]*?-----END (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/g,
      "[SSH PRIVATE KEY REDACTED]",
    )

    return result
  }
}
