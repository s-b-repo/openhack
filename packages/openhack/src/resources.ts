import * as fs from "fs"
import * as path from "path"

export namespace ResourceManager {
  interface Resource {
    id: string
    type: "port" | "file" | "target" | "tunnel" | "process" | "host"
    value: string
    owner: string
    sessionId: string
    agent: string
    expires: number
    createdAt: string
  }

  interface ResourceStore {
    resources: Resource[]
    lastCleanup: string
  }

  const STORE_PATH = ".openhack/resources.json"
  const DEFAULT_TTL_MS = 300000 // 5 minutes

  function load(): ResourceStore {
    if (fs.existsSync(STORE_PATH)) {
      try {
        return JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"))
      } catch {}
    }
    return { resources: [], lastCleanup: new Date().toISOString() }
  }

  function save(store: ResourceStore): void {
    const dir = path.dirname(STORE_PATH)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2))
  }

  function cleanup(store: ResourceStore): ResourceStore {
    const now = Date.now()
    store.resources = store.resources.filter((r) => r.expires > now)
    store.lastCleanup = new Date().toISOString()
    return store
  }

  export function acquire(
    type: Resource["type"],
    value: string,
    owner: string,
    sessionId: string,
    agent: string,
    ttlMs: number = DEFAULT_TTL_MS,
  ): { success: boolean; id?: string; conflict?: Resource; reason?: string } {
    let store = load()
    store = cleanup(store)

    const existing = store.resources.find((r) => r.type === type && r.value === value)
    if (existing) {
      return { success: false, conflict: existing, reason: `Resource ${type}:${value} already held by ${existing.agent}` }
    }

    const resource: Resource = {
      id: `res-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
      type,
      value,
      owner,
      sessionId,
      agent,
      expires: Date.now() + ttlMs,
      createdAt: new Date().toISOString(),
    }

    store.resources.push(resource)
    save(store)

    return { success: true, id: resource.id }
  }

  export function release(id: string): boolean {
    let store = load()
    const idx = store.resources.findIndex((r) => r.id === id)
    if (idx === -1) return false
    store.resources.splice(idx, 1)
    save(store)
    return true
  }

  export function releaseAll(owner: string): number {
    let store = load()
    const before = store.resources.length
    store.resources = store.resources.filter((r) => r.owner !== owner)
    const after = store.resources.length
    save(store)
    return before - after
  }

  export function releaseAllForSession(sessionId: string): number {
    let store = load()
    const before = store.resources.length
    store.resources = store.resources.filter((r) => r.sessionId !== sessionId)
    const after = store.resources.length
    save(store)
    return before - after
  }

  export function list(owner?: string): Resource[] {
    let store = load()
    store = cleanup(store)
    if (owner) {
      return store.resources.filter((r) => r.owner === owner)
    }
    return store.resources
  }

  export function isAvailable(type: Resource["type"], value: string): boolean {
    let store = load()
    store = cleanup(store)
    return !store.resources.some((r) => r.type === type && r.value === value)
  }

  export function findConflicting(agent: string): Resource[] {
    let store = load()
    store = cleanup(store)
    return store.resources.filter((r) => r.agent !== agent)
  }

  export function extendLock(id: string, additionalMs: number): boolean {
    let store = load()
    const resource = store.resources.find((r) => r.id === id)
    if (!resource) return false
    resource.expires = Math.max(resource.expires, Date.now() + additionalMs)
    save(store)
    return true
  }

  export function getOrphanCount(): number {
    let store = load()
    const now = Date.now()
    return store.resources.filter((r) => r.expires <= now).length
  }

  export function forceCleanup(): Resource[] {
    let store = load()
    const orphans = store.resources.filter((r) => r.expires <= Date.now())
    store = cleanup(store)
    save(store)
    return orphans
  }

  function ipInCIDR(ip: string, cidr: string): boolean {
    try {
      const [range, bitsStr] = cidr.split("/")
      const bits = Math.min(32, Math.max(0, parseInt(bitsStr)))
      if (!bits && bits !== 0) return false
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
      const ipNum = ip.split(".").reduce((acc, oct) => ((acc << 8) >>> 0) + parseInt(oct), 0) >>> 0
      const rangeNum = range.split(".").reduce((acc, oct) => ((acc << 8) >>> 0) + parseInt(oct), 0) >>> 0
      return (ipNum & mask) >>> 0 === (rangeNum & mask) >>> 0
    } catch {
      return false
    }
  }

  export function reservePort(port: number, owner: string, sessionId: string, agent: string): { success: boolean; id?: string; conflict?: Resource } {
    return acquire("port", String(port), owner, sessionId, agent, DEFAULT_TTL_MS)
  }

  export function reserveTarget(target: string, owner: string, sessionId: string, agent: string): { success: boolean; id?: string; conflict?: Resource } {
    return acquire("target", target, owner, sessionId, agent, DEFAULT_TTL_MS)
  }

  export function isTargetBeingScanned(target: string): boolean {
    return !isAvailable("target", target)
  }
}
