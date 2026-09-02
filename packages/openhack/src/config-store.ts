import * as fs from "node:fs"
import * as path from "node:path"

/**
 * Read/write dotted keys in `.openhack/openhack.jsonc` so every OpenHack setting is
 * controllable from the shell (`openhack config get|set|list`). Writes strip JSONC
 * comments and re-emit pretty JSON (a programmatic edit of an operational config —
 * the curated repo catalog is edited by hand).
 */
export namespace ConfigStore {
  const FILE = path.join(".openhack", "openhack.jsonc")
  /** Small mtime-keyed cache: every OpenHack plugin hook calls ConfigStore.get(...)
   *  on the hot path, and re-reading + JSON.parse of openhack.jsonc for every tool
   *  call adds up fast. Cache entry is invalidated by any change in the file's
   *  mtime, by explicit `save`, or after CACHE_TTL_MS at most (defense in depth). */
  const CACHE_TTL_MS = 2_000
  const cache = new Map<string, { at: number; mtimeMs: number; cfg: Record<string, any> }>()

  function stripJsonc(s: string): string {
    return s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1")
  }

  function currentMtimeMs(file: string): number {
    try { return fs.statSync(file).mtimeMs } catch { return 0 }
  }

  export function load(file = FILE): Record<string, any> {
    const now = Date.now()
    const entry = cache.get(file)
    const mtime = currentMtimeMs(file)
    if (entry && now - entry.at < CACHE_TTL_MS && entry.mtimeMs === mtime) return entry.cfg
    let cfg: Record<string, any> = {}
    try {
      cfg = JSON.parse(stripJsonc(fs.readFileSync(file, "utf8"))) ?? {}
    } catch {}
    cache.set(file, { at: now, mtimeMs: mtime, cfg })
    return cfg
  }

  export function save(obj: Record<string, any>, file = FILE): void {
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n", "utf8")
    // Bust cache: next load() re-reads and refreshes mtime.
    cache.delete(file)
  }

  /** Test-only: force the next load() to hit disk. Also invoked implicitly by save(). */
  export function invalidateCache(file = FILE): void {
    cache.delete(file)
  }

  /** Look up a dotted key ("council.instances"); returns undefined if any segment is missing. */
  export function get(key: string, cfg = load()): any {
    let node: any = cfg
    for (const seg of key.split(".")) {
      if (node == null || typeof node !== "object") return undefined
      node = node[seg]
    }
    return node
  }

  /**
   * Look up a dotted key that is expected to hold a config BLOCK (object) and
   * return it as a field-guarded record — the type-safe way to read engine
   * namespaces (`dcr`, `lattice`, `temporal`, …) without unchecked casts.
   */
  export function getObject(key: string, cfg = load()): Record<string, unknown> | undefined {
    const value = get(key, cfg)
    if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined
    const record: Record<string, unknown> = value
    return record
  }

  /**
   * Coerce a shell-supplied string value: JSON where it parses (numbers, booleans,
   * null, arrays, objects), otherwise the raw string. So `set x.y 3` stores 3 (number)
   * and `set x.z true` stores true (boolean).
   */
  export function coerce(value: string): any {
    try {
      return JSON.parse(value)
    } catch {
      return value
    }
  }

  /** Set a dotted key, creating intermediate objects, and persist. Returns the new value. */
  export function set(key: string, value: any, file = FILE): any {
    const cfg = load(file)
    const segs = key.split(".")
    let node: any = cfg
    for (let i = 0; i < segs.length - 1; i++) {
      const seg = segs[i]
      if (node[seg] == null || typeof node[seg] !== "object" || Array.isArray(node[seg])) node[seg] = {}
      node = node[seg]
    }
    node[segs[segs.length - 1]] = value
    save(cfg, file)
    return value
  }

  /** Flatten the config to `dotted.key = <json>` lines for `openhack config list`. */
  export function flatten(cfg = load(), prefix = ""): Array<{ key: string; value: any }> {
    const out: Array<{ key: string; value: any }> = []
    for (const [k, v] of Object.entries(cfg)) {
      const key = prefix ? `${prefix}.${k}` : k
      if (v && typeof v === "object" && !Array.isArray(v)) out.push(...flatten(v as any, key))
      else out.push({ key, value: v })
    }
    return out
  }
}
