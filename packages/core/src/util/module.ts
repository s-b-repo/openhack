import { createRequire } from "node:module"
import path from "node:path"

export namespace Module {
  export function resolve(id: string, dir: string) {
    try {
      return createRequire(path.join(dir, "package.json")).resolve(id)
    } catch {
      // Unresolvable module id → return undefined (callers treat it as "not found").
      return undefined
    }
  }
}
