import { loadJSON, saveJSON } from "./persist"

/**
 * Prompt-variant registry + chosen-variant store.
 *
 * A "prompt variant" is an alternative framing appended to a role's worker prompt
 * (e.g. an exhaustive-enumeration lens for recon, a chain-forward lens for exploit).
 * The o5 / Overwatch benchmark council measures `(role × model × variant)` and
 * promotes the best variant per role by writing `.openhack/agent-variants.json`; the
 * loop injects the chosen variant's fragment at dispatch (same seam as the loop's
 * `INSTANCE_LENSES`), so the choice flows to the worker subprocess with no agent
 * `.md` edits and no subprocess changes.
 *
 * NOTE: this is distinct from `ConfigAgentV1.variant`, which is a *model/provider*
 * variant (thinking-mode etc.). Prompt-variants deliberately get their own mechanism
 * rather than overloading that field or rewriting immutable agent files at runtime.
 */
export namespace Variants {
  export interface Variant {
    role: string
    id: string
    label: string
    /** Appended verbatim to the worker prompt. Empty string for the "default" variant. */
    promptFragment: string
  }

  /**
   * Built-in seed set. Every role has a "default" (empty fragment) so a role with no
   * declared alternatives still resolves cleanly. Add new variants here (or, later, a
   * `.openhack/agents/variants/*.md` loader) and reference their ids in
   * `o5.candidates[role].variants`.
   */
  export const REGISTRY: Variant[] = [
    // recon
    { role: "recon", id: "default", label: "Default", promptFragment: "" },
    { role: "recon", id: "exhaustive", label: "Exhaustive enumeration",
      promptFragment: "\n\n[Variant: enumerate exhaustively — every vhost, method, parameter, and technology; prefer breadth of surface over early depth.]" },
    // exploit
    { role: "exploit", id: "default", label: "Default", promptFragment: "" },
    { role: "exploit", id: "chain-forward", label: "Chain-forward",
      promptFragment: "\n\n[Variant: for every primitive you gain, immediately ask what it chains into (entry → access → escalation → impact) and pursue the chain, not just the single bug.]" },
    // post-exploit
    { role: "post-exploit", id: "default", label: "Default", promptFragment: "" },
    { role: "post-exploit", id: "least-impact", label: "Least-impact proof",
      promptFragment: "\n\n[Variant: demonstrate each path with the smallest reversible proof; prioritize evidence quality over expanding blast radius.]" },
    // general
    { role: "general", id: "default", label: "Default", promptFragment: "" },
    { role: "general", id: "gap-hunter", label: "Gap hunter",
      promptFragment: "\n\n[Variant: focus on what was MISSED — untested cells, unasked questions, second-order effects — and turn each gap into a concrete next objective.]" },
    // osint
    { role: "osint", id: "default", label: "Default", promptFragment: "" },
    // defense
    { role: "defense", id: "default", label: "Default", promptFragment: "" },
    // c2
    { role: "c2", id: "default", label: "Default", promptFragment: "" },
  ]

  const STORE_FILE = ".openhack/agent-variants.json"
  interface ChosenStore { chosen: Record<string, string> }

  export function forRole(role: string): Variant[] {
    return REGISTRY.filter((v) => v.role === role)
  }

  export function get(role: string, id: string): Variant | undefined {
    return REGISTRY.find((v) => v.role === role && v.id === id)
  }

  /** Ids available for a role (always includes "default"). */
  export function ids(role: string): string[] {
    const found = forRole(role).map((v) => v.id)
    return found.length ? found : ["default"]
  }

  /** The chosen variant id for a role — reads the store, falls back to "default". */
  export function chosenFor(role: string): string {
    const store = loadJSON<ChosenStore>(STORE_FILE, { chosen: {} })
    return store.chosen?.[role] ?? "default"
  }

  /** Promote a variant for a role (o5/Overwatch enforcement). Persists to disk. */
  export function setChosen(role: string, id: string): void {
    const store = loadJSON<ChosenStore>(STORE_FILE, { chosen: {} })
    store.chosen = store.chosen ?? {}
    store.chosen[role] = id
    saveJSON(STORE_FILE, store)
  }

  /** The prompt fragment for a role's chosen variant ("" when default / unknown). */
  export function fragmentFor(role: string): string {
    return fragmentForId(role, chosenFor(role))
  }

  /** The prompt fragment for a specific role+variant id ("" when default / unknown). */
  export function fragmentForId(role: string, id: string): string {
    return get(role, id)?.promptFragment ?? ""
  }
}
