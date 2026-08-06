import { loadJSON, saveJSON } from "./persist"

export namespace GlobalConfig {
  export type Tier = "main" | "fast" | "cheap" | "draft"

  export interface ModelConfig {
    main: string
    fast: string
    cheap: string
    draft: string
    custom?: string
    /**
     * Per-agent tier override — set from `.openhack/models.json` or CLI.
     * Example: `{ "recon": "cheap", "council": "fast" }`. Unknown agents fall
     * back to the DEFAULT_AGENT_TIERS table below, then to `main`.
     */
    agent_tiers?: Partial<Record<string, Tier>>
  }

  const DEFAULT: ModelConfig = {
    main: process.env.OPENHACK_MODEL || "anthropic/claude-sonnet-4",
    fast: process.env.OPENHACK_FAST_MODEL || "anthropic/claude-haiku-4-5",
    cheap: process.env.OPENHACK_CHEAP_MODEL || "deepseek/deepseek-v4",
    draft: process.env.OPENHACK_DRAFT_MODEL || "deepseek/deepseek-v4",
  }

  /**
   * Doctrine-derived default tier per agent role. Matches MoE's `CHEAP_EXPERTS`
   * intuition (recon-adjacent work goes cheap) and extends it to every specialist:
   *   • recon / osint            → cheap  (broad enumeration; high token volume, low reasoning depth)
   *   • defense / council / triage / general → fast (short structured judgment)
   *   • exploit / post-exploit / c2 / report / plan / planner → main (deep reasoning, chained tool use)
   *   • cleanup                  → draft  (fixed decommission script; token cost irrelevant)
   */
  const DEFAULT_AGENT_TIERS: Record<string, Tier> = {
    recon: "cheap",
    osint: "cheap",
    exploit: "main",
    "post-exploit": "main",
    c2: "main",
    report: "main",
    plan: "main",
    planner: "main",
    defense: "fast",
    "defense-review": "fast",
    council: "fast",
    triage: "fast",
    general: "fast",
    cleanup: "draft",
  }

  // Persisted so `/model set` from the one-shot CLI is visible to the long-running
  // server process (and vice-versa) instead of resetting every invocation.
  const CONFIG_FILE = ".openhack/models.json"
  let activeConfig: ModelConfig = { ...DEFAULT, ...loadJSON<Partial<ModelConfig>>(CONFIG_FILE, {}) }

  function persist(): void { saveJSON(CONFIG_FILE, activeConfig) }

  export function get(): ModelConfig { return { ...activeConfig } }

  export function set(cfg: Partial<ModelConfig>): void {
    activeConfig = { ...activeConfig, ...cfg }
    persist()
  }

  export function main(): string { return activeConfig.custom || activeConfig.main }
  export function fast(): string { return activeConfig.custom || activeConfig.fast }
  export function cheap(): string { return activeConfig.custom || activeConfig.cheap }
  export function draft(): string { return activeConfig.custom || activeConfig.draft }

  /**
   * Resolve the model id an agent should use — tier-aware.
   *   1. `activeConfig.custom` (from `openhack model --set X`) always wins.
   *   2. `activeConfig.agent_tiers[agent]` explicit override.
   *   3. `DEFAULT_AGENT_TIERS[agent]` doctrine default.
   *   4. `"main"` fallback for unknown agents.
   * Returns the model id string (e.g. "deepseek/deepseek-v4"), never a tier.
   */
  export function resolveForAgent(agent: string | undefined | null): string {
    if (activeConfig.custom) return activeConfig.custom
    const explicit = agent && activeConfig.agent_tiers?.[agent]
    const tier: Tier = explicit ?? DEFAULT_AGENT_TIERS[agent ?? ""] ?? "main"
    return tierModel(tier)
  }

  /** Model id for a bare tier — used by tests + resolveForAgent. */
  export function tierModel(tier: Tier): string {
    switch (tier) {
      case "cheap": return activeConfig.cheap
      case "fast":  return activeConfig.fast
      case "draft": return activeConfig.draft
      case "main":  return activeConfig.main
    }
  }

  export function useCustomModel(model: string): void {
    activeConfig.custom = model
    persist()
  }

  export function clearCustom(): void {
    activeConfig.custom = undefined
    persist()
  }

  export function reset(): void {
    activeConfig = { ...DEFAULT }
    persist()
  }

  export function getStatus(): string {
    const custom = activeConfig.custom ? `CUSTOM: ${activeConfig.custom}` : "DEFAULTS"
    return `Models: ${custom}\n  Main:  ${main()}\n  Fast:  ${fast()}\n  Cheap: ${cheap()}\n  Draft: ${draft()}`
  }
}
