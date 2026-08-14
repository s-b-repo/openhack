/**
 * One shared model rate table. Previously two different hardcoded tables
 * (`Automode.estimateCost` and `MOERouter.getCostEstimate`) disagreed on the
 * same models and fell back to different magic numbers. These estimates are
 * rough on purpose — real spend is scraped from the `run` transcript — they only
 * drive the pre-flight `confirm_if_above` gate and the MoE cost hint, so having
 * one consistent source is what matters.
 */
export namespace ModelCosts {
  // Blended USD per 1K tokens, matched by longest prefix first (so
  // "anthropic/claude-sonnet-4-5-2025…" resolves to the sonnet rate). Keep
  // specific ids ahead of their family's catch-all.
  const RATES: Array<[string, number]> = [
    ["deepseek/deepseek-v4", 0.0003],
    ["deepseek/deepseek-chat", 0.0003],
    ["deepseek/", 0.0003],
    ["anthropic/claude-haiku", 0.001],
    ["anthropic/claude-sonnet", 0.009],
    ["anthropic/claude-opus", 0.03],
    ["anthropic/", 0.009],
    ["openai/gpt-4o-mini", 0.0004],
    ["openai/gpt-4o", 0.0075],
    ["openai/o3", 0.02],
    ["openai/", 0.006],
    ["google/gemini-2.5-flash", 0.0004],
    ["google/gemini-2.5-pro", 0.005],
    ["google/gemini", 0.001],
    ["google/", 0.002],
  ]
  const DEFAULT_RATE = 0.005

  /** Blended USD per 1K tokens for a `provider/model` id. */
  export function ratePer1KUsd(model: string): number {
    const m = (model || "").toLowerCase()
    for (const [prefix, rate] of RATES) if (m.startsWith(prefix)) return rate
    return DEFAULT_RATE
  }

  /** Whether a model is in the "cheap" band (≤ $0.001 / 1K). */
  export function isCheap(model: string): boolean {
    return ratePer1KUsd(model) <= 0.001
  }

  /** Estimate a call's USD cost from prompt length + an assumed output size. */
  export function estimateUsd(model: string, promptChars: number, avgOutputTokens = 2000): number {
    const promptTokens = promptChars / 4
    return ((promptTokens + avgOutputTokens) / 1000) * ratePer1KUsd(model)
  }
}
