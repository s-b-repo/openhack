/**
 * Module augmentation for `AI_SDK_LOG_WARNINGS` — a global flag the Vercel
 * AI SDK (Vercel) reads at import time to decide whether to emit a noisy
 * deprecation warning banner. The openhack CLI silences it during boot to
 * keep the TUI clean.
 *
 * Without this augmentation, both `server.ts` and `session/prompt.ts` need a
 * `// @ts-ignore` because `globalThis.AI_SDK_LOG_WARNINGS` is not in the
 * standard `globalThis` type. With the augmentation, the assignment is typed
 * and the type system is informed of the flag's semantics.
 */
declare global {
  /**
   * `true` enables the AI SDK's one-shot deprecation/usage warnings at import
   * time; `false` silences them. Read by the AI SDK at module load — must
   * be set BEFORE any `@ai-sdk/*` import for the toggle to take effect.
   */
  // eslint-disable-next-line no-var
  var AI_SDK_LOG_WARNINGS: boolean | undefined
}

export {}
