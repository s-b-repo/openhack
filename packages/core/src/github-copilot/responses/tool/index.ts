/**
 * Barrel for the GitHub Copilot / OpenAI Responses provider tool factories.
 *
 * Every export in this file is consumed by `openai-responses-language-model.ts`
 * (either via the request builder, the call-item parser, or the tool-detection
 * `hasOpenAITool(...)` path). Re-exports live here so downstream code can
 * `import { imageGeneration, localShell, webSearchPreview } from
 * "@openhack-ai/core/github-copilot/responses/tool"` to build a custom Copilot
 * request without re-implementing the tool-creation wiring.
 */
export { codeInterpreterToolFactory } from "./code-interpreter"
export { fileSearch } from "./file-search"
export { imageGeneration } from "./image-generation"
export { localShell } from "./local-shell"
export { webSearch } from "./web-search"
export { webSearchPreview } from "./web-search-preview"
// Arg/output schemas are the AI-SDK model-facing surfaces (schema is
// distinct from the factory and is what the request builder reads).
export { codeInterpreterInputSchema, codeInterpreterOutputSchema } from "./code-interpreter"
export { fileSearchArgsSchema, fileSearchOutputSchema } from "./file-search"
export { imageGenerationArgsSchema, imageGenerationOutputSchema } from "./image-generation"
export { localShellInputSchema, localShellOutputSchema } from "./local-shell"
export { webSearchArgsSchema } from "./web-search"
export { webSearchPreviewArgsSchema } from "./web-search-preview"
