export * as ConfigDcr from "./dcr"

import { Schema } from "effect"
import { NonNegativeInt } from "../schema"

/**
 * Dynamic Context Runtime (DCR) session context.
 *
 * When enabled, session history is ingested into a dcr-serve sidecar and each
 * model turn receives a budgeted working set assembled by the runtime instead
 * of the full transcript. Compaction remains as overflow fallback.
 */
export class Info extends Schema.Class<Info>("ConfigV2.Dcr")({
  enabled: Schema.Boolean.pipe(Schema.optional),
  bin: Schema.String.pipe(Schema.optional),
  budget: NonNegativeInt.pipe(Schema.optional),
  recentTokens: NonNegativeInt.pipe(Schema.optional),
}) {}
