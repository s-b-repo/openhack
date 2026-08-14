import { run as runTui, type TuiInput } from "@openhack-ai/tui"
import { Global } from "@openhack-ai/core/global"
import { AppNodeBuilder } from "@openhack-ai/core/effect/app-node-builder"
import { Effect } from "effect"

export function run(input: TuiInput) {
  return runTui(input).pipe(Effect.provide(AppNodeBuilder.build(Global.node)))
}
