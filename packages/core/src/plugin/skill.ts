/// <reference path="../markdown.d.ts" />

export * as SkillPlugin from "./skill"

import { define } from "./internal"
import { Effect } from "effect"
import { AbsolutePath } from "../schema"
import { SkillV2 } from "../skill"
import customizeOpenhackContent from "./skill/customize-openhack.md" with { type: "text" }

export const CustomizeOpenhackContent = customizeOpenhackContent

export const Plugin = define({
  id: "skill",
  effect: Effect.fn(function* (ctx) {
    yield* ctx.skill.transform((draft) => {
      draft.source(
        SkillV2.EmbeddedSource.make({
          type: "embedded",
          skill: SkillV2.Info.make({
            name: "customize-openhack",
            description:
              "Use ONLY when the user is editing or creating openhack's own configuration: openhack.json, openhack.jsonc, files under .openhack/, or files under ~/.config/openhack/. Also use when creating or fixing openhack agents, subagents, commands, skills, plugins, MCP servers, or permission rules. Do not use for the user's own application code, or for any project that is not configuring openhack itself.",
            location: AbsolutePath.make("/builtin/customize-openhack.md"),
            content: CustomizeOpenhackContent,
          }),
        }),
      )
    })
  }),
})
