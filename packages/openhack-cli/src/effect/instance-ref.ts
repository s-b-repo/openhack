import { Context } from "effect"
import type { InstanceContext } from "@/project/instance-context"
import type { WorkspaceV2 } from "@openhack-ai/core/workspace"

export const InstanceRef = Context.Reference<InstanceContext | undefined>("~openhack/InstanceRef", {
  defaultValue: () => undefined,
})

export const WorkspaceRef = Context.Reference<WorkspaceV2.ID | undefined>("~openhack/WorkspaceRef", {
  defaultValue: () => undefined,
})
