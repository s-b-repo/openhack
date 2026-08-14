import { $ } from "bun"

await $`bun ./scripts/copy-icons.ts ${process.env.OPENHACK_CHANNEL ?? "dev"}`

await $`cd ../openhack-cli && bun script/build-node.ts`
