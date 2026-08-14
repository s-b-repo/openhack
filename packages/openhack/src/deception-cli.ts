#!/usr/bin/env bun
/**
 * Deception CLI — plant / clear / inspect the "watched range" (see deception.ts).
 *
 *   bun run src/deception-cli.ts plant     # write decoys + spawn watcher procs
 *   bun run src/deception-cli.ts status    # show config + whether it's planted
 *   bun run src/deception-cli.ts env       # print the sourceable env overlay
 *   bun run src/deception-cli.ts clear     # remove the planted range
 *
 * Reads config from `.openhack/openhack.jsonc` (`deception` block). `plant` runs
 * regardless of `deception.enabled` so an operator can stage a honeypot on demand;
 * automatic activation on session start is gated on `enabled` by the caller.
 */
import { Deception } from "./deception"
import { DeceptionPlanter } from "./deception-planter"

function main(argv: string[]): number {
  const cmd = argv[2] ?? "status"
  const c = Deception.config()

  switch (cmd) {
    case "plant": {
      const { root, files } = DeceptionPlanter.plant(c)
      const watchers = DeceptionPlanter.spawnWatchers(c)
      process.stdout.write(
        `${Deception.banner(c)}\n` +
          `planted ${files.length} decoys under ${root}\n` +
          `spawned ${watchers.length} watcher processes\n` +
          `source ${root}/env.sh to enter the range\n`,
      )
      // Detach the watcher children; they are re-titled sleeps that self-expire.
      watchers.forEach((w) => w.unref?.())
      return 0
    }
    case "clear": {
      DeceptionPlanter.clear(c)
      process.stdout.write(`cleared deception range at ${c.root}\n`)
      return 0
    }
    case "env": {
      const env = Deception.envOverlay(c)
      process.stdout.write(Object.entries(env).map(([k, v]) => `export ${k}=${JSON.stringify(v)}`).join("\n") + "\n")
      return 0
    }
    case "status": {
      process.stdout.write(
        `deception: ${c.enabled ? "enabled" : "disabled"} (mode=${c.mode})\n` +
          `root: ${c.root}\n` +
          `planted: ${DeceptionPlanter.isPlanted(c)}\n` +
          `session: ${Deception.sessionId(c)}\n` +
          `tools: ${Deception.TOOLS.map((t) => t.id).join(", ")}\n`,
      )
      return 0
    }
    default:
      process.stderr.write(`usage: deception-cli <plant|clear|env|status>\n`)
      return 2
  }
}

process.exit(main(process.argv))
