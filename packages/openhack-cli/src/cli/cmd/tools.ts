import type { Argv, CommandModule } from "yargs"
import { spawnSync } from "node:child_process"
import * as fs from "node:fs"
import {
  TOOLS, getTool, toolDir, toolStatus, buildArgv, runArgv, updateArgv, defaultBase, groups, hasSystemdRun,
} from "@openhack-ai/tools"

const GREEN = "\x1b[32m", YELLOW = "\x1b[33m", RED = "\x1b[31m", DIM = "\x1b[2m", RESET = "\x1b[0m", BOLD = "\x1b[1m", CYAN = "\x1b[36m"

function base(argv: { base?: string }): string {
  return argv.base || process.env.OPENHACK_TOOLS_BASE || defaultBase()
}

function stateColor(state: string): string {
  return state === "ok" ? GREEN : state === "warn" ? YELLOW : state === "missing" ? RED : DIM
}

function printList(b: string): void {
  console.log(`${DIM}base: ${b}  ·  memory caps: ${hasSystemdRun() ? "on" : "OFF"}${RESET}\n`)
  for (const g of groups()) {
    console.log(`${CYAN}// ${g}${RESET}`)
    for (const t of TOOLS.filter((x) => x.group === g)) {
      const s = toolStatus(b, t)
      console.log(
        `  ${BOLD}${t.name.padEnd(26)}${RESET} ${DIM}${t.lang.padEnd(11)}${RESET} ` +
          `${stateColor(s.state)}${s.text.padEnd(16)}${RESET} ${DIM}${t.desc}${RESET}`,
      )
    }
  }
}

function runArgvInherit(argv: string[] | null, what: string): void {
  if (!argv) {
    console.error(`${RED}nothing to ${what} for this tool${RESET}`)
    process.exitCode = 1
    return
  }
  const r = spawnSync(argv[0], argv.slice(1), { stdio: "inherit" })
  if (r.status && r.status !== 0) process.exitCode = r.status
}

export const ToolsCommand: CommandModule = {
  command: "tools",
  describe: "build, run, update and inspect the open-source security tools",
  builder: (y: Argv) =>
    y
      .option("base", { type: "string", describe: "tools base directory (default ~/Projects/store-tools)" })
      .command(["list", "status"], "list tools and their build status", {}, (argv) => printList(base(argv)))
      .command(
        "build <name>",
        "build a tool (under a soft memory cap)",
        (yy: Argv) => yy.positional("name", { type: "string" }),
        (argv) => {
          if (!argv.name) return notFound(argv.name)
          const t = getTool(argv.name)
          if (!t) return notFound(argv.name)
          console.log(`${CYAN}building ${t.name}…${RESET}`)
          runArgvInherit(buildArgv(base(argv), t), "build")
        },
      )
      .command(
        "run <name>",
        "run a tool in this terminal (OpenHack runs under a hard memory cap)",
        (yy: Argv) => yy.positional("name", { type: "string" }),
        (argv) => {
          if (!argv.name) return notFound(argv.name)
          const t = getTool(argv.name)
          if (!t) return notFound(argv.name)
          const d = toolDir(base(argv), t)
          if (!fs.existsSync(d)) {
            console.error(`${RED}${t.name} is not cloned at ${d}${RESET}`)
            process.exitCode = 1
            return
          }
          runArgvInherit(runArgv(base(argv), t), "run")
        },
      )
      .command(
        "update <name>",
        "git pull a tool",
        (yy: Argv) => yy.positional("name", { type: "string" }),
        (argv) => {
          if (!argv.name) return notFound(argv.name)
          const t = getTool(argv.name)
          if (!t) return notFound(argv.name)
          runArgvInherit(updateArgv(base(argv), t), "update")
        },
      )
      .demandCommand(1, "pick a tools subcommand (list, build, run, update)"),
  handler: () => {},
}

function notFound(name: string | undefined): void {
  console.error(`${RED}unknown tool '${name ?? ""}'${RESET}. Try: openhack tools list`)
  process.exitCode = 1
}
