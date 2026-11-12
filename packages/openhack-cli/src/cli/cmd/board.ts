import type { Argv, CommandModule } from "yargs"
import {
  Project,
  keyDisplay,
  resolvedKey,
  PROVIDER_MODELS,
  PROVIDER_ENV,
  rememberProject,
} from "@openhack-ai/board"

function open(argv: { project?: string }): Project {
  const p = new Project(argv.project || process.cwd())
  if (!p.exists()) p.initDefaults()
  else p.load()
  rememberProject(p.root)
  return p
}

const GREEN = "\x1b[32m", RED = "\x1b[31m", DIM = "\x1b[2m", RESET = "\x1b[0m", BOLD = "\x1b[1m"

export const BoardCommand: CommandModule = {
  command: "board",
  describe: "per-project agent config + an Ed25519-signed, verified message board",
  builder: (y: Argv) =>
    y
      .option("project", { type: "string", describe: "project directory (default: cwd)" })
      .command(
        "agents",
        "list the main session and sub-agents with their provider/model/key",
        {},
        (argv) => {
          const p = open(argv)
          for (const a of p.allAgents()) {
            const tag = a.name === "main" ? "main" : "sub "
            const avail = resolvedKey(a) ? `${GREEN}key ok${RESET}` : a.apiKey ? `${RED}NO KEY${RESET}` : `${DIM}no key${RESET}`
            console.log(
              `[${tag}] ${BOLD}${a.name.padEnd(14)}${RESET} ` +
                `provider=${(a.provider || "-").padEnd(10)} model=${(a.model || "-").padEnd(22)} ` +
                `key=${keyDisplay(a).padEnd(30)} ${avail}`,
            )
          }
          console.log(`\n${DIM}project: ${p.root}${RESET}`)
        },
      )
      .command(
        "set <agent>",
        "set provider / model / api-key for an agent",
        (yy: Argv) =>
          yy
            .positional("agent", { type: "string", describe: "agent name (or 'main')" })
            .option("provider", { type: "string", describe: Object.keys(PROVIDER_MODELS).join(" / ") })
            .option("model", { type: "string" })
            .option("key", { type: "string", describe: "literal secret, or 'env:VARNAME' (preferred)" }),
        (argv) => {
          const p = open(argv)
          if (!argv.agent) return fail("agent is required")
          const a = p.getAgent(argv.agent)
          if (!a) return fail(`unknown agent '${argv.agent}'`)
          if (argv.provider !== undefined) {
            a.provider = argv.provider
            if (!a.apiKey && PROVIDER_ENV[a.provider]) a.apiKey = "env:" + PROVIDER_ENV[a.provider]
          }
          if (argv.model !== undefined) a.model = argv.model
          if (argv.key !== undefined) a.apiKey = argv.key
          p.save()
          console.log(`${GREEN}saved${RESET} ${a.name}: provider=${a.provider} model=${a.model} key=${keyDisplay(a)}`)
        },
      )
      .command(
        "add <agent>",
        "add a sub-agent",
        (yy: Argv) => yy.positional("agent", { type: "string" }),
        (argv) => {
          const p = open(argv)
          if (!argv.agent) return fail("agent is required")
          try {
            p.addAgent(argv.agent)
            console.log(`${GREEN}added${RESET} sub-agent '${argv.agent}'`)
          } catch (e) {
            fail(e instanceof Error ? e.message : String(e))
          }
        },
      )
      .command(
        "rm <agent>",
        "remove a sub-agent",
        (yy: Argv) => yy.positional("agent", { type: "string" }),
        (argv) => {
          const p = open(argv)
          if (!argv.agent) return fail("agent is required")
          if (argv.agent === "main") return fail("cannot remove the main session")
          p.removeAgent(argv.agent)
          console.log(`${GREEN}removed${RESET} '${argv.agent}'`)
        },
      )
      .command(
        "post <author> <message..>",
        "sign a message with the author's key and append it to the board",
        (yy: Argv) =>
          yy
            .positional("author", { type: "string", describe: "posting agent (e.g. main, recon)" })
            .positional("message", { type: "string", array: true }),
        (argv) => {
          const p = open(argv)
          if (!argv.author) return fail("author is required")
          if (!p.getAgent(argv.author)) return fail(`unknown agent '${argv.author}'`)
          const body = (argv.message as string[]).join(" ").trim()
          if (!body) return fail("empty message")
          const m = p.post(argv.author, body)
          console.log(`${GREEN}posted & signed${RESET} #${m.seq} as '${m.author}'`)
        },
      )
      .command("list", "list messages with their verification result", {}, (argv) => {
        const p = open(argv)
        const res = p.verifyBoard()
        if (!res.length) return console.log(`${DIM}no messages yet — use 'openhack board post <agent> <msg>'${RESET}`)
        for (const { msg, ok, reason } of res) {
          const badge = ok ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`
          console.log(`${badge} #${String(msg.seq).padStart(3)} ${BOLD}${(msg.author || "?").padEnd(12)}${RESET} ${DIM}${msg.ts}${RESET}`)
          console.log(`    ${ok ? "" : RED}${msg.body}${RESET}`)
          if (!ok) console.log(`    ${RED}${BOLD}⚠ ${reason}${RESET}`)
        }
      })
      .command("verify", "verify the whole board; exit non-zero if any message fails", {}, (argv) => {
        const p = open(argv)
        const res = p.verifyBoard()
        const okc = res.filter((r) => r.ok).length
        console.log(`${okc === res.length ? GREEN : RED}${okc}/${res.length} verified OK${RESET}`)
        for (const { msg, ok, reason } of res) if (!ok) console.log(`  ${RED}✗ #${msg.seq} ${msg.author}: ${reason}${RESET}`)
        if (okc !== res.length) process.exitCode = 1
      })
      .demandCommand(1, "pick a board subcommand (agents, set, add, rm, post, list, verify)"),
  handler: () => {},
}

function fail(msg: string): void {
  console.error(`\x1b[31merror:\x1b[0m ${msg}`)
  process.exitCode = 1
}
