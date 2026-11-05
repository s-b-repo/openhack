import yargs from "yargs"
import type { Argv, CommandModule, Options } from "yargs"
import { hideBin } from "yargs/helpers"
import { UI } from "./cli/ui"
import { InstallationVersion } from "@openhack-ai/core/installation/version"
import { FormatError } from "./cli/error"
import { EOL } from "os"
import { errorMessage } from "./util/error"
import { Heap } from "./cli/heap"

// Lazy command registration.
//
// Previously every subcommand module was imported at the top of this file, so
// starting openhack — even `--version`, `--help`, or just the TUI — eagerly
// loaded the entire graph of all ~25 commands (effect, ai-sdk, langchain,
// opentui, drizzle, shiki, …). That is hundreds of MB resident before a single
// command runs, and on a low-memory machine it tips the system into swap.
//
// `lazy` keeps each command's name/description/aliases static (so top-level
// `--help` and routing are unchanged) but only `import()`s the real module when
// that command is actually matched — in its builder (for `cmd --help`) or its
// handler (to run). Running one command now loads only that command's subtree.
// Requires parseAsync() below so yargs awaits the async builders.
type LazyMeta = { command: string; describe?: string | false; aliases?: string[] }

function lazy(meta: LazyMeta, load: () => Promise<CommandModule<any, any>>): CommandModule<any, any> {
  let cached: Promise<CommandModule<any, any>> | undefined
  const get = () => (cached ??= load())
  return {
    command: meta.command,
    describe: meta.describe,
    aliases: meta.aliases,
    // yargs' async-builder generics don't line up cleanly, so the two casts
    // below are `as unknown as <the exact field type>` — type-documented, not `any`.
    builder: (async (y: Argv) => {
      const real = await get()
      if (typeof real.builder === "function") return (real.builder as (a: Argv) => Argv | Promise<Argv>)(y)
      if (real.builder && typeof real.builder === "object") return y.options(real.builder as Record<string, Options>)
      return y
    }) as unknown as CommandModule["builder"],
    handler: (async (argv: unknown) => {
      const real = await get()
      return (real.handler as (a: unknown) => unknown)(argv)
    }) as unknown as CommandModule["handler"],
  }
}

const args = hideBin(process.argv)

function show(out: string) {
  const text = out.trimStart()
  if (!text.startsWith("openhack ")) {
    process.stderr.write(UI.logo() + EOL + EOL)
    process.stderr.write(text + EOL)
    return
  }
  process.stderr.write(out)
}

const cli = yargs(args)
  .parserConfiguration({ "populate--": true })
  .scriptName("openhack")
  .wrap(100)
  .help("help", "show help")
  .alias("help", "h")
  .version("version", "show version number", InstallationVersion)
  .alias("version", "v")
  .option("print-logs", {
    describe: "print logs to stderr",
    type: "boolean",
  })
  .option("log-level", {
    describe: "log level",
    type: "string",
    choices: ["DEBUG", "INFO", "WARN", "ERROR"],
  })
  .option("pure", {
    describe: "run without external plugins",
    type: "boolean",
  })
  .middleware(async (opts) => {
    if (opts.printLogs) process.env.OPENHACK_PRINT_LOGS = "1"
    if (opts.logLevel) process.env.OPENHACK_LOG_LEVEL = opts.logLevel
    if (opts.pure) {
      process.env.OPENHACK_PURE = "1"
    }

    Heap.start()

    process.env.AGENT = "1"
    process.env.OPENHACK = "1"
    process.env.OPENHACK = "1"
    process.env.OPENHACK_PID = String(process.pid)
  })
  .usage("")
  .completion("completion", "generate shell completion script")
  .command(lazy({ command: "acp", describe: "start ACP (Agent Client Protocol) server" }, () => import("./cli/cmd/acp").then((m) => m.AcpCommand)))
  .command(lazy({ command: "mcp", describe: "manage MCP (Model Context Protocol) servers" }, () => import("./cli/cmd/mcp").then((m) => m.McpCommand)))
  .command(lazy({ command: "$0 [project]", describe: "start openhack tui" }, () => import("./cli/cmd/tui").then((m) => m.TuiThreadCommand)))
  .command(lazy({ command: "attach <url>", describe: "attach to a running openhack server" }, () => import("./cli/cmd/attach").then((m) => m.AttachCommand)))
  .command(lazy({ command: "run [message..]", describe: "run openhack with a message" }, () => import("./cli/cmd/run").then((m) => m.RunCommand)))
  .command(lazy({ command: "generate" }, () => import("./cli/cmd/generate").then((m) => m.GenerateCommand as CommandModule<any, any>)))
  .command(lazy({ command: "debug", describe: "debugging and troubleshooting tools" }, () => import("./cli/cmd/debug").then((m) => m.DebugCommand)))
  .command(lazy({ command: "console", describe: false }, () => import("./cli/cmd/account").then((m) => m.ConsoleCommand)))
  .command(lazy({ command: "providers", describe: "manage AI providers and credentials", aliases: ["auth"] }, () => import("./cli/cmd/providers").then((m) => m.ProvidersCommand)))
  .command(lazy({ command: "agent", describe: "manage agents" }, () => import("./cli/cmd/agent").then((m) => m.AgentCommand)))
  .command(lazy({ command: "upgrade [target]", describe: "upgrade openhack to the latest or a specific version" }, () => import("./cli/cmd/upgrade").then((m) => m.UpgradeCommand as CommandModule<any, any>)))
  .command(lazy({ command: "uninstall", describe: "uninstall openhack and remove all related files" }, () => import("./cli/cmd/uninstall").then((m) => m.UninstallCommand as unknown as CommandModule<any, any>)))
  .command(lazy({ command: "serve", describe: "starts a headless openhack server" }, () => import("./cli/cmd/serve").then((m) => m.ServeCommand)))
  .command(lazy({ command: "web", describe: "start openhack server and open web interface" }, () => import("./cli/cmd/web").then((m) => m.WebCommand)))
  .command(lazy({ command: "models [provider]", describe: "list all available models" }, () => import("./cli/cmd/models").then((m) => m.ModelsCommand)))
  .command(lazy({ command: "stats", describe: "show token usage and cost statistics" }, () => import("./cli/cmd/stats").then((m) => m.StatsCommand)))
  .command(lazy({ command: "export [sessionID]", describe: "export session data as JSON" }, () => import("./cli/cmd/export").then((m) => m.ExportCommand)))
  .command(lazy({ command: "import <file>", describe: "import session data from JSON file or URL" }, () => import("./cli/cmd/import").then((m) => m.ImportCommand)))
  .command(lazy({ command: "github", describe: "manage GitHub agent" }, () => import("./cli/cmd/github").then((m) => m.GithubCommand)))
  .command(lazy({ command: "pr <number>", describe: "fetch and checkout a GitHub PR branch, then run openhack" }, () => import("./cli/cmd/pr").then((m) => m.PrCommand)))
  .command(lazy({ command: "session", describe: "manage sessions" }, () => import("./cli/cmd/session").then((m) => m.SessionCommand)))
  .command(lazy({ command: "plugin <module>", describe: "install plugin and update config", aliases: ["plug"] }, () => import("./cli/cmd/plug").then((m) => m.PluginCommand)))
  .command(lazy({ command: "db", describe: "database tools" }, () => import("./cli/cmd/db").then((m) => m.DbCommand)))
  .command(lazy({ command: "board", describe: "agent config + Ed25519-signed message board" }, () => import("./cli/cmd/board").then((m) => m.BoardCommand)))
  .command(lazy({ command: "tools", describe: "build/run/update the open-source security tools" }, () => import("./cli/cmd/tools").then((m) => m.ToolsCommand)))
  .command(lazy({ command: "openhack", describe: "OpenHack security assessment commands" }, () => import("./cli/cmd/openhack").then((m) => m.OpenHackCommand as CommandModule<any, any>)))
  .fail((msg, err) => {
    if (
      msg?.startsWith("Unknown argument") ||
      msg?.startsWith("Not enough non-option arguments") ||
      msg?.startsWith("Invalid values:")
    ) {
      if (err) throw err
      cli.showHelp(show)
    }
    if (err) throw err
    process.exit(1)
  })
  .strict()

try {
  const wantsHelp = args.includes("-h") || args.includes("--help")
  const firstPositional = args.find((a) => !a.startsWith("-"))
  if (wantsHelp && !firstPositional) {
    // Top-level help (no subcommand). With async (lazy) command builders the
    // parse-callback's `out` comes back empty for root help, so render it
    // directly. getHelp() is async and awaits the lazy builders.
    show(await cli.getHelp())
  } else if (wantsHelp) {
    // `openhack <cmd> --help` — let yargs route to the subcommand's help.
    await cli.parseAsync(args, (err: Error | undefined, _argv: unknown, out: string) => {
      if (err) throw err
      if (!out) return
      show(out)
    })
  } else {
    await cli.parseAsync()
  }
} catch (e) {
  const formatted = FormatError(e)
  if (formatted) UI.error(formatted)
  if (formatted === undefined) {
    UI.error("Unexpected error" + EOL)
    process.stderr.write(errorMessage(e) + EOL)
  }
  process.exitCode = 1
} finally {
  // Some subprocesses don't react properly to SIGTERM and similar signals.
  // Most notably, some docker-container-based MCP servers don't handle such signals unless
  // run using `docker run --init`.
  // Explicitly exit to avoid any hanging subprocesses.
  process.exit()
}
