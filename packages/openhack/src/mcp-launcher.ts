import { spawn } from "node:child_process"
import type { ChildProcess } from "node:child_process"
import * as http from "node:http"

export namespace MCPLauncher {
  interface LauncherConfig {
    name: string
    serverCommand: string[]
    serverHealthUrl: string
    serverPort: number
    mcpCommand: string[]
    mcpCwd?: string
    startupTimeout: number
    healthCheckInterval: number
    healthCheckPath: string
  }

  interface LauncherState {
    config: LauncherConfig
    serverProcess: ChildProcess | null
    mcpProcess: ChildProcess | null
    status: "starting" | "running" | "unhealthy" | "stopped"
    startedAt: string
  }

  export const CONFIGS: Record<string, LauncherConfig> = {
    hexstrike: {
      name: "hexstrike",
      serverCommand: ["python3", "hexstrike_server.py", "--port", "8899"],
      serverHealthUrl: "http://localhost:8899",
      serverPort: 8899,
      mcpCommand: ["python3", "hexstrike_mcp.py", "--server", "http://localhost:8899"],
      mcpCwd: process.env.HEXSTRIKE_PATH || process.env.OPENHACK_MCP_DIR + "/hexstrike-ai" || "/opt/hexstrike-ai",
      startupTimeout: 15000,
      healthCheckInterval: 500,
      healthCheckPath: "/health",
    },
  }

  async function healthCheck(url: string, path: string): Promise<boolean> {
    return new Promise((resolve) => {
      const req = http.get(`${url}${path}`, (res) => {
        resolve(res.statusCode === 200)
      })
      req.on("error", () => resolve(false))
      req.setTimeout(2000, () => {
        req.destroy()
        resolve(false)
      })
    })
  }

  async function waitForHealthy(config: LauncherConfig): Promise<boolean> {
    const deadline = Date.now() + config.startupTimeout
    while (Date.now() < deadline) {
      const healthy = await healthCheck(config.serverHealthUrl, config.healthCheckPath)
      if (healthy) return true
      await new Promise((r) => setTimeout(r, config.healthCheckInterval))
    }
    return false
  }

  export function launch(serverName: string): LauncherState {
    const config = CONFIGS[serverName]
    if (!config) {
      throw new Error(`Unknown MCP server: ${serverName}. Known: ${Object.keys(CONFIGS).join(", ")}`)
    }

    const state: LauncherState = {
      config,
      serverProcess: null,
      mcpProcess: null,
      status: "starting",
      startedAt: new Date().toISOString(),
    }

    console.error(`[mcp-launcher] Starting ${config.name} API server...`)

    state.serverProcess = spawn(config.serverCommand[0], config.serverCommand.slice(1), {
      cwd: config.mcpCwd,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env },
    })

    state.serverProcess.stdout?.on("data", (data: Buffer) => {
      console.error(`[${config.name}-server] ${data.toString().trim()}`)
    })

    state.serverProcess.stderr?.on("data", (data: Buffer) => {
      console.error(`[${config.name}-server-err] ${data.toString().trim()}`)
    })

    state.serverProcess.on("error", (err: Error) => {
      console.error(`[${config.name}-server] Failed to start: ${err.message}`)
      state.status = "unhealthy"
    })

    state.serverProcess.on("exit", (code: number | null) => {
      console.error(`[${config.name}-server] Exited with code ${code}`)
      state.status = "stopped"
      if (state.mcpProcess && !state.mcpProcess.killed) {
        state.mcpProcess.kill("SIGTERM")
      }
    })

    waitForHealthy(config).then((healthy) => {
      if (healthy) {
        console.error(`[mcp-launcher] ${config.name} API server healthy, starting MCP wrapper...`)
        startMCPWrapper(state)
      } else {
        console.error(`[mcp-launcher] ${config.name} API server failed to become healthy within ${config.startupTimeout}ms`)
        state.status = "unhealthy"
        if (state.serverProcess) state.serverProcess.kill("SIGTERM")
        process.exit(1)
      }
    }).catch((err) => {
      console.error(`[mcp-launcher] Health check error: ${err.message}`)
      state.status = "unhealthy"
      process.exit(1)
    })

    const onSigterm = () => shutdown(state)
    const onSigint = () => shutdown(state)
    process.on("SIGTERM", onSigterm)
    process.on("SIGINT", onSigint)
    process.once("SIGTERM", () => {
      process.off("SIGTERM", onSigterm)
      process.off("SIGINT", onSigint)
    })

    return state
  }

  function startMCPWrapper(state: LauncherState): void {
    state.status = "running"

    state.mcpProcess = spawn(
      state.config.mcpCommand[0],
      state.config.mcpCommand.slice(1),
      {
        cwd: state.config.mcpCwd,
        stdio: ["inherit", "inherit", "inherit"],
        env: { ...process.env },
      },
    )

    state.mcpProcess.on("error", (err: Error) => {
      console.error(`[${state.config.name}-mcp] Failed to start: ${err.message}`)
      state.status = "unhealthy"
      shutdown(state)
    })

    state.mcpProcess.on("exit", (code: number | null) => {
      console.error(`[${state.config.name}-mcp] Exited with code ${code}`)
      shutdown(state)
    })
  }

  function shutdown(state: LauncherState): void {
    if (state.status === "stopped") return
    state.status = "stopped"

    if (state.mcpProcess && !state.mcpProcess.killed) {
      state.mcpProcess.kill("SIGTERM")
    }

    if (state.serverProcess && !state.serverProcess.killed) {
      state.serverProcess.kill("SIGTERM")
    }

    setTimeout(() => {
      if (state.mcpProcess && !state.mcpProcess.killed) {
        state.mcpProcess.kill("SIGKILL")
      }
      if (state.serverProcess && !state.serverProcess.killed) {
        state.serverProcess.kill("SIGKILL")
      }
    }, 5000)
  }

  export function isHealthy(state: LauncherState): boolean {
    return state.status === "running"
  }

  export function getStatus(state: LauncherState): string {
    return `[${state.config.name}] status: ${state.status}, started: ${state.startedAt}`
  }
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  const serverName = process.argv[2]
  if (!serverName) {
    console.error("Usage: openhack-mcp-launcher <server-name>")
    process.exit(1)
  }
  MCPLauncher.launch(serverName)
}
