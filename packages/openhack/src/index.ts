import { Safety } from "./safety"
import { Scope } from "./scope"
import { Automode } from "./automode"
import { Findings } from "./findings"
import { HallucinationGuard } from "./hallucination"
import { Workflow } from "./workflow"
import { ResourceManager } from "./resources"
import { Secrets } from "./secrets"
import { Audit } from "./audit"
import { MiddlewareChain } from "./middleware"
import { MCPLauncher } from "./mcp-launcher"
import { ROE } from "./roe"
import { Net } from "./net"
import { Orchestrator } from "./orchestrator"
import { Advisor } from "./advisor"
import { MOERouter } from "./moe-router"
import { GlobalConfig } from "./global-config"
import { Codeguard } from "./codeguard"
import { Orchestrators } from "./orchestrators"
import { OpenHackPlugin } from "./plugin"
import { RoundBudget } from "./round-budget"
import { Managers } from "./managers"
import { Blackboard } from "./blackboard"
import { Overwatch } from "./overwatch"
import { Variants } from "./variants"

export {
  Safety, Scope, Automode, Findings, HallucinationGuard,
  Workflow, ResourceManager, Secrets, Audit, MiddlewareChain,
  MCPLauncher, ROE, Net, Orchestrator, Advisor,
  MOERouter, GlobalConfig, Codeguard, Orchestrators, OpenHackPlugin,
  RoundBudget, Managers, Blackboard, Overwatch, Variants,
}

export const OPENHACK_VERSION = "0.5.0"
export const OPENHACK_ASCII = `
  ___                   __  __           __
 / _ \\ ___  ___ ________/ / / / ___ _____/ /__
/ // / _ \\/ _\`/ __/ _  / _  / / _ \`/ __/  '_/
\\___/ .__/\\_,_/\\__/\\_,_/_/ /_/  \\_,_/\\__/_/\\_\\
   /_/
  Safety harness · Scope & ROE enforcement · Findings · MoE routing
`
