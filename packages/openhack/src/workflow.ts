import * as fs from "fs"
import * as path from "path"

export namespace Workflow {
  export interface WorkflowConfig {
    id: string
    description: string
    agent: string
    prompt: string
    context_share: boolean
    output_save: string
    tools: string[]
    timeout?: number
  }

  export interface ActiveWorkflow {
    id: string
    config: WorkflowConfig
    status: "running" | "paused" | "completed" | "failed"
    startedAt: string
    endedAt?: string
    outputDir: string
    contextSize: number
    taskCount: number
  }

  const WORKFLOW_DIR = ".openhack/workflows"

  export function ensureDir(): void {
    if (!fs.existsSync(WORKFLOW_DIR)) {
      fs.mkdirSync(WORKFLOW_DIR, { recursive: true })
    }
  }

  export function create(config: WorkflowConfig): ActiveWorkflow {
    ensureDir()
    const id = config.id || `wf-${Date.now().toString(36)}`
    const outputDir = config.output_save || path.join(WORKFLOW_DIR, id)

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true })
    }

    const workflow: ActiveWorkflow = {
      id,
      config: { ...config, id, output_save: outputDir },
      status: "running",
      startedAt: new Date().toISOString(),
      outputDir,
      contextSize: 0,
      taskCount: 0,
    }

    saveState(workflow)
    return workflow
  }

  export function saveState(workflow: ActiveWorkflow): void {
    ensureDir()
    const filepath = path.join(WORKFLOW_DIR, `${workflow.id}.json`)
    fs.writeFileSync(filepath, JSON.stringify(workflow, null, 2), "utf-8")
  }

  export function list(): ActiveWorkflow[] {
    ensureDir()
    const workflows: ActiveWorkflow[] = []
    if (!fs.existsSync(WORKFLOW_DIR)) return workflows

    const files = fs.readdirSync(WORKFLOW_DIR).filter((f) => f.endsWith(".json"))
    for (const file of files) {
      try {
        const wf = JSON.parse(fs.readFileSync(path.join(WORKFLOW_DIR, file), "utf-8"))
        workflows.push(wf)
      } catch {}
    }
    return workflows
  }

  export function get(id: string): ActiveWorkflow | null {
    const filepath = path.join(WORKFLOW_DIR, `${id}.json`)
    if (!fs.existsSync(filepath)) return null
    try {
      return JSON.parse(fs.readFileSync(filepath, "utf-8"))
    } catch {
      return null
    }
  }

  export function stop(id: string, status: "completed" | "failed" = "completed"): ActiveWorkflow | null {
    const wf = get(id)
    if (!wf) return null
    wf.status = status
    wf.endedAt = new Date().toISOString()
    saveState(wf)
    return wf
  }

  export function saveOutput(
    workflow: ActiveWorkflow,
    filename: string,
    content: string,
  ): void {
    if (!fs.existsSync(workflow.outputDir)) {
      fs.mkdirSync(workflow.outputDir, { recursive: true })
    }
    fs.writeFileSync(path.join(workflow.outputDir, filename), content, "utf-8")
  }

  export function getDefaultWorkflows(target: string): WorkflowConfig[] {
    return [
      {
        id: `recon-${target.replace(/[^a-zA-Z0-9.-]/g, "_")}`,
        description: "Passive and active reconnaissance",
        agent: "recon",
        prompt: `Conduct comprehensive reconnaissance on ${target}. Include port scanning, DNS enumeration, subdomain discovery, service fingerprinting, and technology stack identification.`,
        context_share: false,
        output_save: path.join(WORKFLOW_DIR, `recon-${target.replace(/[^a-zA-Z0-9.-]/g, "_")}`),
        tools: ["nmap", "rustscan", "amass", "subfinder", "dnsenum", "theharvester"],
      },
      {
        id: `web-${target.replace(/[^a-zA-Z0-9.-]/g, "_")}`,
        description: "Web application assessment workflow",
        agent: "exploit",
        prompt: `Assess ${target} for web application vulnerabilities including XSS, SQL injection, CSRF, SSRF, path traversal, and authentication bypass.`,
        context_share: false,
        output_save: path.join(WORKFLOW_DIR, `web-${target.replace(/[^a-zA-Z0-9.-]/g, "_")}`),
        tools: ["sqlmap", "nuclei", "ffuf", "dalfox", "wpscan", "nikto", "arjun"],
      },
      {
        id: `report-${target.replace(/[^a-zA-Z0-9.-]/g, "_")}`,
        description: "Pentest report generation",
        agent: "report",
        prompt: `Generate a comprehensive penetration test report for ${target}. Aggregate all findings, assign CVSS scores, map to CWE, generate executive summary, and export to SysReptor.`,
        context_share: false,
        output_save: path.join(WORKFLOW_DIR, `report-${target.replace(/[^a-zA-Z0-9.-]/g, "_")}`),
        tools: ["sysreptor"],
      },
    ]
  }
}
