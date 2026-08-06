import { Server } from "@modelcontextprotocol/sdk/server/index.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
} from "@modelcontextprotocol/sdk/types.js"
import * as path from "node:path"
import * as fs from "node:fs"

const REPORTS_BASE = process.env.OPENHACK_REPORTS_DIR || ".openhack/reports"

const SYSREPTOR_URL = process.env.SYSREPTOR_URL || "http://localhost:8000"
const SYSREPTOR_TOKEN = process.env.SYSREPTOR_TOKEN || ""

// File I/O for report/evidence tools is confined to REPORTS_BASE with a strict
// allowlist: canonical (symlink-resolved) paths only, an exact directory
// boundary (not a bare startsWith prefix), an extension allowlist, and a size
// cap. There is deliberately no "sensitive file" denylist — anything outside
// REPORTS_BASE is rejected outright.
const EVIDENCE_EXT_ALLOW = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".txt", ".log", ".md", ".json", ".csv"])
const MAX_EVIDENCE_BYTES = 25 * 1024 * 1024

function canonicalReportsBase(): string {
  const base = path.resolve(REPORTS_BASE)
  try {
    return fs.realpathSync(base)
  } catch {
    return base
  }
}

function isWithinBase(candidate: string, base: string): boolean {
  return candidate === base || candidate.startsWith(base + path.sep)
}

function toolError(text: string) {
  return { content: [{ type: "text", text }], isError: true }
}

interface ApiResponse {
  ok: boolean
  status: number
  data?: unknown
  error?: string
}

async function apiRequest(
  method: string,
  endpoint: string,
  body?: unknown,
): Promise<ApiResponse> {
  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    }
    if (SYSREPTOR_TOKEN) {
      headers["Authorization"] = `Bearer ${SYSREPTOR_TOKEN}`
    }

    const url = `${SYSREPTOR_URL}${endpoint}`
    const options: RequestInit = {
      method,
      headers,
    }
    if (body) {
      options.body = JSON.stringify(body)
    }

    const response = await fetch(url, options)
    const data = await response.json().catch(() => null)

    return {
      ok: response.ok,
      status: response.status,
      data,
      error: response.ok ? undefined : String(data?.detail || data?.error || response.statusText),
    }
  } catch (err) {
    return {
      ok: false,
      status: 0,
      error: String(err),
    }
  }
}

const TOOLS = [
  {
    name: "sr_project_create",
    description: "Create a new pentest project in SysReptor",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Project name" },
        description: { type: "string", description: "Project description" },
        client_name: { type: "string", description: "Client name (optional)" },
      },
      required: ["name"],
    },
  },
  {
    name: "sr_finding_create",
    description: "Add a security finding to a SysReptor project",
    inputSchema: {
      type: "object",
      properties: {
        project_id: { type: "string", description: "Project UUID" },
        title: { type: "string", description: "Finding title" },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "info"],
          description: "Severity level",
        },
        description: { type: "string", description: "Detailed finding description" },
        remediation: { type: "string", description: "Remediation recommendations" },
        cwe: { type: "string", description: "CWE identifier (e.g. CWE-89)" },
        cvss_score: { type: "number", description: "CVSS 3.1 score (0-10)" },
        cvss_vector: { type: "string", description: "CVSS 3.1 vector string" },
        affected_component: { type: "string", description: "Affected component or URL" },
      },
      required: ["project_id", "title", "severity"],
    },
  },
  {
    name: "sr_finding_update",
    description: "Update an existing finding in SysReptor",
    inputSchema: {
      type: "object",
      properties: {
        finding_id: { type: "string", description: "Finding UUID" },
        title: { type: "string", description: "Updated title" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
        description: { type: "string", description: "Updated description" },
        remediation: { type: "string", description: "Updated remediation" },
        status: { type: "string", enum: ["open", "resolved", "accepted", "wont_fix"] },
      },
      required: ["finding_id"],
    },
  },
  {
    name: "sr_finding_list",
    description: "List all findings for a SysReptor project",
    inputSchema: {
      type: "object",
      properties: {
        project_id: { type: "string", description: "Project UUID" },
      },
      required: ["project_id"],
    },
  },
  {
    name: "sr_report_generate",
    description: "Generate a PDF or HTML report for a SysReptor project",
    inputSchema: {
      type: "object",
      properties: {
        project_id: { type: "string", description: "Project UUID" },
        format: { type: "string", enum: ["pdf", "html"], description: "Report format" },
        template: { type: "string", description: "Template name (optional)" },
      },
      required: ["project_id"],
    },
  },
  {
    name: "sr_report_export",
    description: "Export a generated report to a local file",
    inputSchema: {
      type: "object",
      properties: {
        project_id: { type: "string", description: "Project UUID" },
        format: { type: "string", enum: ["pdf", "html", "md"], description: "Export format" },
        output_path: { type: "string", description: "Path to save the exported report" },
      },
      required: ["project_id", "format", "output_path"],
    },
  },
  {
    name: "sr_template_list",
    description: "List available report templates in SysReptor",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "sr_section_add",
    description: "Add a custom section to a SysReptor report",
    inputSchema: {
      type: "object",
      properties: {
        project_id: { type: "string", description: "Project UUID" },
        title: { type: "string", description: "Section title" },
        content: { type: "string", description: "Section content (Markdown)" },
        order: { type: "number", description: "Section order/position" },
      },
      required: ["project_id", "title", "content"],
    },
  },
  {
    name: "sr_evidence_upload",
    description: "Attach evidence (screenshots, logs) to a finding",
    inputSchema: {
      type: "object",
      properties: {
        finding_id: { type: "string", description: "Finding UUID" },
        file_path: { type: "string", description: "Path to evidence file" },
        caption: { type: "string", description: "Evidence caption/description" },
      },
      required: ["finding_id", "file_path"],
    },
  },
  {
    name: "sr_project_summary",
    description: "Get project overview including finding counts by severity",
    inputSchema: {
      type: "object",
      properties: {
        project_id: { type: "string", description: "Project UUID" },
      },
      required: ["project_id"],
    },
  },
]

async function handleToolCall(request: CallToolRequest) {
  const { name, arguments: args } = request.params

  switch (name) {
    case "sr_project_create": {
      const result = await apiRequest("POST", "/api/v1/projects/", {
        name: args.name,
        description: args.description || "",
        client_name: args.client_name || "",
      })
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      }
    }

    case "sr_finding_create": {
      const result = await apiRequest("POST", `/api/v1/projects/${args.project_id}/findings/`, {
        title: args.title,
        severity: args.severity,
        description: args.description || "",
        remediation: args.remediation || "",
        cwe: args.cwe || null,
        cvss_score: args.cvss_score || null,
        cvss_vector: args.cvss_vector || null,
        affected_component: args.affected_component || null,
      })
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      }
    }

    case "sr_finding_update": {
      const body: Record<string, unknown> = {}
      if (args.title) body.title = args.title
      if (args.severity) body.severity = args.severity
      if (args.description) body.description = args.description
      if (args.remediation) body.remediation = args.remediation
      if (args.status) body.status = args.status

      const result = await apiRequest("PATCH", `/api/v1/findings/${args.finding_id}/`, body)
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      }
    }

    case "sr_finding_list": {
      const result = await apiRequest("GET", `/api/v1/projects/${args.project_id}/findings/`)
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      }
    }

    case "sr_report_generate": {
      const format = args.format || "pdf"
      const result = await apiRequest("POST", `/api/v1/projects/${args.project_id}/reports/`, {
        template: args.template || "default",
        format,
      })
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      }
    }

    case "sr_report_export": {
      const format = args.format || "pdf"
      const result = await apiRequest(
        "GET",
        `/api/v1/projects/${args.project_id}/reports/export/?format=${format}`,
      )
      if (result.ok && result.data) {
        const base = canonicalReportsBase()
        const requested = path.resolve(args.output_path as string)
        // Resolve the (existing) parent through symlinks, then re-attach the
        // basename, so a symlinked parent cannot redirect the write outside base.
        let parentReal: string
        try {
          parentReal = fs.realpathSync(path.dirname(requested))
        } catch {
          return toolError(`Blocked: output directory must exist within ${REPORTS_BASE}`)
        }
        const outputFile = path.join(parentReal, path.basename(requested))
        if (!isWithinBase(outputFile, base)) {
          return toolError(`Blocked: output path must be within ${REPORTS_BASE}`)
        }
        // Refuse to write through an existing symlink at the target itself.
        try {
          if (fs.lstatSync(outputFile).isSymbolicLink()) {
            return toolError("Blocked: refusing to write through a symlink")
          }
        } catch {}
        fs.writeFileSync(outputFile, JSON.stringify(result.data, null, 2), { mode: 0o600 })
        return {
          content: [{ type: "text", text: `Report exported to ${outputFile}` }],
        }
      }
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      }
    }

    case "sr_template_list": {
      const result = await apiRequest("GET", "/api/v1/templates/")
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      }
    }

    case "sr_section_add": {
      const result = await apiRequest(
        "POST",
        `/api/v1/projects/${args.project_id}/sections/`,
        {
          title: args.title,
          content: args.content,
          order: args.order || 0,
        },
      )
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      }
    }

    case "sr_evidence_upload": {
      try {
        const base = canonicalReportsBase()
        // Canonicalize through symlinks; the file must exist to be evidence.
        let evidenceFile: string
        try {
          evidenceFile = fs.realpathSync(path.resolve(args.file_path as string))
        } catch {
          return toolError("Blocked: evidence file not found")
        }
        if (!isWithinBase(evidenceFile, base)) {
          return toolError(`Blocked: evidence must be within ${REPORTS_BASE}`)
        }
        if (!EVIDENCE_EXT_ALLOW.has(path.extname(evidenceFile).toLowerCase())) {
          return toolError(`Blocked: unsupported evidence type (allowed: ${[...EVIDENCE_EXT_ALLOW].join(", ")})`)
        }
        const stat = fs.statSync(evidenceFile)
        if (!stat.isFile()) return toolError("Blocked: evidence path is not a regular file")
        if (stat.size > MAX_EVIDENCE_BYTES) {
          return toolError(`Blocked: evidence file exceeds ${MAX_EVIDENCE_BYTES} bytes`)
        }
        const base64 = fs.readFileSync(evidenceFile).toString("base64")
        const result = await apiRequest(
          "POST",
          `/api/v1/findings/${args.finding_id}/evidence/`,
          {
            filename: path.basename(evidenceFile),
            content: base64,
            caption: args.caption || "",
          },
        )
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          isError: !result.ok,
        }
      } catch (err) {
        return toolError(`Failed to read file: ${err}`)
      }
    }

    case "sr_project_summary": {
      const result = await apiRequest("GET", `/api/v1/projects/${args.project_id}/`)
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      }
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      }
  }
}

async function main() {
  const server = new Server(
    { name: "openhack-sysreptor", version: "0.1.0" },
    { capabilities: { tools: {} } },
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }))
  server.setRequestHandler(CallToolRequestSchema, handleToolCall)

  const transport = new StdioServerTransport()
  await server.connect(transport)

  console.error(`SysReptor MCP server started — endpoint: ${SYSREPTOR_URL}`)
}

main().catch(console.error)
