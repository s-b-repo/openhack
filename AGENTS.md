# OpenHack

An AI-powered security assessment assistant for authorized penetration testing professionals.

## Commands

| Command | Description |
|---|---|
| `/connect` | Configure LLM provider |
| `/init` | Analyze project and create AGENTS.md |
| `/automode` | Run batch prompt processing |
| `/danger` | Toggle safety harness override |
| `/findings list` | List all findings for current target |
| `/findings uncertain` | Show findings needing manual verification |
| `/findings export` | Export findings to SysReptor |
| `/workflow start <name>` | Launch a new workflow session |
| `/workflow list` | List all active workflows |
| `/hallucination stats` | Show hallucination counter |
| `/recover now` | Save and restart session |
| `/undo` | Undo last changes |
| `/share` | Share session link |

## Agents

| Agent | Mode | Purpose |
|---|---|---|
| **build** | primary | Default security assessment agent with full tool access |
| **plan** | primary | Read-only planning and analysis mode |
| **planner** | primary | Multi-plan orchestration with parallel agent execution |
| **recon** | subagent | Network and web reconnaissance |
| **exploit** | subagent | Exploitation and vulnerability testing |
| **post-exploit** | subagent | Post-exploitation operations |
| **c2** | subagent | C2 operations (arcticfox) |
| **report** | subagent | Pentest report generation (SysReptor) |
| **general** | subagent | Multi-step task execution |
| **explore** | subagent | Codebase exploration |

## MCP Servers

Bundled in `.openhack/openhack.jsonc` (all **opt-in**, `"enabled": false` by default — flip to `true` and install the server to use it):

| Server | Tools | Kind |
|---|---|---|
| HexStrike AI | 150+ security tools | Security |
| pentest-ai | 200+ tools, 60 probes | Security |
| rustsploit | 29 MCP tools | Security |
| arcticfox-c3 | C2 + agent management | Security |
| SysReptor | 10 reporting tools | Reporting |
| filesystem | read/write files | General |
| git | repo operations | General |
| fetch | fetch/convert web pages | General |
| memory | persistent knowledge graph | General |
| websearch | Brave search (needs `BRAVE_API_KEY`) | General |
| camoufox | stealth browser — passes Cloudflare managed challenges, carries `cf_clearance` (see `packages/openhack/mcp/README.md`) | Browser |
| onlyoffice | docx/xlsx/pptx report generation (replaces SysReptor; `~/onlyoffice-mcp`) | Reporting |

### Adding any MCP server

MCP tools become agent tools automatically, scoped as `<server>_<tool>`. Add a server under `mcp` and grant its tools under `agent.<name>.mcp_tools`:

```jsonc
{
  "mcp": {
    // local (stdio) server:
    "myserver": { "type": "local", "command": ["npx", "-y", "some-mcp-server"], "enabled": true,
                  "environment": { "API_KEY": "{env:MY_API_KEY}" } },
    // or a remote server:
    "remote": { "type": "remote", "url": "https://host/mcp", "enabled": true,
                "headers": { "Authorization": "Bearer {env:TOKEN}" } }
  },
  "agent": { "build": { "mcp_tools": { "myserver": ["myserver_*"] } } }
}
```

`{env:VAR}` interpolates environment variables. Enforcement (safety/scope/ROE) applies to MCP tool calls too.

## Configuration

Configure via `openhack.json` or `.openhack/openhack.jsonc`:

```jsonc
{
  "mcp": {
    "hexstrike": { "type": "local", "command": ["python3", "hexstrike_mcp.py"], "enabled": true }
  },
  "safety": { "enabled": true },
  "automode": { "output_dir": ".openhack/automode-results" }
}
```

## Safety & enforcement

When a `.openhack/` directory is present, OpenHack registers a runtime plugin
(`packages/openhack/src/plugin`) that enforces policy on **every** tool call via
the `tool.execute.before` hook — blocking with a tool error:

- **Safety harness** — destructive commands (`rm -rf /`, `dd` to a disk, `mkfs`,
  fork bombs, `curl | sh`, shutdown/reboot). Matching normalizes the command
  first, so quote/comment obfuscation (`r''m -rf /`, `rm -rf / #x`) is still caught.
  Toggle with `/danger`.
- **Scope** — targets referenced in a command or tool arguments must be in the
  engagement scope (`.openhack/scope.json`); supports exact, wildcard, and CIDR.
- **Rules of Engagement** — a signed ROE (`.openhack/roe/active.roe.json`) is
  enforced for target-bearing commands: revoked/expired ROEs, out-of-scope
  targets, unauthorized tools, and post-signing tampering all block execution.

Tool output is additionally scrubbed of secrets and scanned for findings, and
the active scope/ROE is injected into the system prompt. Without `.openhack/`,
none of this loads and OpenHack behaves like vanilla OpenCode.

## Attack graph & tight loop (`openhack automode --loop --graph`)

The `openhack automode --loop` driver iterates rounds against a target and terminates on cost / ROE / coverage-% / convergence / max-rounds. When the **attack-graph controller** is enabled, rounds ≥ 2 are shaped by a live graph instead of the static objective batch:

- Every engagement's **AttackGraph** (`.openhack/graph/<target>.json`, HMAC-signed) holds three node kinds — `AssetNode` (host/port/service/endpoint/cred), `FindingNode` (reference to `Findings` by hash), and `ActionNode` (the candidate-dispatch frontier).
- Once per round, a small **controller** (LLM if `Provider.getSmallModel` resolves one, otherwise a deterministic heuristic) reads the round's new findings + coverage gaps + last-round delta and returns a `GraphUpdate` (add nodes, add edges, reprioritize, prune, rationale). All errors, timeouts, and schema mismatches degrade to the heuristic.
- The frontier is pruned through the existing pure enforcement decisions (`evaluateToolCall("task", …)` composes safety + scope + ROE; `ResourceManager.findConflicting` marks resource-conflicted actions but doesn't drop them) — a candidate that would be blocked at dispatch is instead recorded with `blockedReason` and an `invalidates` edge so the controller stops re-emitting it.
- Round 1 always uses the static `Orchestrators.buildBatch` for a warm start; rounds 2+ dispatch the top-K queued frontier. If the frontier is empty AND coverage has no untested cells, the loop terminates on `frontier_empty` before hitting `maxRounds`.

Config keys (in `.openhack/openhack.jsonc`):

| Key | Default | Meaning |
|---|---|---|
| `graph.controller_enabled` | `false` | Enable the controller. `LoopOptions.graph` overrides. |
| `graph.controller_model` | *(unset)* | Explicit `provider/model` for the graph controller. If unset, uses `Provider.getSmallModel` (honors `experimental.provider.small_model` plugin hook). |
| `graph.frontier_k` | `6` | Frontier width per round. `LoopOptions.frontierK` overrides. |

Package: `packages/openhack-orchestration/` — `AttackGraph`, `GraphStore`, `Frontier`, `HeuristicController`, `LlmController`. Tests live in `packages/openhack/test/` (run `bun test` from that package).

## Loop performance harness (`bench:loop`)

Two new package scripts on `packages/opencode/`:

- **`bench:loop`** — `bun run script/bench-attack-loop.ts`. Env-driven: `BENCH_TARGET`, `BENCH_ROUNDS`, `BENCH_MODE=graph|static`, `BENCH_FIXTURE=perf/fixtures/site1.json`, `BENCH_FRONTIER_K`, `BENCH_INSTANCES`. Runs `runOrchestrationLoop` end-to-end with a deterministic mock LLM factory (no cost, no network) and emits `METRIC name=value` lines: rounds-to-goal, wall-seconds, cost-to-first-critical, total cost/tokens, coverage %, final frontier size, controller p50, task-tool p50/p95, block ratio, termination reason.
- **`bench:loop:compare`** — `bun run script/bench-attack-loop-compare.ts HEAD~1 HEAD`. Runs the bench in `git worktree` sandboxes for two refs (never touches the caller's tree), prints a Markdown delta table, exits 1 if any of `loop_total_cost_usd` / `loop_wall_seconds` / `loop_rounds_to_goal` regresses by > 15%.

Fixtures live under `perf/fixtures/` (`site1.json`, `site2.json`, `site3-verify.json`) — swap in your own to exercise a specific attack surface.

## Loop-graph hybrid + universal LLM wiring

The `openhack automode --loop` driver now unifies the static-orchestrator batch, the live attack-graph controller, and the review/QA slash-command macros into one dispatch surface. Two changes matter for operators:

### 1. Universal LLM provider setup

Auth is opencode-layer; every provider `@opencode-ai/core/models-dev` knows about is discoverable via env vars:

```bash
export DEEPSEEK_API_KEY=…                  # DeepSeek — cheapest
export ANTHROPIC_API_KEY=…                 # Claude Sonnet + Haiku
export GOOGLE_GENERATIVE_AI_API_KEY=…      # Gemini Flash / Pro
export OPENAI_API_KEY=…                    # GPT-4o / o3
```

Or, interactive: `opencode auth login <providerID>` writes `~/.local/share/opencode/auth.json`.

Model selection (framework-layer):

```bash
openhack model --set deepseek/deepseek-v4  # writes .openhack/models.json
openhack automode --target … --loop        # picks up the set model automatically
```

**The `openhack model --set X` command now actually affects automode.** Previously it was a silent no-op — the automode CLI ignored `.openhack/models.json` and fell back to opencode's provider default. Fixed in `runAutomodeCli`: `argv.model` defaults from `GlobalConfig.main()` when unset.

**Per-agent tier resolution.** `GlobalConfig.resolveForAgent(agent)` picks a tier per dispatch:

| Agent | Default tier | Rationale |
|---|---|---|
| `recon`, `osint` | `cheap` (deepseek) | High-volume enumeration, low reasoning depth |
| `defense`, `defense-review`, `council`, `triage`, `general` | `fast` (haiku) | Short structured judgment |
| `exploit`, `post-exploit`, `c2`, `report`, `plan`, `planner` | `main` (sonnet) | Deep reasoning, chained tool use |
| `cleanup` | `draft` (deepseek) | Fixed decommission script |

Overridable via `.openhack/models.json` under `agent_tiers`: `{"agent_tiers": {"recon": "main"}}`.

### 2. Every specialist role is a first-class graph ActionNode

The heuristic controller emits four new node kinds each round when their triggers fire, and the loop's `runInstance` dispatches them uniformly through the same enforcement + scoring path as recon/exploit/post-exploit:

| Node kind | Trigger | Dispatch |
|---|---|---|
| `command:council` ActionNode | `newFindings >= 2` this round | `/council` macro via `runCommandMacro` (source of truth = `.opencode/command/council.md`) |
| `command:triage` ActionNode | `coverageGaps > 20 && methodGaps > 5` | `/triage` macro |
| `osint` ActionNode | round 1 only | `.openhack/agents/osint.md` (passive intel: CT logs, passive DNS, GitHub leaks — no direct probes) |
| `command:cleanup` ActionNode | frontier + coverage + combos all empty | `/cleanup` macro (reverse-deploy order; verify each removal) |

Static-batch orchestrators (`packages/openhack/src/orchestrators.ts`) gained four new declarations covering the same roles at loop startup: `osint-passive` (priority 0), `defense-review` (priority 3), `c2-handoff` (priority 3, opt-in), `cleanup-artifacts` (priority 99, `command: "cleanup"`).

**`ActionNode.command` sentinel** — added on both `Automode.TaskSpec` and `ActionNode` types. When set, `runInstance` fires `run --command <name>` on the openhack subprocess so the macro file drives the protocol. When unset, the normal `--agent <agent>` path runs. This is what makes `/council`, `/triage`, and `/cleanup` first-class ActionNodes without any new dispatch layer — the plumbing already existed.

**Council / Plan invocation** in the loop now prefers the macro over the inline `COUNCIL_PROMPT` / `PLAN_PROMPT` paraphrases, with graceful fallback when the macro isn't available. Any future edit to `.opencode/command/council.md` is picked up automatically — no more drift between the shell-run macro and the loop's paraphrase.

## ROE-control MCP (`packages/openhack-mcp-roe/`)

A dedicated MCP server that lets agents (and human operators) read, draft, and — with explicit env-var consent — sign or revoke the engagement's Rules of Engagement without hand-editing `.openhack/roe/active.roe.json`.

Tools split by risk:

| Tools | Access | Notes |
|---|---|---|
| `roe_status`, `roe_validate`, `roe_list_authorized_tools`, `roe_list_authorized_models`, `roe_validate_model`, `roe_time_remaining_minutes`, `roe_summary_markdown`, `roe_get`, `roe_diff` | **Read-only** — every specialist agent | Same enforcement decisions the runtime plugin uses; safe to call from any agent. |
| `roe_create_draft`, `roe_set_targets`, `roe_set_authorized_tools`, `roe_set_authorized_models`, `roe_set_exclusions`, `roe_set_expiry_days`, `roe_set_notes`, `roe_add_authorized_model`, `roe_remove_authorized_model` | **Draft edits** — `build`, `recon` | Mutates a draft only. Any edit to a signed doc demotes it back to draft (the signature is dropped), so the runtime keeps blocking until an operator signs again. |
| `roe_sign_current`, `roe_revoke` | **Gated** — `build` only | Fail unless `OPENHACK_ROE_MCP_ALLOW_SIGN=1` / `OPENHACK_ROE_MCP_ALLOW_REVOKE=1` is present in the MCP's environment. In `OPENHACK_ROE_MCP_STRICT=1` mode the env value must additionally match a one-use nonce at `.openhack/roe/.mcp-consent-nonce`. |

**AI-model authorization axis.** `ROEDocument.authorized_models` is a first-class field alongside `authorized_tools`, covered by the same HMAC signature. Supports exact ids (`"deepseek/deepseek-v4"`), wildcard patterns (`"anthropic/*"`), and the omnibus `"*"`. `ROE.enforceModel(roe, model)` returns the same `{ blocked, reason? }` shape as `ROE.enforce` for tools.

**Wiring** — enabled by default in `.openhack/openhack.jsonc` under `mcp.roe`. The two gate env vars are surfaced there via `{env:…}` interpolation so they only take effect when the operator sets them for that shell session.

## Combinatorial coverage & payload families (`openhack combos`)

The single-cell coverage matrix (`openhack coverage --gaps`) tells you which `endpoint × method × class` cells are still untested. The **combinatorial checklist** (`openhack combos`) closes the axes it can't:

- **Method-tuples per endpoint** — did the engagement really test `/x` against every applicable HTTP method (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD), or only whichever came up first?
- **Payload-family per (endpoint, method, class)** — a class we tested with one payload family still leaves the rest of that class's PayloadsAllTheThings families untested (SQLi tested with boolean-blind but not time-based, union, oob, polyglot, second-order, ...).
- **Chain-pair per vulnerable finding** — `Checklist.chainHints` list class pairs known to combine (SQLi↔auth, XSS↔CSRF, SSRF↔IMDS, upload↔RCE); every vulnerable A-cell whose B-cell isn't vulnerable-tested is a chain-pair gap.
- **Per-relevant-finding** — for each real Finding, walk every open combo in its neighbourhood (same endpoint × same class, same endpoint × chain-hint class, same class × other endpoints). This is the "checking algorithm per relevant finding" — a mathematical iteration, not a heuristic sample.

The algorithm is a set-difference over an explicit obligation graph:

```
universe   = discovered-endpoints × METHOD_UNIVERSE × applicable-classes × payload-families(class)
satisfied  = every (ep, m, cls, family) actually exercised in Coverage
missing    = universe \ satisfied      // this is the mathematical checklist
```

Runtime is O(n) in the coverage matrix; on 200 endpoints × 6 classes = 1200 cells it runs in < 1 ms.

### CLI

```
openhack combos --target <t> --gaps           # print all three axes
openhack combos --target <t> --methods        # only method-tuple gaps
openhack combos --target <t> --payloads       # only payload-family gaps
openhack combos --target <t> --chains         # only chain-pair gaps
openhack combos --target <t> --per-finding    # only per-finding breakdown
openhack combos --target <t> --report         # also write .openhack/checklists/<t>.md
openhack combos --target <t> --version-info   # print vendored index versions
```

### Knowledge indexes (vendored, offline by default)

Three curated JSON manifests under `packages/openhack/knowledge/`:

| Index | Source | License |
|---|---|---|
| `payloadsallthethings-index.json` | swisskyrepo/PayloadsAllTheThings | MIT |
| `hacktricks-index.json` | book.hacktricks.wiki | CC-BY-4.0 |
| `wstg-index.json` | OWASP Web Security Testing Guide | CC-BY-SA-4.0 |

They index the *taxonomy* (payload family ids, page URLs, WSTG ids) — never raw payload strings. The full payloads stay upstream. Refresh manually with:

```
bun run --cwd packages/openhack refresh:knowledge
```

The refresh script (`packages/openhack/script/ingest-knowledge.ts`) shallow-clones PayloadsAllTheThings, bumps version strings, and prints a diff of upstream categories vs. our taxonomy so unmapped categories are surfaced for hand-curation. Never runs at boot.

### Loop integration

When `graph.controller_enabled=true`, the loop driver calls `Combinations.checklist(target)` each round and hands the report to both the LLM controller (`buildUser` gets a `## Untested combinations` section) and the heuristic controller (step 4 emits `test-method-*`, `test-payload-*`, and `chain-*` ActionNodes). The `frontier_empty` termination guard is stricter: it now requires `frontier + coverage gaps + combinatorial checklist` all empty.

## Authorized Use Only

This tool is designed for authorized security assessments. Always obtain written permission before testing any target. Misuse may violate laws including the Computer Fraud and Abuse Act.
