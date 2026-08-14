/**
 * Code-quality guardrail. Inspects the code the AI agent is about to write (via
 * the write/edit/apply_patch tools) for well-known anti-patterns and reports
 * violations so the OpenHack plugin can block the write with actionable, framework-
 * grounded guidance — forcing the agent into a goal-directed "fix and retry" loop
 * rather than letting it silently degrade the codebase.
 *
 * Detection is line-level regex over the *introduced* text (full content for
 * `write`, the inserted fragment for `edit`, the added lines for `apply_patch`),
 * which catches the target patterns without needing to read files. Each rule cites
 * the standard it comes from (MITRE CWE, OWASP, CERT, NIST SSDF) so the block
 * message teaches rather than just refuses.
 */
export namespace Codeguard {
  export type Category =
    | "error-swallowing"
    | "suppressed-diagnostics"
    | "silent-stub"
    | "unchecked-or-secret"
    | "resource-safety"
    | "integer-overflow"
    | "input-validation"
  export type Severity = "block" | "warn"

  export interface Rule {
    id: string
    category: Category
    cwe: string
    frameworks: string[]
    languages: Set<string> | "*"
    pattern: RegExp
    severity: Severity
    /** Why the pattern is harmful. */
    message: string
    /** How to write it correctly instead. */
    fix: string
  }

  export interface Violation {
    ruleId: string
    category: Category
    cwe: string
    frameworks: string[]
    severity: Severity
    message: string
    fix: string
    line: number
    snippet: string
  }

  const LANG_BY_EXT: Record<string, string> = {
    ".py": "python",
    ".pyi": "python",
    ".ts": "ts",
    ".tsx": "ts",
    ".mts": "ts",
    ".cts": "ts",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".cxx": "c",
    ".hpp": "c",
    ".sh": "shell",
    ".bash": "shell",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
  }

  export function languageOf(filePath: string): string | null {
    const dot = filePath.lastIndexOf(".")
    if (dot < 0) return null
    return LANG_BY_EXT[filePath.slice(dot).toLowerCase()] ?? null
  }

  const JS_TS = new Set(["js", "ts"])
  const C_LIKE = new Set(["java", "csharp", "c"])

  export const RULES: Rule[] = [
    // ---- Error swallowing (CWE-390: detection of error condition without action) ----
    {
      id: "py-except-pass",
      category: "error-swallowing",
      cwe: "CWE-390",
      frameworks: ["OWASP", "CERT ERR00"],
      languages: new Set(["python"]),
      pattern: /\bexcept\b[^:\n]*:\s*(?:pass|\.\.\.)(?![\w(])/,
      severity: "block",
      message: "Bare/empty except swallows the error — failures vanish silently",
      fix: "Handle the specific exception (log with context, recover, or re-raise); never `except: pass`",
    },
    {
      id: "js-empty-catch",
      category: "error-swallowing",
      cwe: "CWE-1069",
      frameworks: ["OWASP", "Google JS style"],
      languages: JS_TS,
      pattern: /\bcatch\b\s*(?:\([^)]*\))?\s*\{\s*\}/,
      severity: "block",
      message: "Empty catch block swallows the error",
      fix: "Handle or rethrow in the catch; at minimum log the error with context",
    },
    {
      id: "js-catch-noop",
      category: "error-swallowing",
      cwe: "CWE-390",
      frameworks: ["OWASP"],
      languages: JS_TS,
      pattern: /\.catch\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*(?:\{\s*\}|null|undefined)\s*\)/,
      severity: "block",
      message: "Promise .catch handler discards the rejection",
      fix: "Handle the rejection (log/recover) or let it propagate; don't map it to null/{}",
    },
    {
      id: "go-ignore-err",
      category: "error-swallowing",
      cwe: "CWE-252",
      frameworks: ["CERT", "Effective Go"],
      languages: new Set(["go"]),
      pattern: /(?:^|[^.\w])_\s*=\s*err\b|if\s+err\s*!=\s*nil\s*\{\s*\}/,
      severity: "block",
      message: "Error assigned to _ or an empty `if err != nil {}` — the error is ignored",
      fix: "Check and handle err (wrap and return, or log); do not discard it to _",
    },
    {
      id: "java-empty-catch",
      category: "error-swallowing",
      cwe: "CWE-1069",
      frameworks: ["CERT ERR00-J", "OWASP"],
      languages: C_LIKE,
      pattern: /\bcatch\s*\([^)]*\)\s*\{\s*\}/,
      severity: "block",
      message: "Empty catch block swallows the exception",
      fix: "Log the exception with context and handle or rethrow it",
    },
    {
      id: "ruby-rescue-nil",
      category: "error-swallowing",
      cwe: "CWE-390",
      frameworks: ["OWASP"],
      languages: new Set(["ruby"]),
      pattern: /\brescue\s+nil\b|\brescue\b[^\n]*\n\s*end\b/,
      severity: "block",
      message: "`rescue nil` / empty rescue swallows the exception",
      fix: "Rescue the specific error class and handle it (log/recover/re-raise)",
    },
    {
      id: "rust-unwrap",
      category: "error-swallowing",
      cwe: "CWE-703",
      frameworks: ["Rust API guidelines"],
      languages: new Set(["rust"]),
      pattern: /\.(?:unwrap|expect)\s*\(/,
      severity: "warn",
      message: ".unwrap()/.expect() panics on Err/None instead of handling it",
      fix: "Propagate with `?` or match on the Result/Option; reserve unwrap for provably-infallible cases",
    },

    // ---- Suppressed diagnostics (silencing the tools that catch bugs) ----
    {
      id: "ts-ignore",
      category: "suppressed-diagnostics",
      cwe: "CWE-1078",
      frameworks: ["OWASP", "TypeScript guidance"],
      languages: new Set(["ts"]),
      pattern: /@ts-(?:ignore|nocheck)\b/,
      severity: "block",
      message: "@ts-ignore/@ts-nocheck hides a real type error the checker found",
      fix: "Fix the underlying type error; if truly unavoidable use @ts-expect-error with a reason",
    },
    {
      id: "eslint-disable",
      category: "suppressed-diagnostics",
      cwe: "CWE-1078",
      frameworks: ["OWASP"],
      languages: JS_TS,
      pattern: /eslint-disable(?:-next-line|-line)?\b/,
      severity: "block",
      message: "eslint-disable silences a lint rule that flagged a real issue",
      fix: "Resolve the lint finding instead of disabling the rule",
    },
    {
      id: "py-type-ignore",
      category: "suppressed-diagnostics",
      cwe: "CWE-1078",
      frameworks: ["OWASP"],
      languages: new Set(["python"]),
      pattern: /#\s*(?:type:\s*ignore|noqa)\b/,
      severity: "block",
      message: "# type: ignore / # noqa suppresses a type or lint error",
      fix: "Fix the reported issue rather than suppressing the checker",
    },
    {
      id: "go-nolint",
      category: "suppressed-diagnostics",
      cwe: "CWE-1078",
      frameworks: ["OWASP"],
      languages: new Set(["go"]),
      pattern: /\/\/\s*nolint\b/,
      severity: "block",
      message: "//nolint suppresses a linter finding",
      fix: "Address the linter finding rather than suppressing it",
    },
    {
      id: "java-suppresswarnings",
      category: "suppressed-diagnostics",
      cwe: "CWE-1078",
      frameworks: ["CERT", "OWASP"],
      languages: new Set(["java"]),
      pattern: /@SuppressWarnings\b/,
      severity: "warn",
      message: "@SuppressWarnings hides a compiler warning",
      fix: "Prefer fixing the cause; scope the suppression as narrowly as possible with a comment",
    },
    {
      id: "rust-allow",
      category: "suppressed-diagnostics",
      cwe: "CWE-1078",
      frameworks: ["OWASP"],
      languages: new Set(["rust"]),
      pattern: /#!?\[allow\(/,
      severity: "warn",
      message: "#[allow(...)] silences a compiler/clippy lint",
      fix: "Fix the lint; if intentional, scope the allow tightly with a justification",
    },

    // ---- Silent stubs / fake success ----
    {
      id: "stub-return-todo",
      category: "silent-stub",
      cwe: "CWE-1339",
      frameworks: ["NIST SSDF PW.7"],
      languages: "*",
      pattern: /\breturn\b[^\n;]*(?:true|false|null|none|nil|\{\s*\}|\[\s*\])[^\n;]*;?\s*(?:\/\/|#).*\btodo\b/i,
      severity: "block",
      message: "Stubbed return with a TODO fakes success — the feature isn't implemented",
      fix: "Implement the behavior, or fail loudly (throw/return an explicit error) so callers aren't misled",
    },
    {
      id: "py-pass-todo",
      category: "silent-stub",
      cwe: "CWE-1339",
      frameworks: ["NIST SSDF PW.7"],
      languages: new Set(["python"]),
      pattern: /\bpass\b[ \t]*#[^\n]*\btodo\b/i,
      severity: "block",
      message: "`pass  # TODO` leaves an unimplemented body that silently does nothing",
      fix: "Implement it or `raise NotImplementedError(...)` so callers get a clear signal",
    },
    {
      id: "not-implemented-throw",
      category: "silent-stub",
      cwe: "CWE-1339",
      frameworks: ["NIST SSDF"],
      languages: "*",
      pattern: /(?:throw\s+new\s+\w*Error\s*\(\s*["'][^"']*not\s+implemented|raise\s+NotImplementedError)/i,
      severity: "warn",
      message: "Not-implemented placeholder shipped — ensure this is intentional, not forgotten work",
      fix: "Implement the behavior before relying on it; a placeholder is only acceptable as an explicit TODO gate",
    },

    // ---- Unchecked results / hardcoded secrets (warn: false-positive-prone in PoCs) ----
    {
      id: "hardcoded-secret",
      category: "unchecked-or-secret",
      cwe: "CWE-798",
      frameworks: ["OWASP Top 10 A07", "OWASP ASVS"],
      languages: "*",
      pattern: /\b(?:password|passwd|pwd|api[_-]?key|secret|access[_-]?token|private[_-]?key)\s*[=:]\s*["'][^"'\s]{4,}["']/i,
      severity: "warn",
      message: "Looks like a hardcoded credential/secret in source",
      fix: "Load secrets from env/secret manager; never commit real credentials (test creds: mark with openhack-allow)",
    },
    {
      id: "aws-access-key",
      category: "unchecked-or-secret",
      cwe: "CWE-798",
      frameworks: ["OWASP", "AWS guidance"],
      languages: "*",
      pattern: /\bAKIA[0-9A-Z]{16}\b/,
      severity: "warn",
      message: "Looks like a hardcoded AWS access key ID",
      fix: "Remove it; use IAM roles or env-provided credentials",
    },
    {
      id: "private-key-block",
      category: "unchecked-or-secret",
      cwe: "CWE-798",
      frameworks: ["OWASP"],
      languages: "*",
      pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
      severity: "warn",
      message: "A private key is embedded in source",
      fix: "Store keys outside the repo (secret manager / mounted file); never commit private keys",
    },

    // ---- Resource safety / memory (CWE-120/674: overflow, OOM-adjacent) ----
    {
      id: "c-unsafe-str",
      category: "resource-safety",
      cwe: "CWE-120",
      frameworks: ["CERT STR", "MITRE CWE"],
      languages: new Set(["c"]),
      pattern: /\b(?:strcpy|strcat|gets|sprintf|vsprintf)\s*\(/,
      severity: "block",
      message: "unbounded string operation — classic buffer overflow / memory corruption",
      fix: "use the bounded variant (strncpy/strncat/snprintf/fgets) with an explicit size, or a safe string type",
    },
    {
      id: "unbounded-read",
      category: "resource-safety",
      cwe: "CWE-674",
      frameworks: ["CERT MEM", "MITRE CWE"],
      languages: "*",
      // slurp an entire stream/body into memory with no cap → OOM on hostile input
      pattern: /\.(?:readAll|ReadAll)\(\s*\)|\bread_to_string\s*\(|\bresp(?:onse)?\.read\(\s*\)/,
      severity: "warn",
      message: "reading an entire stream/response into memory with no size limit can OOM on large/hostile input",
      fix: "cap the read (max bytes) or stream in bounded chunks",
    },

    // ---- Integer overflow (CWE-190) ----
    {
      id: "c-alloc-mult",
      category: "integer-overflow",
      cwe: "CWE-190",
      frameworks: ["CERT INT/MEM", "MITRE CWE"],
      languages: new Set(["c"]),
      pattern: /\b(?:malloc|realloc|alloca)\s*\([^)]*\*[^)]*\)/,
      severity: "warn",
      message: "multiplication inside an allocation size can integer-overflow into an undersized buffer",
      fix: "use calloc(n, size), or verify n*size does not overflow before allocating",
    },

    // ---- Input validation (CWE-95/20/704) ----
    {
      id: "dynamic-eval",
      category: "input-validation",
      cwe: "CWE-95",
      frameworks: ["OWASP", "MITRE CWE"],
      languages: new Set(["js", "ts", "python"]),
      pattern: /\beval\s*\(/,
      severity: "block",
      message: "eval() executes arbitrary code — an injection sink if any input reaches it",
      fix: "parse/validate explicitly (JSON.parse, ast.literal_eval, a real parser); never eval a dynamic string",
    },
    {
      id: "py-yaml-unsafe",
      category: "input-validation",
      cwe: "CWE-20",
      frameworks: ["OWASP", "MITRE CWE"],
      languages: new Set(["python"]),
      pattern: /\byaml\.load\s*\((?![^)]*Loader\s*=)/,
      severity: "warn",
      message: "yaml.load without a safe Loader can instantiate arbitrary Python objects",
      fix: "use yaml.safe_load(...) or yaml.load(..., Loader=yaml.SafeLoader)",
    },
    {
      id: "js-parseint-radix",
      category: "input-validation",
      cwe: "CWE-704",
      frameworks: ["CERT", "MDN"],
      languages: JS_TS,
      pattern: /\bparseInt\s*\(\s*[^,)]+\)/,
      severity: "warn",
      message: "parseInt without a radix mis-parses some inputs (e.g. leading zeros / '0x')",
      fix: "pass a radix — parseInt(x, 10) — or use Number()/BigInt with explicit validation",
    },
  ]

  /** Rule ids the author explicitly waived via an `openhack-allow:` comment in the text. */
  function allowed(text: string): { all: boolean; ids: Set<string> } {
    const ids = new Set<string>()
    let all = false
    const re = /openhack-allow:?[ \t]*([a-z0-9,\- ]*)/gi
    let m: RegExpExecArray | null
    while ((m = re.exec(text))) {
      const list = (m[1] || "").trim().toLowerCase()
      if (!list || list === "all") all = true
      else for (const id of list.split(/[,\s]+/)) if (id) ids.add(id)
    }
    return { all, ids }
  }

  /** Inspect introduced text for anti-patterns applicable to the file's language. */
  export function inspect(filePath: string, addedText: string): Violation[] {
    const lang = languageOf(filePath)
    if (!lang || !addedText) return []
    const waived = allowed(addedText)
    if (waived.all) return []

    const out: Violation[] = []
    for (const rule of RULES) {
      if (rule.languages !== "*" && !rule.languages.has(lang)) continue
      if (waived.ids.has(rule.id)) continue
      const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g"
      const re = new RegExp(rule.pattern.source, flags)
      let m: RegExpExecArray | null
      while ((m = re.exec(addedText))) {
        out.push({
          ruleId: rule.id,
          category: rule.category,
          cwe: rule.cwe,
          frameworks: rule.frameworks,
          severity: rule.severity,
          message: rule.message,
          fix: rule.fix,
          line: addedText.slice(0, m.index).split("\n").length,
          snippet: m[0].replace(/\s+/g, " ").trim().slice(0, 100),
        })
        if (m.index === re.lastIndex) re.lastIndex++ // guard against zero-width matches
      }
    }
    return out
  }

  /** Extract the file path + introduced text from a file-mutation tool call. */
  export function extractContent(tool: string, args: Record<string, unknown>): { filePath: string; text: string } | null {
    if (tool === "write" && typeof args["filePath"] === "string" && typeof args["content"] === "string") {
      return { filePath: args["filePath"], text: args["content"] }
    }
    if (tool === "edit" && typeof args["filePath"] === "string" && typeof args["newString"] === "string") {
      return { filePath: args["filePath"], text: args["newString"] }
    }
    if (tool === "apply_patch" && typeof args["patchText"] === "string") {
      const patch = args["patchText"]
      return { filePath: patchPrimaryPath(patch), text: addedLines(patch) }
    }
    return null
  }

  /** First file path referenced by a patch (openhack `*** ... File:` or unified `+++ b/`). */
  function patchPrimaryPath(patch: string): string {
    const oh = patch.match(/\*\*\*\s+(?:Add|Update|Delete|Move)\s+File:\s*(.+)/i)
    if (oh) return oh[1].trim()
    const unified = patch.match(/^\+\+\+\s+(?:b\/)?(.+)$/m)
    if (unified) return unified[1].trim()
    return ""
  }

  /** Added ('+') content lines of a patch, excluding the '+++' file header. */
  function addedLines(patch: string): string {
    return patch
      .split("\n")
      .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
      .map((l) => l.slice(1))
      .join("\n")
  }

  /** Render blocking violations into an educational, retry-oriented tool error. */
  export function formatBlock(filePath: string, violations: Violation[]): string {
    const lines = [
      `CODE-QUALITY BLOCKED: ${violations.length} issue(s) in ${filePath} must be fixed before this write is allowed.`,
      "",
    ]
    for (const v of violations) {
      lines.push(`• [${v.ruleId}] ${v.message} (${v.cwe}; ${v.frameworks.join(", ")})`)
      lines.push(`    line ${v.line}: ${v.snippet}`)
      lines.push(`    fix: ${v.fix}`)
    }
    lines.push("")
    lines.push(
      "Rewrite the code to resolve every issue above, then retry — do not work around the check. " +
        'If a match is a genuine false positive, add a comment "openhack-allow: <rule-id>" on/near that line.',
    )
    return lines.join("\n")
  }

  /** Render warn-level violations for a non-blocking note on the tool result. */
  export function formatWarnings(filePath: string, violations: Violation[]): string {
    const lines = [`⚠ OpenHack code-quality notes for ${filePath} (not blocking, but please review):`]
    for (const v of violations) {
      lines.push(`  • [${v.ruleId}] ${v.message} (${v.cwe}) — ${v.fix}`)
    }
    return lines.join("\n")
  }

  /**
   * System-prompt guidance telling the agent the standards it is held to, so it
   * writes conforming code up front instead of discovering the guardrail by
   * getting blocked. Grounded in the same frameworks the rules cite.
   */
  export const SYSTEM_GUIDANCE = `## Code quality & security standards (enforced at write time)
A runtime guardrail inspects every file you write; code containing these patterns is BLOCKED, so write it correctly the first time:
- Never swallow errors (CWE-390/703): no bare \`except: pass\`, empty \`catch {}\`, \`.catch(() => null)\`, \`_ = err\`, or \`rescue nil\`. Handle with context, recover, or propagate.
- Never suppress the tools that catch bugs (CWE-1078): no \`@ts-ignore\`/\`@ts-nocheck\`, \`eslint-disable\`, \`# type: ignore\`/\`# noqa\`, or \`//nolint\`. Fix the underlying issue instead.
- No silent stubs or fake success (CWE-1339): implement the behavior or fail loudly (throw / return an explicit error); never \`return true // TODO\`.
- No hardcoded secrets (CWE-798): load credentials from the environment or a secret manager.
- Resource safety (CWE-120/674): no unbounded C string ops (strcpy/strcat/gets/sprintf); do not read an entire stream/response into memory without a size cap (OOM). Use bounded ops + streaming.
- No integer overflow in sizing (CWE-190): don't multiply inside malloc/realloc; use calloc or check for overflow.
- Validate input (CWE-20/95/704): no \`eval\` on dynamic input, no \`yaml.load\` without a safe Loader, no \`parseInt\` without a radix. Parse/validate explicitly.
These distill MITRE CWE, OWASP (Top 10 / ASVS / LLM Top 10), NIST SSDF (SP 800-218), CERT secure-coding standards, and vendor guidance (Anthropic, Google SAIF, Microsoft SDL). If a match is a genuine false positive, waive it with a nearby \`openhack-allow: <rule-id>\` comment — do not restructure code just to evade the check.`
}
