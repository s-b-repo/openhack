/**
 * Shell command safety hook — the single source of truth for the OpenHack
 * safety harness. Both the interactive shell tool and the `Safety` middleware
 * import their block/warning patterns from here so that enforcement stays
 * consistent across every code path.
 *
 * Kept dependency-free on purpose: it is imported by hot paths and exercised
 * directly by CI, so it must remain trivially bundleable and side-effect free.
 */

export interface CommandPattern {
  pattern: RegExp
  reason: string
}

/**
 * Commands that are blocked outright — irreversible data loss, host takedown,
 * or untrusted remote code execution. These are never appropriate during an
 * authorized assessment and are refused even with a signed ROE.
 */
export const DESTRUCTIVE_PATTERNS: CommandPattern[] = [
  { pattern: /sudo\s+rm\s+-rf\s+(\/|\*|~\s|\$HOME)/, reason: "Destructive recursive delete on root/home directory" },
  { pattern: /rm\s+-rf\s+\/(\*|\s)/, reason: "Destructive recursive delete on root filesystem" },
  { pattern: /rm\s+-rf\s+~(\/|\s|$)/, reason: "Destructive recursive delete on home directory" },
  { pattern: /dd\s+if=\/dev\/(zero|random|urandom)\s+of=\/dev\/sd[a-z]+/, reason: "Writing raw data to disk device" },
  { pattern: /dd\s+if=\/dev\/(zero|random|urandom)\s+of=\/dev\/nvme/, reason: "Writing raw data to NVMe device" },
  { pattern: /mkfs\.\w+\s+\/dev\//, reason: "Creating filesystem on device - data destruction" },
  { pattern: /chmod\s+-R\s+777\s+\//, reason: "Recursive world-writable permissions on root" },
  { pattern: /chown\s+-R\s+\S+\s+\//, reason: "Recursive ownership change on root" },
  { pattern: /:\s*\(\)\s*{\s*:\s*\|\s*:\s*&\s*}\s*;\s*:/, reason: "Classic bash fork bomb" },
  { pattern: /:\(\)\s*\{/, reason: "Fork bomb pattern detected" },
  { pattern: /while\s*:\s*;.*do.*done/, reason: "Infinite while loop - potential fork bomb" },
  { pattern: /curl\s+.*\|\s*(ba)?sh/, reason: "Curl-to-shell pipe - untrusted execution" },
  { pattern: /wget\s+.*\|\s*(ba)?sh/, reason: "Wget-to-shell pipe - untrusted execution" },
  { pattern: /sudo\s+su\b/, reason: "Privilege escalation to root shell" },
  { pattern: /visudo.*NOPASSWD.*ALL/, reason: "Modifying sudoers for passwordless root" },
  { pattern: /shutdown\s+-[rh].*now/, reason: "System shutdown command" },
  { pattern: /systemctl\s+(halt|poweroff|reboot|shutdown)/, reason: "System control shutdown command" },
  { pattern: /init\s+[06]/, reason: "System runlevel change (shutdown/reboot)" },
]

/**
 * Commands that are allowed to run but surface a warning — recoverable but
 * risky operations the operator should double-check before proceeding.
 */
export const WARNING_PATTERNS: CommandPattern[] = [
  { pattern: /rm\s+-rf\b/, reason: "Recursive force delete - may cause data loss" },
  { pattern: /dd\s+if=/, reason: "Raw disk operation - may cause data loss" },
  { pattern: /iptables\s+-F/, reason: "Flushing firewall rules - may disrupt network" },
  { pattern: /kill\s+-9\s+-1/, reason: "Killing all processes - will crash the system" },
  { pattern: /killall/, reason: "Killing processes by name - may disrupt services" },
]

export interface ShellInspection {
  /** True when the command matches a destructive pattern and must be refused. */
  blocked: boolean
  /** Human-readable explanation of the block, present when `blocked` is true. */
  reason?: string
  /** The source of the matched destructive pattern, for auditing. */
  pattern?: string
  /** Non-blocking warnings for risky-but-recoverable commands. */
  warnings: string[]
}

/**
 * Normalize a command before pattern matching so trivial obfuscation cannot slip
 * a destructive command past the harness:
 *  - strip `#` comments (which can push the dangerous token out of a pattern),
 *  - drop quotes / backslash escapes used to break up a binary name (`r''m`, `\rm`),
 *  - collapse runs of whitespace,
 *  - append a trailing space so a command ending in the target (e.g. `rm -rf /`)
 *    still satisfies patterns that expect a whitespace terminator.
 */
export function normalizeCommand(command: string): string {
  return (
    command
      .replace(/#.*$/gm, " ")
      .replace(/['"`\\]/g, "")
      .replace(/\s+/g, " ")
      .trim() + " "
  )
}

/**
 * Inspect a shell command against the safety harness. Returns whether the
 * command should be blocked plus any non-blocking warnings. Pure and
 * synchronous so it can be called from any context (tool, middleware, CI).
 * Matches against both the raw and the normalized command so obfuscated
 * destructive commands are still caught.
 */
export function inspectShellCommand(command: string): ShellInspection {
  const trimmed = command.trim()
  const normalized = normalizeCommand(command)

  for (const { pattern, reason } of DESTRUCTIVE_PATTERNS) {
    if (pattern.test(normalized) || pattern.test(trimmed)) {
      return { blocked: true, reason, pattern: pattern.source, warnings: [] }
    }
  }

  const warnings = WARNING_PATTERNS.filter(
    ({ pattern }) => pattern.test(normalized) || pattern.test(trimmed),
  ).map(({ reason }) => reason)
  return { blocked: false, warnings }
}
