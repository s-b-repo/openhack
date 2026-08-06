export namespace HallucinationGuard {
  const KNOWN_TOOLS = new Set([
    "nmap", "rustscan", "masscan", "amass", "subfinder", "dnsenum", "fierce",
    "nuclei", "gobuster", "dirsearch", "feroxbuster", "ffuf", "dirb", "httpx",
    "katana", "hakrawler", "sqlmap", "wpscan", "nikto", "dalfox", "wafw00f",
    "arjun", "paramspider", "hydra", "john", "hashcat", "medusa", "patator",
    "netexec", "crackmapexec", "evil-winrm", "enum4linux", "enum4linux-ng",
    "smbmap", "responder", "theharvester", "autorecon", "whatweb", "testssl",
    "sslscan", "sslyze", "gdb", "radare2", "binwalk", "ghidra", "checksec",
    "strings", "objdump", "volatility", "volatility3", "foremost", "steghide",
    "exiftool", "prowler", "scout-suite", "trivy", "kube-hunter", "kube-bench",
    "msfconsole", "msfvenom", "searchsploit", "exploitdb", "metasploit",
    "powershell", "pwsh", "python", "python3", "ruby", "perl", "php", "node",
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "telnet", "ftp",
    "tcpdump", "tshark", "wireshark", "burpsuite", "zaproxy", "caido",
    "bloodhound", "bloodhound-python", "ldapsearch", "rpcclient", "smbclient",
    "snmpwalk", "onesixtyone", "redis-cli", "mysql", "psql", "mongosh",
    "docker", "kubectl", "helm", "aws", "az", "gcloud", "git", "cargo",
    "pip", "pip3", "bun", "npm", "yarn", "pnpm", "make", "cmake", "gcc",
    "cd", "ls", "cat", "echo", "mkdir", "rm", "cp", "mv", "chmod", "chown",
    "grep", "find", "which", "whoami", "id", "uname", "ps", "top", "htop",
    "netstat", "ss", "ip", "ifconfig", "ping", "traceroute", "dig", "nslookup",
    "host", "arp", "route", "iptables", "nft", "systemctl", "journalctl",
  ])

  const VALID_NMAP_FLAGS = [
    /^-s[STUVWAPMO]$/, /^-p\s*[0-9,-]+$/, /^-T[0-5]$/, /^-O$/, /^-A$/, /^-sV$/,
    /^-sC$/, /^-Pn$/, /^-[v]+$/, /^--script/, /^--top-ports/, /^--min-rate/,
    /^--max-retries/, /^--max-rtt-timeout/, /^--host-timeout/, /^--scan-delay/,
    /^-o[ANGX]$/, /^--open$/, /^--reason$/, /^--privileged$/, /^--unprivileged$/,
    /^--source-port/, /^--data-length/, /^--ttl/, /^--spoof-mac/, /^--badsum$/,
    /^-n$/, /^-6$/, /^--packet-trace$/, /^--traceroute$/,
  ]

  const FAKE_NMAP_FLAGS = [
    "--auto-pwn", "--super-scan", "--magic", "--hack-all", "--exploit",
    "--auto-exploit", "--pwn", "--full-auto", "--aggressive-plus", "--ultra-fast",
    "--stealth-mode", "--bypass-firewall", "--ghost", "--nuke",
  ]

  const FAKE_SQLMAP_FLAGS = [
    "--auto", "--full-scan", "--deep", "--everything", "--super-dump",
    "--bypass-all", "--inject-all",
  ]

  const FAKE_NUCLEI_FLAGS = [
    "--all", "--full", "--scan-all", "--everything", "--hack",
  ]

  const FAKE_TOOLS = [
    "autohack", "superscan", "autopwn", "hacktool", "pentest-everything",
    "autoexploit", "fullhack", "instant-pwn", "megascan", "hyperexploit",
    "0day-scanner", "vuln-finder-9000", "auto-root", "instant-shell",
    "magic-exploit", "all-in-one-hack",
  ]

  interface HallucinationResult {
    hallucinated: boolean
    reason?: string
    command: string
  }

  function extractTool(command: string): string {
    return command.trim().split(/\s+/)[0].replace(/^sudo\s+/, "")
  }

  function extractFlags(command: string): string[] {
    return (command.match(/--?[a-zA-Z0-9][a-zA-Z0-9-]*/g) || []).filter((f) => f.startsWith("-"))
  }

  export function detectHallucination(command: string): HallucinationResult {
    const tool = extractTool(command)
    const flags = extractFlags(command)

    for (const fake of FAKE_TOOLS) {
      if (tool.toLowerCase().includes(fake.toLowerCase())) {
        return { hallucinated: true, reason: `Tool does not exist: ${tool}`, command }
      }
    }

    if (!KNOWN_TOOLS.has(tool) && tool.length > 1 && !tool.startsWith("./") && !tool.startsWith("/")) {
      return {
        hallucinated: true,
        reason: `Unknown tool: ${tool}. Known: nmap, sqlmap, hydra, nuclei, gobuster, msfconsole, etc.`,
        command,
      }
    }

    if (tool === "nmap") {
      for (const flag of flags) {
        if (FAKE_NMAP_FLAGS.some((f) => flag.toLowerCase().includes(f.toLowerCase()))) {
          return { hallucinated: true, reason: `Nmap does not support flag: ${flag}`, command }
        }
        if (flag.startsWith("--") && !VALID_NMAP_FLAGS.some((r) => r.test(flag))) {
          return { hallucinated: true, reason: `Unrecognized nmap flag: ${flag}`, command }
        }
      }
    }

    if (tool === "sqlmap") {
      for (const flag of flags) {
        if (FAKE_SQLMAP_FLAGS.some((f) => flag.toLowerCase().includes(f.toLowerCase()))) {
          return { hallucinated: true, reason: `sqlmap does not support flag: ${flag}`, command }
        }
      }
    }

    if (tool === "nuclei") {
      for (const flag of flags) {
        if (FAKE_NUCLEI_FLAGS.some((f) => flag.toLowerCase().includes(f.toLowerCase()))) {
          return { hallucinated: true, reason: `nuclei does not support flag: ${flag}`, command }
        }
      }
    }

    if (command.includes("\n") && command.length > 5000) {
      return { hallucinated: true, reason: "Command likely garbled (contains newlines, too long)", command }
    }

    return { hallucinated: false, command }
  }

  export class Guard {
    counter: number
    threshold: number
    flagged: HallucinationResult[]
    globalRecoveryCount: number
    maxGlobalRecoveries: number

    constructor(threshold = 3, maxGlobalRecoveries = 3) {
      this.counter = 0
      this.threshold = threshold
      this.flagged = []
      this.globalRecoveryCount = 0
      this.maxGlobalRecoveries = maxGlobalRecoveries
    }

    check(command: string): { blocked: boolean; reason?: string; shouldRecover: boolean } {
      const result = detectHallucination(command)

      if (result.hallucinated) {
        this.counter++
        this.flagged.push(result)

        if (this.counter >= this.threshold) {
          if (this.globalRecoveryCount >= this.maxGlobalRecoveries) {
            this.flagged = []
            return {
              blocked: true,
              reason: `CRITICAL: Hallucination threshold exceeded AND global recovery limit reached (${this.globalRecoveryCount}/${this.maxGlobalRecoveries}). Assessment aborted. Human intervention required.`,
              shouldRecover: false,
            }
          }

          this.globalRecoveryCount++
          this.flagged = []
          return {
            blocked: true,
            reason: `Hallucination threshold reached (${this.counter}/${this.threshold}). Global recovery #${this.globalRecoveryCount}/${this.maxGlobalRecoveries}. Triggering auto-recovery.`,
            shouldRecover: true,
          }
        }

        return {
          blocked: false,
          reason: `Possible hallucination (${this.counter}/${this.threshold}): ${result.reason}`,
          shouldRecover: false,
        }
      }

      if (this.counter > 0) {
        this.counter = Math.max(0, this.counter - 1)
      }

      return { blocked: false, shouldRecover: false }
    }

    getStats(): {
      counter: number
      threshold: number
      globalRecoveryCount: number
      maxGlobalRecoveries: number
      recentFlags: HallucinationResult[]
    } {
      return {
        counter: this.counter,
        threshold: this.threshold,
        globalRecoveryCount: this.globalRecoveryCount,
        maxGlobalRecoveries: this.maxGlobalRecoveries,
        recentFlags: this.flagged.slice(-5),
      }
    }

    reset(): void {
      this.counter = 0
      this.flagged = []
    }

    resetGlobal(): void {
      this.globalRecoveryCount = 0
      this.reset()
    }
  }

  export function createRecoveryPrompt(target: string, findings: string, tasks: string): string {
    return `You are resuming an OpenHack security assessment session that was auto-restarted.

## IMPORTANT — READ THIS FIRST
The previous session was restarted because it generated commands that do not exist
(hallucinated tools or flags). You must ONLY use commands and flags that actually exist.
If you are uncertain about a tool or flag, ASK for clarification rather than guessing.
Consult the tool's --help output if available before using unfamiliar flags.

## Previous Session
- Target: ${target || "unknown"}
- All findings are saved and accessible

## Saved Findings
${findings || "No findings recorded"}

## Remaining Tasks
${tasks || "Continue previous assessment"}

## Instructions
- Continue from where the previous session stopped
- Do NOT re-run already-completed tasks
- Verify tool flags before executing — use --help if unsure
- Save new findings immediately

Continue the assessment.`
  }
}
