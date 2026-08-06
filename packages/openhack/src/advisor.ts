import { loadJSON, saveJSON } from "./persist"

export namespace Advisor {
  export interface Advice {
    level: "tip" | "warn" | "error" | "alt"
    message: string
    apply?: string
  }

  interface ToolKnowledge {
    tips: Array<{ trigger: RegExp; advice: string | ((command: string) => string) }>
    warnings: Array<{ trigger: RegExp; advice: string }>
    alternatives: Array<{ trigger: RegExp; alt: string }>
    errors: Array<{ trigger: RegExp; advice: string }>
  }

  const KNOWLEDGE_BASE: Record<string, ToolKnowledge> = {
    nmap: {
      tips: [
        { trigger: /^nmap\s+(?!.*-s[CV]\b)(?!.*\b-sV\b)/, advice: "Add -sV for service version detection" },
        { trigger: /^nmap\s+(?!.*-T\d)/, advice: "Use -T4 for faster scanning on local networks" },
        { trigger: /^nmap\s+(?!.*-Pn)(?!.*-sn)/, advice: "Add -Pn to skip host discovery on known hosts" },
        { trigger: /^nmap\s+(?!.*--max-retries)/, advice: "Set --max-retries 2 to avoid hanging" },
        { trigger: /-p\s+80,443\s+(?!.*--script)/, advice: "Add --script http-* for web service enumeration" },
        { trigger: /-p\s+(\d+)-(\d+)/, advice: (m: string) => m.includes("1-65535") ? "" : "Use --top-ports for common services first" },
        { trigger: /(?!.*-o[ANGX])/, advice: "Save output with -oN scan.txt for audit trail" },
      ],
      warnings: [
        { trigger: /-T5.*-p\s+1-65535/, advice: "Aggressive full-port scan will be very noisy — may trigger IDS" },
        { trigger: /-sS\s+(?!.*-Pn)/, advice: "SYN scan without -Pn may miss filtered hosts" },
        { trigger: /--script\s+default\s+-p\s+1-65535/, advice: "Running NSE scripts on all ports will take extremely long" },
      ],
      alternatives: [
        { trigger: /-p\s+1-65535/, alt: "rustscan -p 1-65535 (3-5x faster for port discovery)" },
        { trigger: /-sV\s+--script/, alt: "Try masscan for initial port scan, then nmap -sV -sC on found ports" },
      ],
      errors: [
        { trigger: /-s[IJKLQR]/, advice: "Invalid scan type. Use -sS (SYN), -sT (TCP), -sU (UDP), -sV (version). -sX (Xmas), -sY (SCTP), -sZ (SCTP Cookie) are also valid but specialized" },
      ],
    },
    sqlmap: {
      tips: [
        { trigger: /sqlmap\s+(?!.*--batch)/, advice: "Use --batch for non-interactive mode" },
        { trigger: /sqlmap\s+(?!.*--random-agent)/, advice: "Add --random-agent to avoid WAF detection" },
        { trigger: /sqlmap\s+(?!.*--level)/, advice: "Use --level=3 for thorough testing (default is 1)" },
        { trigger: /sqlmap\s+(?!.*--risk)/, advice: "Use --risk=2 for more thorough tests" },
        { trigger: /--url\s+(?!.*--dbs)/, advice: "Start with --dbs to enumerate databases before dumping" },
      ],
      warnings: [
        { trigger: /--os-shell/, advice: "--os-shell is extremely aggressive — confirm ROE allows it" },
        { trigger: /--dump-all/, advice: "--dump-all extracts ALL data — use --dump -D dbname -T tablename instead" },
      ],
      alternatives: [
        { trigger: /sqlmap\s+--url/, alt: "Try manual SQLi first with ' OR 1=1-- to confirm injection exists" },
      ],
      errors: [
        { trigger: /--url[=\s]+["\s]*(?!https?:\/\/)/, advice: "URL must start with http:// or https://" },
      ],
    },
    gobuster: {
      tips: [
        { trigger: /gobuster\s+dir\s+(?!.*-w)/, advice: "Specify wordlist with -w /usr/share/wordlists/dirb/common.txt" },
        { trigger: /gobuster\s+dir\s+(?!.*-x)/, advice: "Add -x php,html,txt to check for extensions" },
        { trigger: /gobuster\s+(?!.*-t)/, advice: "Use -t 50 for faster scanning (default 10 threads)" },
      ],
      warnings: [
        { trigger: /-t\s*1\d{2}/, advice: "High thread count may overwhelm target or trigger rate limiting" },
        { trigger: /-w\s+\/usr\/share\/wordlists\/dirbuster\/directory-list-2\.3-medium\.txt/, advice: "Started with a large wordlist — common.txt is faster for initial scan" },
      ],
      alternatives: [
        { trigger: /gobuster\s+dir/, alt: "Try feroxbuster for recursive directory scanning with --recursive" },
        { trigger: /gobuster\s+dns/, alt: "Use subfinder or amass for subdomain enumeration instead" },
      ],
      errors: [],
    },
    hydra: {
      tips: [
        { trigger: /hydra\s+-l\s+(?!.*-P)/, advice: "Specify password list with -P /path/to/wordlist.txt" },
        { trigger: /hydra\s+(?!.*-t)/, advice: "Use -t 4 for SSH (fewer connections to avoid lockouts)" },
        { trigger: /hydra\s+.*-V/, advice: "Remove -V in production — it logs every attempt to stdout" },
      ],
      warnings: [
        { trigger: /-t\s*2\d+/, advice: "High thread count may lock out accounts — use -t 4 for SSH/remote services" },
        { trigger: /ssh:\/\//, advice: "SSH brute force triggers alerts on most IDS — ensure ROE covers this" },
      ],
      alternatives: [
        { trigger: /hydra\s+-l.*ssh/, alt: "Consider using SSH key-based auth testing or patator for more control" },
      ],
      errors: [],
    },
    msfvenom: {
      tips: [
        { trigger: /msfvenom\s+(?!.*-f)/, advice: "Specify output format with -f exe,elf,python,etc." },
        { trigger: /msfvenom\s+(?!.*-o)/, advice: "Set output file with -o payload.exe" },
      ],
      warnings: [
        { trigger: /windows\/meterpreter\/reverse_tcp/, advice: "Meterpreter is heavily signatured — use -e x86/xor_dynamic or custom stager with encryption" },
      ],
      alternatives: [],
      errors: [
        { trigger: /msfvenom\s+-p\s+(?!.*LHOST)/, advice: "Missing LHOST — reverse shell needs your IP. Use LHOST=<your-ip>" },
      ],
    },
    nuclei: {
      tips: [
        { trigger: /nuclei\s+(?!.*-t)/, advice: "Specify template(s) with -t /path/to/templates/" },
        { trigger: /nuclei\s+(?!.*-severity)/, advice: "Filter by severity: -severity critical,high" },
        { trigger: /nuclei\s+(?!.*-rl)/, advice: "Set rate limit with -rl 10 to avoid overwhelming target" },
      ],
      warnings: [],
      alternatives: [
        { trigger: /nuclei\s+-u/, alt: "Use -l targets.txt for batch scanning multiple URLs" },
      ],
      errors: [],
    },
    ssh: {
      tips: [
        { trigger: /^ssh\s+(?!.*-o StrictHostKeyChecking)/, advice: "Add -o StrictHostKeyChecking=no for automation" },
        { trigger: /^ssh\s+(?!.*-o UserKnownHostsFile)/, advice: "Add -o UserKnownHostsFile=/dev/null to avoid host key prompts" },
      ],
      warnings: [
        { trigger: /^ssh\s+root@/, advice: "Direct root SSH is blocked on most systems — try a regular user first" },
      ],
      alternatives: [],
      errors: [],
    },
    curl: {
      tips: [
        { trigger: /curl\s+(?!.*-s)/, advice: "Use -s for silent mode (no progress bar)" },
        { trigger: /curl\s+(?!.*-k)/, advice: "Add -k to ignore SSL cert errors (testing only)" },
      ],
      warnings: [
        { trigger: /curl\s+.*\|\s*(ba)?sh/, advice: "Piping curl to bash is BLOCKED by safety harness. Use wget && bash instead." },
      ],
      alternatives: [],
      errors: [],
    },
    wpscan: {
      tips: [
        { trigger: /wpscan\s+(?!.*--enumerate)/, advice: "Use --enumerate u,p,t for users, plugins, and themes" },
        { trigger: /wpscan\s+(?!.*--api-token)/, advice: "Get a free API token from wpscan.com for vulnerability data" },
      ],
      warnings: [],
      alternatives: [],
      errors: [],
    },
    chmod: {
      tips: [
        { trigger: /chmod\s+(?!.*\+x)/, advice: "Use chmod +x to make scripts executable" },
      ],
      warnings: [
        { trigger: /chmod\s+777/, advice: "777 gives write access to ALL users — use 755 or 644 instead" },
        { trigger: /chmod\s+-R\s+777/, advice: "Recursive 777 is dangerous — restricts to specific files only" },
      ],
      alternatives: [],
      errors: [],
    },
    rm: {
      warnings: [
        { trigger: /rm\s+-rf\s+\//, advice: "BLOCKED by safety harness — cannot delete root filesystem" },
        { trigger: /rm\s+-rf\s+(?!\/tmp)/, advice: "Use rm -rf with caution — no undo. Consider mv to /tmp first" },
      ],
      tips: [],
      alternatives: [],
      errors: [],
    },
    masscan: {
      tips: [
        { trigger: /masscan\s+(?!.*--rate)/, advice: "Set --rate 1000 to control scan speed (default unlimited)" },
        { trigger: /masscan\s+(?!.*-p)/, advice: "Specify ports with -p80,443,8000-9000" },
      ],
      warnings: [
        { trigger: /--rate\s*\d{5,}/, advice: "Very high rate may crash local network equipment" },
        { trigger: /0\.0\.0\.0\/0/, advice: "Internet-wide scan — ensure you have ISP permission" },
      ],
      alternatives: [
        { trigger: /masscan\s+/, alt: "For smaller ranges, nmap -sS is more thorough" },
      ],
      errors: [
        { trigger: /masscan\s+(?!.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/, advice: "Missing target IP — masscan requires an IP range" },
      ],
    },
    rustscan: {
      tips: [
        { trigger: /rustscan\s+(?!.*-b)/, advice: "Use -b 2000 for batch size (higher = faster)" },
        { trigger: /rustscan\s+(?!.*-t)/, advice: "Use -t 2000 for timeout in ms" },
      ],
      warnings: [
        { trigger: /-b\s*\d{5,}/, advice: "High batch size may overwhelm target or local network" },
      ],
      alternatives: [
        { trigger: /rustscan\s+/, alt: "For deep service scanning, pipe to nmap: rustscan -a IP -- -A -sV" },
      ],
      errors: [],
    },
    ffuf: {
      tips: [
        { trigger: /ffuf\s+(?!.*-w)/, advice: "Specify wordlist with -w /path/to/wordlist" },
        { trigger: /ffuf\s+(?!.*-u)/, advice: "Specify URL with FUZZ placeholder: -u http://target/FUZZ" },
        { trigger: /ffuf\s+(?!.*-t)/, advice: "Use -t 50 for faster scanning" },
        { trigger: /ffuf\s+(?!.*-fc)/, advice: "Filter status codes: -fc 403,404 to hide noise" },
      ],
      warnings: [
        { trigger: /-t\s*\d{3,}/, advice: "High thread count may crash target — start with -t 20" },
      ],
      alternatives: [
        { trigger: /ffuf\s+/, alt: "For recursive scanning, try feroxbuster with --recursive" },
      ],
      errors: [
        { trigger: /ffuf\s+-u\s+(?!.*FUZZ)/, advice: "URL must contain FUZZ keyword: -u http://target/FUZZ" },
      ],
    },
    dirsearch: {
      tips: [
        { trigger: /dirsearch\s+(?!.*-u)/, advice: "Specify URL with -u http://target" },
        { trigger: /dirsearch\s+(?!.*-e)/, advice: "Add -e php,html,js for extension checks" },
        { trigger: /dirsearch\s+(?!.*-t)/, advice: "Use -t 30 for faster results" },
      ],
      warnings: [],
      alternatives: [],
      errors: [],
    },
    john: {
      tips: [
        { trigger: /john\s+(?!.*--wordlist)/, advice: "Specify wordlist with --wordlist=/path/to/rockyou.txt" },
        { trigger: /john\s+(?!.*--format)/, advice: "Specify hash format: --format=raw-md5, --format=NT, etc." },
      ],
      warnings: [
        { trigger: /john\s+(?!.*(?:--wordlist|--incremental|--single))/, advice: "No wordlist or attack mode specified — john will run very slow single-crack mode" },
      ],
      alternatives: [
        { trigger: /john\s+/, alt: "For GPU-accelerated cracking, use hashcat instead" },
      ],
      errors: [],
    },
    hashcat: {
      tips: [
        { trigger: /hashcat\s+(?!.*-m)/, advice: "Specify hash type: -m 0 for MD5, -m 1000 for NTLM, -m 3200 for bcrypt" },
        { trigger: /hashcat\s+(?!.*-a)/, advice: "Set attack mode: -a 0 (straight/wordlist), -a 3 (mask/brute)" },
        { trigger: /hashcat\s+-a\s+3\s+(?!.*-i)/, advice: "Use -i for increment mode on brute force attacks" },
        { trigger: /hashcat\s+(?!.*-O)/, advice: "Use -O for optimized kernels (faster, but limits password length to 32)" },
      ],
      warnings: [
        { trigger: /hashcat\s+-a\s+3\s+(?!.*-i)/, advice: "Brute force without -i will try all lengths — potentially huge keyspace" },
      ],
      alternatives: [],
      errors: [
        { trigger: /hashcat\s+(?!.*-m)/, advice: "Missing hash type (-m). Use 'hashcat --help' for types" },
      ],
    },
    nc: {
      tips: [
        { trigger: /nc\s+-lvnp/, advice: "Adding all flags: -l (listen), -v (verbose), -n (no DNS), -p (port)" },
      ],
      warnings: [
        { trigger: /nc\s+-e/, advice: "-e is the 'execute' flag — only use on authorized shell access testing" },
      ],
      alternatives: [
        { trigger: /nc\s+-e/, alt: "Modern netcat builds may not support -e. Use ncat or socat instead" },
      ],
      errors: [],
    },
    tcpdump: {
      tips: [
        { trigger: /tcpdump\s+(?!.*-w)/, advice: "Save capture to file with -w capture.pcap" },
        { trigger: /tcpdump\s+(?!.*-i)/, advice: "Specify interface with -i eth0 (use -i any for all)" },
        { trigger: /tcpdump\s+(?!.*-c)/, advice: "Limit packet count with -c 100 to avoid filling disk" },
      ],
      warnings: [
        { trigger: /tcpdump\s+(?!.*-c)(?!.*-w)/, advice: "No capture limit or output file — may fill terminal or disk" },
      ],
      alternatives: [],
      errors: [],
    },
    nikto: {
      tips: [
        { trigger: /nikto\s+(?!.*-h)/, advice: "Specify host with -h http://target.com" },
        { trigger: /nikto\s+(?!.*-Tuning)/, advice: "Use -Tuning 1,2,3,etc. to focus on specific test types" },
      ],
      warnings: [
        { trigger: /nikto\s+(?!.*-Tuning)/, advice: "Full scan is VERY noisy — use -Tuning to limit test scope" },
      ],
      alternatives: [],
      errors: [],
    },
    enum4linux: {
      tips: [
        { trigger: /enum4linux\s+(?!.*-a)/, advice: "Use -a for comprehensive enum (users, shares, groups, policies)" },
      ],
      warnings: [],
      alternatives: [
        { trigger: /enum4linux\s+/, alt: "Try enum4linux-ng for faster, more modern SMB enumeration" },
      ],
      errors: [],
    },
    impacket: {
      tips: [
        { trigger: /GetUserSPNs/, advice: "Use impacket-GetUserSPNs -request for Kerberoastable accounts" },
        { trigger: /secretsdump/, advice: "Use impacket-secretsdump for SAM/SECURITY/SYSTEM hash extraction" },
        { trigger: /psexec/, advice: "impacket-psexec requires admin credentials on the target" },
      ],
      warnings: [
        { trigger: /secretsdump/, advice: "secretsdump creates heavy traffic — run during off-hours if on production" },
      ],
      alternatives: [],
      errors: [],
    },
    responder: {
      tips: [
        { trigger: /responder\s+(?!.*-I)/, advice: "Specify interface with -I eth0" },
      ],
      warnings: [
        { trigger: /responder\s+-A/, advice: "Analyze mode shows potential targets but doesn't poison — use for initial recon" },
        { trigger: /responder\s+/, advice: "Responder poisons LLMNR/NBT-NS — ensure target network has these protocols active" },
      ],
      alternatives: [],
      errors: [],
    },
    netexec: {
      tips: [
        { trigger: /netexec\s+(?!.*--local-auth)/, advice: "Use --local-auth for local account testing vs domain" },
        { trigger: /netexec\s+smb/, advice: "netexec smb is the successor to crackmapexec — same syntax, more features" },
      ],
      warnings: [],
      alternatives: [],
      errors: [],
    },
    msfconsole: {
      tips: [
        { trigger: /msfconsole\s+(?!.*-q)/, advice: "Use -q for quiet mode (no banner)" },
        { trigger: /msfconsole\s+(?!.*-x)/, advice: "Use -x 'commands' to auto-run commands on startup" },
        { trigger: /msfconsole\s+(?!.*-r)/, advice: "Use -r script.rc to auto-run a resource script" },
      ],
      warnings: [
        { trigger: /msfconsole\s+/, advice: "Metasploit has heavy signature — consider custom tooling for stealth ops" },
      ],
      alternatives: [],
      errors: [],
    },
    mcp: {
      tips: [
        { trigger: /.*/, advice: "MCP tool detected. MCP servers provide structured output and auto-logging. For fine-grained control or stealth, use the underlying bash command instead." },
        { trigger: /hexstrike_nmap_scan/, advice: "hexstrike wraps nmap behind an HTTP API. Large scan output may be truncated. For verbose output, use bash nmap with -oN" },
        { trigger: /ptai_run_probe/, advice: "ptai probes produce VERIFIED findings with replayable proof capsules — zero false positives by design" },
        { trigger: /sr_finding_create/, advice: "Map findings to CWE and set cvss_score for professional reports. Descriptions <80 chars look unprofessional." },
        { trigger: /arcticfox_/, advice: "ArcticFox is for C2 operations with heartbeat monitoring and command queuing" },
        { trigger: /rustsploit_/, advice: "rustsploit is a native Rust framework — use setg for global options, workspace isolation per engagement" },
      ],
      warnings: [
        { trigger: /MCP.*tool.*fail|EADDRINUSE|ECONNREFUSED/, advice: "MCP server connection failed. Check: openhack status, or the server's health endpoint" },
        { trigger: /hexstrike_nmap_scan/, advice: "hexstrike tools use intelligent caching — repeated scans may return cached results. Use --no-cache for fresh data" },
        { trigger: /ptai_start_engagement/, advice: "ptai standalone CLI hits PTAI_PRICE_LIMIT ($10). On MCP path (Claude Code/Cursor), your existing subscription covers LLM cost" },
        { trigger: /sr_report_generate.*html/i, advice: "HTML reports are for internal preview only. Use PDF format for client deliverables" },
        { trigger: /arcticfox_agent_deploy/, advice: "C2 agent deployment leaves persistent artifacts. Ensure cleanup agent runs after engagement" },
        { trigger: /rustsploit_run_module/, advice: "rustsploit modules run natively (no external tool wrappers). If a module fails, the underlying protocol handler may be unavailable" },
      ],
      alternatives: [
        { trigger: /hexstrike_nmap_scan/, alt: "nmap -sV -sC -oN scan.txt <target> (direct bash for full output)" },
        { trigger: /ptai_run_probe/, alt: "Run the individual tool: sqlmap --batch --url <target> or dalfox url <target>" },
        { trigger: /sr_finding_create/, alt: "Save locally as markdown: echo '## Finding: XSS' >> .openhack/reports/draft.md" },
        { trigger: /sr_report_generate/, alt: "Generate manual markdown report in .openhack/reports/ with pandoc for PDF conversion" },
        { trigger: /arcticfox_agent_deploy/, alt: "msfvenom + custom listener (lower-level, stealthier, harder to signature)" },
        { trigger: /rustsploit_run_module/, alt: "For network ops, try nmap directly; for exploits, check metasploit or manual PoC" },
      ],
      errors: [
        { trigger: /hexstrike.*EADDRINUSE|port.*8899/, advice: "HexStrike server port conflict (8899). Kill existing process or change port in config" },
        { trigger: /ptai.*api.*key|openai|anthropic/, advice: "No API key needed on MCP path. If on standalone CLI, set ANTHROPIC_API_KEY or OPENAI_API_KEY" },
        { trigger: /sr_.*SYSREPTOR/, advice: "SysReptor MCP server not running. Check SYSREPTOR_URL and SYSREPTOR_TOKEN env vars" },
        { trigger: /arcticfox.*fail/, advice: "ArcticFox agent unreachable. Check implant heartbeat and dead-drop resolution" },
        { trigger: /rustsploit.*cargo|build/, advice: `rustsploit binary not found. Build with: cd ${process.env.RUSTSPLOIT_PATH || "~/rustsploit"} && cargo build --release` },
      ],
    },
    mcp_vs_bash: {
      tips: [
        { trigger: /automate|workflow|pipeline|batch/, advice: "For automated workflows, use MCP tools — structured output that chains programmatically via the Orchestrator" },
        { trigger: /stealth|quiet|covert|evade/, advice: "For stealth operations, prefer bash over MCP — MCP servers add HTTP API overhead, timing patterns, detection surface" },
        { trigger: /quick|fast|one-off/, advice: "For quick checks, bash is faster — no MCP server startup, no JSON serialization. Save MCP for structured workflows" },
        { trigger: /audit|compliance|deliverable|client report/, advice: "For regulated engagements needing audit trails, prefer MCP — all calls logged with timestamps and ROE validation" },
        { trigger: /large|massive|thousands|full port/i, advice: "Large-scale ops (full port scans, brute-force with big wordlists) work better in bash — MCP output often truncated through JSON relay" },
      ],
      warnings: [],
      alternatives: [],
      errors: [],
    },
    rustsploit: {
      tips: [
        { trigger: /setg\s+(?!concurrency)/, advice: "Set global options before scanning: setg concurrency 50, timeout 30, save_results y" },
        { trigger: /use\s+(?!.*\/)/, advice: "Module path format: category/module (e.g., scanners/port_scanner, exploits/ssh/openssh_regresshion)" },
        { trigger: /run\s+(?!.*-j)/, advice: "Use run -j for background jobs on mass scans. Poll with jobs list" },
        { trigger: /mass|subnet|range|CIDR/, advice: "For mass scans: setg exclusions 10.0.0.0/8 first, use CIDR targets, set background:true" },
        { trigger: /(?!.*prescan)/, advice: "Set prescan auto before CIDR scans to pre-filter alive hosts" },
        { trigger: /creds\s+add/, advice: "Stored credentials persist across sessions in ~/.rustsploit/creds.json — use creds add host:port user pass" },
        { trigger: /workspace\s+switch/, advice: "Use workspace isolation per engagement: workspace add <name>, workspace switch <name>" },
      ],
      warnings: [
        { trigger: /t\s+0\.0\.0\.0(?!\/)/, advice: "Bare 0.0.0.0 is treated as a single host. Use 0.0.0.0/0 for mass scan" },
        { trigger: /run\s+exploit.*(?!check)/, advice: "Prefer check() first for exploits with probe-only support — safer than blind run()" },
        { trigger: /bruteforce|brute/, advice: "Use enablebruteforce to raise fd limits. Set concurrency limits to avoid lockouts" },
      ],
      alternatives: [
        { trigger: /rustsploit_run_module/, alt: "Equivalent in MCP: rustsploit_list_modules → rustsploit_set_target → rustsploit_run_module" },
        { trigger: /rustsploit.*down|unavailable/, alt: "rustsploit down? Use bash nmap + hydra + searchsploit as fallback. Export workspace data first with rustsploit_export_data" },
      ],
      errors: [],
    },
    sysreptor: {
      tips: [
        { trigger: /sr_project_create(?!.*client_name)/, advice: "Always set client_name — projects without it are hard to locate in a large engagement history" },
        { trigger: /sr_finding_create(?!.*cwe)/, advice: "Map finding to CWE (CWE-89 for SQLi, CWE-79 for XSS). Enables CWE-based report filtering" },
        { trigger: /sr_finding_create(?!.*cvss_score)/, advice: "Set cvss_score (0-10) and cvss_vector. Reports auto-calculate risk levels from CVSS 3.1" },
        { trigger: /sr_report_generate(?!.*template)/, advice: "List templates with sr_template_list first. Using wrong template produces unacceptable client report" },
        { trigger: /sr_section_add/, advice: "Section content supports Markdown — use headings, tables, code blocks for professional appearance" },
        { trigger: /sr_evidence_upload(?!.*caption)/, advice: "Add caption describing evidence — captions appear beneath images in the PDF report" },
      ],
      warnings: [
        { trigger: /sr_finding_create.*critical(?!.*cvss)/, advice: "Critical severity should match CVSS 9.0+. Severity/score mismatch confuses clients" },
        { trigger: /sr_finding_update.*resolved/, advice: "Marking resolved is permanent — retest the fix first" },
        { trigger: /sr_report_generate.*no.*finding/, advice: "Generating report with zero findings produces mostly-empty document. Verify with sr_project_summary first" },
        { trigger: /sr_evidence_upload.*10.*MB|large.*file/i, advice: "Files >10MB slow as base64 (~33% inflation). Compress or resize images first" },
      ],
      alternatives: [
        { trigger: /sr_finding_create/, alt: "Save findings locally: echo '## Finding' >> .openhack/reports/draft.md for later batch import" },
        { trigger: /sr_report_generate/, alt: "Manual markdown report: write findings in .openhack/reports/ and convert with pandoc --pdf" },
        { trigger: /sr_evidence_upload/, alt: "If file is on target, use scp to pull it locally first, then upload" },
      ],
      errors: [
        { trigger: /sr_report_export.*outside/, advice: "Export path must be within .openhack/reports/. Blocked by safety harness" },
        { trigger: /sr_evidence_upload.*outside/, advice: "Evidence path must be within .openhack/ or project directories. Blocked by safety harness" },
      ],
    },
  }

  const TOOL_ALIASES: Record<string, string> = {
    "impacket-GetUserSPNs": "impacket",
    "impacket-secretsdump": "impacket",
    "impacket-psexec": "impacket",
    "impacket-wmiexec": "impacket",
    "impacket-smbexec": "impacket",
    "impacket-atexec": "impacket",
    "impacket-dcomexec": "impacket",
    "impacket-GetNPUsers": "impacket",
    "impacket-GetADUsers": "impacket",
    "impacket-mssqlclient": "impacket",
    "evil-winrm": "winrm",
    "netexec": "netexec",
    "ncat": "nc",
    "netcat": "nc",
    "nc": "nc",
    "hexstrike_nmap_scan": "nmap",
    "hexstrike_rustscan_scan": "rustscan",
    "hexstrike_masscan_scan": "masscan",
    "hexstrike_gobuster_scan": "gobuster",
    "hexstrike_ffuf_scan": "ffuf",
    "hexstrike_sqlmap_scan": "sqlmap",
    "hexstrike_hydra_scan": "hydra",
    "hexstrike_john_hash": "john",
    "hexstrike_hashcat_crack": "hashcat",
    "hexstrike_nuclei_scan": "nuclei",
    "hexstrike_nikto_scan": "nikto",
    "hexstrike_wpscan_scan": "wpscan",
    "hexstrike_msfvenom_build": "msfvenom",
    "hexstrike_msfconsole_start": "msfconsole",
    "ptai_run_tool": "generic_mcp",
    "ptai_run_probe": "generic_mcp",
  }

  const MCP_PREFIXES = ["hexstrike_", "ptai_", "sr_", "arcticfox_", "rustsploit_"]

  export function analyze(command: string): Advice[] {
    const rawTool = command.trim().split(/\s+/)[0]
    const tool = TOOL_ALIASES[rawTool] || rawTool
    let knowledge = KNOWLEDGE_BASE[tool]

    const isMCP = MCP_PREFIXES.some((p) => rawTool.startsWith(p))
    if (!knowledge && isMCP) {
      knowledge = KNOWLEDGE_BASE["mcp"]
    }
    if (isMCP) {
      const mcpAdvice = KNOWLEDGE_BASE["mcp"] ? analyzeWith(command, KNOWLEDGE_BASE["mcp"]) : []
      if (knowledge && knowledge !== KNOWLEDGE_BASE["mcp"]) {
        return [...analyzeWith(command, knowledge), ...mcpAdvice]
      }
      return [...(knowledge === KNOWLEDGE_BASE["mcp"] ? [] : analyzeWith(command, knowledge || { tips: [], warnings: [], alternatives: [], errors: [] })), ...mcpAdvice]
    }

    if (!knowledge) {
      if (command.includes("&&") || command.includes(";")) {
        return [{ level: "tip", message: "Chained commands — ensure each command succeeds before the next with &&" }]
      }
      if (command.length > 200) {
        return [{ level: "warn", message: "Very long command — consider breaking into smaller steps" }]
      }
      return []
    }

    return analyzeWith(command, knowledge)
  }

  function analyzeWith(command: string, knowledge: ToolKnowledge): Advice[] {

    const advice: Advice[] = []

    for (const tip of knowledge.tips) {
      if (tip.trigger.test(command)) {
        const msg = typeof tip.advice === "function" ? tip.advice(command) : tip.advice
        if (msg) advice.push({ level: "tip", message: msg })
      }
    }

    for (const warn of knowledge.warnings) {
      if (warn.trigger.test(command)) {
        advice.push({ level: "warn", message: warn.advice })
      }
    }

    for (const alt of knowledge.alternatives) {
      if (alt.trigger.test(command)) {
        advice.push({ level: "alt", message: `Alternative: ${alt.alt}` })
      }
    }

    for (const err of knowledge.errors) {
      if (err.trigger.test(command)) {
        advice.push({ level: "error", message: err.advice })
      }
    }

    return advice
  }

  // Persisted so `/advise` and `/advise-level` survive across CLI invocations and
  // are shared with the running server process.
  const STATE_FILE = ".openhack/advisor.json"
  const savedState = loadJSON<{ enabled: boolean; verbosity: 1 | 2 | 3 }>(STATE_FILE, { enabled: true, verbosity: 2 })
  let advisorEnabled = savedState.enabled
  let verbosity: 1 | 2 | 3 = savedState.verbosity
  function persistState(): void { saveJSON(STATE_FILE, { enabled: advisorEnabled, verbosity }) }

  export function isEnabled(): boolean { return advisorEnabled }
  export function toggle(): boolean { advisorEnabled = !advisorEnabled; persistState(); return advisorEnabled }
  export function setVerbosity(v: 1 | 2 | 3): void {
    verbosity = Math.max(1, Math.min(3, v)) as 1 | 2 | 3
    persistState()
  }
  export function getVerbosity(): number { return verbosity }

  export function formatAdvice(advice: Advice[]): string[] {
    if (!advisorEnabled || advice.length === 0) return []

    const lines: string[] = []
    for (const a of advice) {
      if (a.level === "error" && verbosity >= 1) {
        lines.push(`  \x1b[31m✗ ${a.message}\x1b[0m`)
      } else if (a.level === "warn" && verbosity >= 1) {
        lines.push(`  \x1b[33m⚠ ${a.message}\x1b[0m`)
      } else if (a.level === "tip" && verbosity >= 2) {
        lines.push(`  \x1b[36m💡 ${a.message}\x1b[0m`)
      } else if (a.level === "alt" && verbosity >= 3) {
        lines.push(`  \x1b[35m🔄 ${a.message}\x1b[0m`)
      }
    }
    return lines
  }
}
