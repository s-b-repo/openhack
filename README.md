# OpenHack

**AI-powered security assessment agent for authorized professionals.**

OpenHack is a fork of [OpenCode](https://github.com/anomalyco/opencode) tailored for penetration testing, vulnerability research, and security auditing workflows.

## Features

- **Multi-agent architecture**: Recon, exploit, post-exploit, and report subagents
- **MCP integration**: Connect HexStrike AI, pentest-ai, rustsploit, arcticfox-c3, SysReptor
- **Runtime enforcement plugin**: a single `tool.execute.before` hook enforces the safety harness (destructive-command blocking, resistant to quote/comment obfuscation), the engagement **scope**, and the signed **Rules of Engagement** — on *every* tool call, not just shell
- **Signed ROE**: rules of engagement are hash-signed over all authorization fields; post-signing tampering is detected and blocks execution
- **Secret scrubbing & instant findings**: tool output is scrubbed of credentials and scanned for findings, saved immediately with HMAC integrity + uncertainty flags
- **MoE routing**: generic subagent dispatches are routed to the best-matching specialist; usage stats persist across runs
- **Council review**: `/council` fans out real reviewer subagents to validate findings and find gaps (no simulation)

## Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/s-b-repo/openhack/main/install.sh | bash

# Or clone manually
git clone https://github.com/s-b-repo/openhack.git ~/openhack
cd ~/openhack
bun install

# Run
bun run packages/opencode/src/index.ts
```

## Requirements

- [Bun](https://bun.sh) 1.3+
- Node.js 22+
- Python 3.8+ (for MCP servers)
- Rust (for rustsploit/arcticfox)

## License

MIT — based on OpenCode by Anomaly

## Disclaimer

OpenHack is designed for **authorized security assessments only**. You must obtain written permission before testing any target. Unauthorized use may violate the Computer Fraud and Abuse Act and equivalent laws in your jurisdiction. The authors assume no liability for misuse.
