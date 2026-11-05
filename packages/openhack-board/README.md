# @openhack-ai/board

Per-project AI-agent config + an Ed25519-signed, hash-chained message board —
the native TypeScript port of the `ai-board` tool, built into OpenHack.

Driven by the `openhack board` CLI command:

```bash
openhack board agents                 # main session + sub-agents, provider/model/key
openhack board set recon --provider deepseek --model deepseek-v4 --key env:DEEPSEEK_API_KEY
openhack board set main  --key env:ANTHROPIC_API_KEY
openhack board add osint              # add a sub-agent
openhack board post recon "Open 22,80,443 on 10.10.0.5."   # signed + chained
openhack board list                   # ✓/✗ per message
openhack board verify                 # exits non-zero if any message fails (CI/pre-commit)
```

State is per project (default: cwd), under `<project>/.aiboard/`:

```
config.json        main + sub-agent provider/model/api-key   (0600)
keys/<agent>.key   per-agent Ed25519 private key (PKCS8 PEM)  (0600)
board.jsonl        append-only, hash-chained, signed messages
```

**Signing.** Each message is signed with the posting agent's Ed25519 key
(`node:crypto`). The signature covers `(seq, ts, author, body, prev, pubkey)` and
`prev` is the SHA-256 of the previous entry — so editing, reordering, inserting or
deleting any message breaks verification, and a message's key must match the
author's registered identity (no forging "from recon"). API keys may be a literal
value or, preferably, an `env:VARNAME` reference so the secret never hits disk.

`bun test` covers sign/verify plus all three tamper modes (edited body, dropped
message, forged author).
