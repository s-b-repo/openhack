# @openhack-ai/tools

Registry + actions for the open-source security tools cloned under a base
directory (default `~/Projects/store-tools`) — the native TypeScript port of the
Tool Manager, built into OpenHack.

Driven by the `openhack tools` CLI command:

```bash
openhack tools list                   # all tools, grouped, with build status
openhack tools build rustsploit       # build under a soft memory cap
openhack tools run openhack           # run in this terminal (hard memory cap for OpenHack)
openhack tools update cau             # git pull
openhack tools list --base ~/other    # point at a different base dir
```

Covers the 15 tools (Quicmap, rustsploit, rustforce, OpenHack, ArcticFox-C3, CAU,
Elastacat, Wazuh installer, p2soc, windows-hardening, Peregrine, OnlyOffice MCP,
cardsz, advanced-shodan, and the dcr-mcp memory bridge), resolving absolute-path
tools (dcr-mcp) and crate subdirs (rustforce) correctly.

**Memory.** This box is RAM-constrained. When `systemd-run` + cgroup v2 are
present, builds run under a soft `MemoryHigh` throttle and OpenHack runs under a
hard `MemoryMax` with swap disabled, so a runaway can't freeze the machine
(`openhack tools list` shows whether caps are on).

`bun test` covers registry shape, base-vs-absolute path resolution, status, and
the build/run/update argv builders.
