---
description: Show Orchestrator routing table and tool scores
---
Show the Orchestrator routing table for $ARGUMENTS.
If no args: show all 20 routing categories with primary/fallback MCP servers.
If "route <command>": test-route a command to see which MCP server would handle it.
If "scores": show tool scoring data (success rates, average duration, last used).
The Orchestrator auto-routes commands to the best MCP server: recon→hexstrike, web→pentestai, exploit→hexstrike, c2→arcticfox, report→sysreptor.
