---
description: Manage Docker containers — status, start, stop, network
---
Manage Docker MCP containers for $ARGUMENTS.
If no args or "status": show all MCP container statuses (docker ps --filter name=openhack).
If "start": start all 5 MCP containers (hexstrike, pentestai, rustsploit, arcticfox, sysreptor).
If "stop": stop all MCP containers.
If "net": show Docker network info (openhack-net subnet, gateway, container IPs).
If "setup": run the full MCP deployment setup script.
Containers are on a private bridge network (default: 10.99.0.0/24) with static IPs.
rustsploit runs as privileged container for raw socket access.
