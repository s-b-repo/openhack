---
description: Run post-assessment cleanup — remove all deployed artifacts
---
Run the post-assessment cleanup process for $ARGUMENTS.
The cleanup agent:
1. Enumerates all deployed artifacts (arcticfox agents, persistence mechanisms, dead drops, tunnels, files, registry modifications)
2. Removes each in reverse deployment order
3. Verifies removal (heartbeat check)
4. Generates Cleanup Verification Report → .openhack/reports/cleanup-<target>.md
5. Flags any artifacts that could not be removed for manual remediation
6. Purges the secrets store

Always run cleanup before ending an engagement. NEVER leave artifacts on target systems.
