---
description: Show or manage the current Rules of Engagement
---
Handle ROE operations for $ARGUMENTS.
If no args: show current ROE status (read .openhack/roe/active.roe.json).
If "create": create a new ROE from template.
If "sign": sign the current ROE with SHA-256.
If "revoke": revoke and remove current ROE.
The ROE grants authorized scope and tool permissions. Operations without valid signed ROE are blocked.
