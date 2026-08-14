---
description: List or manage parallel workflows
---
Manage parallel workflows for $ARGUMENTS.
If no args: list all active workflows with status.
If "start <name>": launch a new workflow session (recon, exploit, web, report, etc.).
If "stop <id>": stop a specific workflow.
If "switch <id>": switch context to a workflow.
Workflows run as independent sub-sessions with their own context windows.
They communicate through the shared findings store (.openhack/findings/).
