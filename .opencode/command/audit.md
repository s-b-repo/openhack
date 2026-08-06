---
description: Show audit trail for the current session
---
Show the audit trail for $ARGUMENTS.
If no args: show today's activity summary.
If "target <name>": show all actions on a specific target.
If "export": export full audit trail as JSON/CSV/markdown.
Every action (tool calls, safety blocks, scope violations, findings, recoveries) is logged as JSONL in .openhack/logs/<session>.jsonl with timestamps, agent provenance, and ROE validation status.
