---
description: List or manage assessment findings
---
Manage findings for $ARGUMENTS.
If no args: list all findings for current target.
If "uncertain": show only findings needing manual verification.
If "deduplicate": run SHA-256 dedup on findings store.
Findings are saved in .openhack/findings/ with HMAC integrity.
