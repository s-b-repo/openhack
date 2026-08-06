---
description: Show or manage engagement scope
---
Manage engagement scope for $ARGUMENTS.
If no args: read .openhack/scope.json and show current scope (targets, exclusions, allowed tools).
If "add <target>": add a target to scope.
If "enable": enable scope enforcement.
If "disable": disable scope enforcement.
The scope enforcer validates every tool call against this scope. Out-of-scope targets are BLOCKED.
