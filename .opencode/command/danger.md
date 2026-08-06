---
description: Toggle the safety harness ON/OFF (3-second confirmation)
subtask: true
---
Toggle the OpenHack safety harness. Run `echo SAFETY_TOGGLE` to simulate.
The safety harness blocks destructive commands: rm -rf /, dd, mkfs, fork bombs, curl|sh, shutdown.
When ON: destructive commands return block messages.
When OFF: all commands execute normally (DANGEROUS).
Default state is ON. Auto-re-enables on next session.
