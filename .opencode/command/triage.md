---
description: Triage pass — fix bad code (error-handling/OOM/int-overflow/input-validation) + verify every vector is tested
---
Run a **triage pass** over $ARGUMENTS (a path, "framework", or "engagement").

Dispatch the `triage` subagent via the `task` tool (`subagent_type: "triage"`) with a targeted prompt:

1. **Code quality + security** — review the code in scope and **fix in place** (visible edits): swallowed errors
   / bare-context, unbounded reads or recursion (OOM), integer overflow in sizing, missing input validation
   (eval / unsafe deserialization / unradixed parseInt / unsafe YAML/XML), silent stubs, suppressed diagnostics,
   hardcoded secrets. Fix the root cause — never disable a check. Grounded in MITRE CWE / OWASP / NIST SSDF / CERT.
2. **Coverage** — read `.openhack/coverage/<target>.json` + the built-in checklist; list every untested endpoint ×
   method × vulnerability-class cell as a concrete next objective, and confirm tests exercise error paths, not just
   the happy path.

For a large surface, fan out **several** triage subagents over disjoint file/endpoint sets (in parallel) and
synthesize. Base every fix and gap on the real code/coverage — never rubber-stamp. Report: fixes applied
(file + change + why), defects that need manual remediation, and the coverage gaps still to test.
