---
description: Recover an interrupted loop by resuming the rounds ledger (--resume)
---
Recover from a crash or an interrupted loop by resuming the engagement from the
last recorded round in `.openhack/rounds/<target>.jsonl`.

Use this when an automode loop crashed or was killed, and you want to pick up
where it stopped without re-running completed rounds. The recovery is driven
by the durable rounds ledger + the RLEM durable-event store, so a partial
agent that died after publishing one or more events will have its work
replayed before the next new round dispatches.

**Inputs.** Optional: a target name. If omitted, the macro reads the most
recently-touched target from `.openhack/rounds/` (the same target the last
loop run wrote to). Examples: `/recover` (auto-detect), `/recover example.com`.

**Preconditions.** A rounds ledger entry must exist for the target (or for
some target if auto-detecting). An authorized, signed ROE and an in-scope
target must still be in force — the resume does not re-authorize; the
runtime's safety harness, scope and ROE checks still apply on every new
round that gets dispatched.

**Steps.**

1. **Pick the target** — auto-detect or use the argument:
   - If `$ARGUMENTS` is empty, read `.openhack/rounds/` and pick the
     most-recently-modified `<target>.jsonl`; report which target you're
     resuming and the last recorded round number.
   - Otherwise, treat the argument as the target.
2. **Read the last recorded round** from `.openhack/rounds/<target>.jsonl`
   (or `openhack status --target <target>` for the human summary). Note the
   `round` number, the `totalCostUsd`, the `findingsTotal` / `findingsHigh`,
   and the dispatched-task list.
3. **Dispatch the resume** as a real shell call so the framework does the
   heavy lifting:
   ```bash
   openhack automode --target <target> --loop --resume
   ```
   Do NOT re-run the full loop without `--resume`; the recovery starts at
   `lastRound + 1` and replays durable events so no work is lost.
4. **Surface any safety / budget signals** that the previous loop left in
   the ledger (e.g. `rssMb` near the cliff, a high `newHigh` with a
   low coverage delta). Do not silently re-dispatch the same objective;
   if the previous loop got blocked by ROE/scope/cost, fix the blocker
   first.
5. **Report status on completion** — `openhack status --target <target>`
   after the resume; the new ledger entries will show the recovered round
   numbers continuing from the previous high-water mark.

**Doctrine.** The resume path is the recovery boundary. Do not delete or
truncate `.openhack/rounds/<target>.jsonl` — the ledger is the durable
source of truth for crash recovery, bench analysis, and the temporal mirror
(`temporal.enabled=true` → `temporal workflow start` per round). Editing
the ledger by hand is a recoverable mistake (the loop re-dispatches) but it
defeats the resume and can produce double-billing.
