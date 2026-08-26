# Lattice — dynamic-dispatch recall (containment + computed-member dispatch)

**Date:** 2026-06-13
**Branch:** phase1
**Status:** approved (design), implementing
**Sub-project:** #2b — pivot from name-match (#2) to the recall gap the evidence actually identified.
**Constraint:** cs-wide — containment core is language-agnostic; dispatch-site detection is per-frontend (TS first).

## Why this, not name-match

Two real-code measurements redirected the recall effort here:
- **zx**: remaining dead_code FPs were `formatters[entry.kind]()` — computed-member dispatch.
- **lattice (Python)**: name-match (#2) yielded 0 real edges.

Both say the missing recall is **dynamic dispatch**, not named-call resolution.

## Root cause (verified)

For zx's `const formatters = { cmd(){…}, stdout(){…}, … }` invoked as
`formatters[entry.kind]()`:
1. **Containment is not modeled.** LSP flattens object-literal methods to module-level
   `method` symbols (`log.ts#cmd`, not `log.ts#formatters.cmd`) — no link to `formatters`.
2. **The container read is missed.** `formatters` has `fan_in=0`; the computed-member read
   was never recorded as an edge.

So the members look dead and the dispatch is invisible. Verified: members **do** line-nest
inside the container's span (`formatters` 81–113; `cmd` 82–84 … `kill` 110–112), so
containment is recoverable from the position index the builder already has.

## Design (full dispatch, three parts)

### Part A — containment by line-nesting (cs-wide builder core)

Derive a `container → [member vertex ids]` map: a `function`/`method` vertex is a member of
the smallest non-module vertex (`variable`/`class`/`interface`) whose line span strictly
contains it. Reuse the existing `by_file` position index. Emit `defines` edges
(container → member) so the relationship is first-class (benefits impact/diagnose too).
Language-agnostic — works for any frontend's line-spanned symbols.

### Part B — dynamic-dispatch-site detection (per-frontend; TS first)

A frontend flags a dynamic-dispatch site and emits it as a `RawReference` with
`kind="dyn_dispatch"`, `name=<base object name>`, `from_file`/`from_line` = the call site.
Idioms: TS/JS `obj[<dynamic>](…)`; (later) Python `getattr(obj,k)()` / `d[k]()`, Ruby
`obj.send(k)`. **TS**: extend the `js_arbitrary_call.py` AST scan (already finds
`callee.computed` member-calls at line 316) to also capture `callee.object.name` (the base)
and the node line; wire that scan into general TS ingest (it is currently security-only).

### Part C — builder dispatch-edge emission

For each `dyn_dispatch` reference: resolve `name` → its container vertex (a `variable`/
`class` of that name, via a container-name index); via Part A's containment map, get its
members; emit `dispatch` edges from the enclosing function of the site to each member —
`provenance="dynamic-dispatch"`, `confidence≈1/N`, **fan-out capped** (`_MAX_NAME_DISPATCH`,
reused — the lesson from #2: ubiquitous fan-out is noise). Marks the container used and the
members reached.

## Safety / additivity

`dyn_dispatch` is a new reference kind; existing frontends never emit it → no behavior
change until a frontend opts in (the #2 baseline-safety pattern). `defines` edges are
additive. Dispatch edges carry `confidence<1.0` + provenance → honest leads (FIRE=lead).

## Scope

**In:** containment core (all languages); TS computed-member dispatch detection + edges.
**Out / follow-up:** Python `getattr`/dict-dispatch and Ruby `send` detection (next frontends,
same model); precise key-narrowing (when the dynamic key is a known enum/literal-union, link
only matching members) — a precision follow-up; Go/Ruby/Rust general graphs (Phase 4).

## Testing & acceptance

- **Part A (TDD, builder):** object-literal members get `defines` edges to their container;
  nested-within-nested attributed to the innermost container; class methods unaffected;
  language-agnostic (py/ts prefixes).
- **Part B (TDD, frontend):** the TS scan emits a `dyn_dispatch` ref with the base name and
  site line for `obj[k]()`; not for static `obj.m()`.
- **Part C (TDD, builder):** a `dyn_dispatch` ref to a container yields capped `dispatch`
  edges to its members (`provenance="dynamic-dispatch"`); unknown base → no edge; fan-out
  above cap → skip.
- Full suite green (718 baseline).
- **Empirical:** fresh zx `hunt` — the `formatters` cluster (`cmd`/`stdout`/`cd`/`kill`/…)
  should drop out of `dead_code`; report the before/after count.

## Philosophy

Same as the program: additive, confidence/provenance-tagged, demote-don't-drop, measured on
real code before claiming a win.
