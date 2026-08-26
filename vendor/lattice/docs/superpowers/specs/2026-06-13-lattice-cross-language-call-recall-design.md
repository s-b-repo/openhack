# Lattice — cross-language call-edge recall (shared name-resolution pass)

**Date:** 2026-06-13
**Branch:** phase1
**Status:** approved (design), implementing
**Sub-project:** #2 of the improve-lattice program (precision → **recall** → robustness → coverage)
**Constraint:** "cs wide" — the mechanism must be **language-agnostic**, not a TS point fix.

## Problem

Downstream analyses (impact, hunt, taint, dead-code) are only as complete as the call
edges. Today the builder resolves calls/references **by location only**
(`enclosing(r.to_file, r.to_line)`, `builder.py` Pass 3). There is **no shared
name-based fallback**, and the frontends diverge:

- **TS / JS (`lsp_client`)** — resolves via LSP "who references this symbol". Precise, but
  has no call-site→target *by name* path, so named calls LSP can't pin are lost
  (the recall gap behind the zx eval).
- **Python / C / C++ / Solidity** — each independently builds a `name→definition` map
  (`func_pos`) and resolves callee names against it, collapsing ambiguity to the **first**
  match (`setdefault`) — so polymorphic / overloaded same-name methods lose their sibling
  edges. Three copies of the same logic.

(Go / Ruby / Rust are taint-only — no general call graph at all.)

## Goal

One **language-agnostic** name-resolution pass in the builder that recovers call/dispatch
edges any frontend leaves unresolved, keyed on a callee name carried by `RawReference`.
Cross-language by construction: every frontend benefits by emitting names; future
frontends (and eventually Go/Ruby/Rust) get it for free.

## Design

### Model — `RawReference.name`

Add optional `name: str | None = None` (the callee name) to `RawReference`
(`ingest/types.py`). Defaults to `None`, so **every existing reference and frontend is
unaffected until it opts in** — the safety property that protects the 705-test baseline.

### Builder — shared name-resolution pass (additive)

Build `name_index: dict[str, list[vid]]` over `function`/`method` vertices (by bare
`v.name`). The pass **only adds edges, never removes or alters existing ones**:

- For a call/reference `r` carrying `r.name`:
  - **fully unresolved** (no internal location): candidates = `name_index[r.name]` minus
    the calling vertex and externals.
    - 1 candidate → `references` edge, `resolved=True`, `provenance="name-match"`,
      `confidence=0.9`.
    - >1 → `dispatch` edges to **all** candidates, `provenance="name-match"`,
      `confidence≈1/N` (ambiguity policy: **dispatch-to-all**, per decision).
    - 0 → unchanged (honest non-edge / external_call).
  - **already resolved by the frontend** but `r.name` is ambiguous → add `dispatch` edges
    to the *other* same-name candidates not already edged from this site (recovers the
    polymorphic siblings the first-match collapse dropped). The frontend's own edge stays.

`dispatch` is already consumed as inbound-flow by `hunt` (`INBOUND_FLOW_KINDS`) — the
consumer side is ready.

### Frontend emission — phased

1. **Builder core + model** *(this pass)* — the cs-wide mechanism. TDD'd at the builder
   layer, proven language-agnostic with multi-language-prefix tests. No-op until a
   frontend sets `name`.
2. **Python** — already enumerates call-site names (`visit_Call`); emit `name` on its
   references. Additive: existing first-match edges stay; the pass adds polymorphic
   sibling dispatch edges. Demonstrable recall win on a Python fixture.
3. **TS / JS** — the biggest recall win, but requires a new AST call-site scan (lsp_client
   is reference-oriented). May reuse the JS/TS AST machinery already in
   `js_arbitrary_call.py`. Emit `name` on calls LSP left unresolved.
4. **C / C++, Solidity** — opt in by emitting `name` on their `func_pos` misses /
   ambiguous calls.

Each frontend wiring is its own TDD step with its own tests; none touches another
frontend's resolved-edge logic.

## Scope

**Out of scope (documented follow-ups):**
- **Computed-member dynamic dispatch** (`obj[key]()` — the zx `formatters[entry.kind]`
  cluster). No static callee name, so name-match can't recover it; needs an object-dispatch
  heuristic. Seam exists: `js_arbitrary_call.py:317` already detects `obj[KEY]` dispatch.
- **General call graphs for Go / Ruby / Rust** (no general frontend — Phase 4).
- **Full type inference / precise receiver-type dispatch.**

## Testing & acceptance

- **Builder TDD** (the language-agnostic core): single-candidate recovery; multi-candidate
  dispatch-to-all; no-match left unchanged; location-resolved still wins (name ignored when
  already located); already-resolved-but-ambiguous adds sibling dispatch; a `language=
  "python"` and a `language="typescript"` case proving the same pass fires for both.
- **Per-frontend tests** as each is wired (Python first).
- Full suite stays green (708 baseline; existing exact-edge-count tests updated where the
  additive siblings legitimately change counts).
- **Empirical:** a Python polymorphic fixture (sibling dispatch recovered) + fresh zx
  measurement reported **as-is** (modest — the big remaining zx cluster is the deferred
  computed-member case).

## Philosophy

Name-match / dispatch edges carry `provenance="name-match"` and `confidence<1.0` — honest
leads, not asserted facts (FIRE=lead / SILENCE≠proof). The pass is purely additive, so it
can raise recall without ever disturbing the fact-grade edges the frontends resolve.
