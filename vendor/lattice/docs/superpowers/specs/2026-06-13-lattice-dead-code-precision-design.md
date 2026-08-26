# Lattice — dead_code precision: public methods of exported classes

**Date:** 2026-06-13
**Branch:** phase1
**Status:** approved (design), pending implementation
**Sub-project:** #1 of a 4-part "improve lattice" program (precision → method-call recall → MCP robustness → Python depth)

## Problem

`hunt`'s `dead_code` detector floods false positives on libraries. Measured on
`google/zx` @ `6a62a4b` (17 TS source files): **48 findings, all `low` `dead_code`,
~all false positives** — e.g. `ProcessPromise.pipe`, `.stdout`, `.text`, `YAML.parse`.

These are **public methods of an exported class** — part of the library's public API,
consumed by external callers the graph cannot see. They are not dead.

## Root cause

`src/lattice/graph/builder.py` Pass 4 (line ~138):

```python
for v in vertices.values():
    if v.exported and v.kind in ("function", "method"):
        surfaces.append(Surface(id=f"surf-api-{si}", vertex_id=v.id, kind="public_api"))
```

A TypeScript class method never individually carries `export`; only the enclosing
`class` does. So `ProcessPromise.pipe` has `exported=False`, receives **no `public_api`
surface**, and is therefore:

1. excluded as a reachability root, and
2. eligible for `dead_code` in `src/lattice/hunt.py` (line ~139, `not v.exported`).

The same modeling gap silently weakens `secaudit` (attack surface) and `impact`
(public-API reach): public methods of exported classes are invisible as entry points
everywhere, not just in dead-code.

## Design (surface-layer fix)

**Two changes, one notion.** The graph already has a first-class concept for
"externally reachable": the `public_api` surface. Make method visibility flow through it.

### Change 1 — `builder.py` Pass 4: emit surfaces for public methods of exported classes

In addition to the existing `v.exported` rule, emit a `public_api` surface for a
`method` vertex when **its enclosing class/interface is exported and the method is
public-by-convention**:

- Enclosing type id = `v.id.rsplit(".", 1)[0]` (only when the qualified name after `#`
  contains a `.`).
- Look it up in `vertices`; include only if it exists, `kind in ("class","interface")`,
  and `.exported` is True.
- **Exclude** hard-private `#name` (ES private) and convention-internal `_name`.
  Rationale: an `_`-prefixed method with no in-repo callers is a *legitimate* dead-code
  lead, so it must stay eligible.

### Change 2 — `hunt.py` dead-code predicate: consult `public_api` surfaces

Replace the raw `not v.exported` gate with "not backed by a `public_api` surface":

```python
public_api_ids = {s.vertex_id for s in net.surfaces if s.kind == "public_api"}
# ... dead = [v for v in net.vertices if v.kind in ("function","method")
#            and v.id not in public_api_ids and not v.stub ... ]
```

This is internally consistent: dead-code reachability is *already* rooted at
`public_api`/`entrypoint` surfaces (hunt.py:87), so excluding `public_api`-backed
vertices from "dead" closes the loop with the same notion.

## Scope

**In scope:** the two changes above; TS class methods of exported classes.

**Out of scope (deferred):**
- Improving method-call *edge recall* (sub-project #2). A method genuinely called
  in-repo but missed by reference resolution is a recall problem, not this fix.
- Capturing real TS `private`/`protected` modifiers into a `Vertex.visibility` field
  across frontends (approach C). That is a model + multi-frontend change.

## Honest trade (documented limitation)

A TS method declared with the `private`/`protected` **keyword** but a public-looking
name (no `#`/`_`) will now be treated as public API and **not** flagged dead. Accepted:
48 FPs to catch one rare keyword-private dead method is poor signal, and *not flagging
is not a claim of liveness* (SILENCE ≠ proof). Recoverable later via approach C.

## Testing & acceptance

- **TDD** in `tests/test_hunt_precision.py`:
  - a public method of an exported class is **not** `dead_code` (RED → GREEN);
  - an `_`-prefixed method of an exported class **is** still eligible;
  - a method of a **non-exported** class **is** still eligible;
  - (regression) a genuinely dead non-exported top-level function is still flagged.
- Full suite stays green (`705 passed` baseline).
- **Empirical:** re-run `hunt` on `google/zx` and report the before/after `dead_code`
  count; target a large reduction in the `ProcessPromise.*` / exported-class-method FPs
  with no loss of true dead-code findings.

## Implementation results (2026-06-13)

Implemented TDD-first. Two changes: `builder.py` Pass 4 (surface emission) and the
`hunt.py` dead-code predicate (`not v.exported and v.id not in public_api_ids` — a
superset of the old exclusion, so surface-less call paths are unchanged). Three new
tests (1 builder, 2 hunt) RED→GREEN; full suite green.

**Empirical on `google/zx` @ `6a62a4b`:** `dead_code` findings **48 → 15**. All
`ProcessPromise.*` and `YAML.*` findings (≈33, public methods of exported classes)
eliminated — verified-correct removals (they are public API).

**Discovered during measurement (out of scope, candidate follow-up):** the remaining 15
are dominated by a *second, distinct* FP cause — methods of a `const` **object-literal
method table** invoked via **dynamic dispatch / computed member access**
(`formatters[entry.kind]` at `zx/src/log.ts:124`). The graph cannot see the computed
key, so the 8 formatter methods (`cmd`/`stdout`/`stderr`/`custom`/`fetch`/`cd`/`retry`/
`kill`) appear uncalled. This is NOT the exported-class gap; it belongs with method-call
recall (#2) or a dedicated dispatch heuristic. The few genuine leads remaining
(`core.ts#set`, `deps.ts#npm`, `internals.ts#apply`, `goods.ts#_read`) are correct
behavior.

## Consistency with project philosophy

FIRE = lead / SILENCE ≠ proof: this raises finding precision (fewer noisy leads) without
ever asserting a suppressed method is alive — the same demote/suppress-don't-overclaim
stance as the prior `secaudit` sink-precision and taint work.
