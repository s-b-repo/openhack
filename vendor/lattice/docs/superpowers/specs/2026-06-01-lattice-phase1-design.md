# Lattice — Phase 1 Design Spec

**Date:** 2026-06-01
**Status:** Draft for review
**Scope:** Phase 1 of 4 — LSP ingestion → typed hypernetwork → completeness gate → recall persistence, one language.

> Working name "Lattice" is a placeholder. Lattice is a multi-domain, security-oriented
> structural-analysis tool built on the principles of `defi-v2` (typed dependency graph →
> topological obstruction detection → calibrated witness extraction → RRT search → conservative
> ranking), generalized beyond Solidity/DeFi and hardened with recall-backed memory and
> solver-backed math. This spec covers only the foundation: turning any codebase into a verified
> hypernetwork. RRT analysis, scoring, and the decision loop are later phases.

## 1. Goal

Given a path to a codebase, produce a **typed hypernetwork** of its symbols and relationships via
a Language Server, **verify the mapping is complete** (a graph-integrity gate), and **persist the
hypernetwork to recall** — so that a later phase can run RRT obstruction analysis over a structure
we trust. Phase 1 is done when we can point Lattice at a real repository and get back a complete,
recall-persisted hypernetwork plus a pass/fail completeness report.

## 2. Why LSP

LSP is the generalizer. Instead of writing an AST adapter per language (as `defi-v2` does for
TypeScript), Lattice talks to each language's existing Language Server and gets symbols,
references, definitions, and diagnostics through one protocol. One client, many languages — this
is the mechanism by which the tool "doesn't have to be just for defi."

## 3. Phase 1 scope

**In scope**
- Python-first implementation.
- LSP ingestion via `multilspy` for **one language: TypeScript** (decision — see §10).
- The typed hypernetwork data model (§5) and its on-disk JSON contract.
- Completeness gate (§6) with a structured report.
- recall persistence of the hypernetwork (§7).
- A minimal CLI entrypoint (§8). No `SKILL.md` yet (Phase 3).

**Out of scope (later phases)**
- RRT search / topological obstruction detection / witness extraction (Phase 2).
- solver-backed scoring, calibration, ranking (Phase 2–3).
- Decision loop UX and `SKILL.md` (Phase 3).
- Multi-language adapters, autonomous mode, cross-run drift (Phase 4).
- Any DeFi/Solidity-specific witness families.

## 4. Architecture (Phase 1 layers)

```
codebase path
     │
 ingest/   ── multilspy LSP client → raw symbols/refs/defs/diagnostics
     │
 graph/    ── normalize into typed hypernetwork (vertices, hyperedges, surfaces)
     │
 complete/ ── completeness gate → HypernetworkReport (pass/fail + gaps)
     │
 memory/   ── persist hypernetwork + report to recall
     │
 cli/      ── `lattice ingest <path> --lang ts` orchestrates the above
```

Each layer has one responsibility and a typed interface to the next. The seam between `graph/` and
everything downstream is the **`hypernetwork.json` contract** (§5), deliberately shaped to match
what `defi-v2`'s engine already consumes so the TS engine can serve as a validation oracle.

### Module contracts
- `ingest/lsp_client.py` — `ingest(root: Path, lang: str) -> RawIngest`. Owns multilspy lifecycle
  (start server, open files, query, shut down). Depends on: multilspy. Knows nothing about the
  hypernetwork model.
- `graph/builder.py` — `build(raw: RawIngest) -> Hypernetwork`. Pure transform; no I/O.
- `complete/gate.py` — `check(net: Hypernetwork) -> HypernetworkReport`. Pure; no I/O.
- `memory/recall_sink.py` — `persist(net: Hypernetwork, report: HypernetworkReport, project: str) -> None`.
  Owns recall writes. Reuses `recall_code_extract`/`recall_helper` patterns.
- `cli/main.py` — orchestration only.

## 5. Data model — the typed hypernetwork

The stable contract. Serialized to `hypernetwork.json`.

**Vertex** (a symbol):
- `id` (stable, e.g. `ts-sym:<file>#<qualified-name>`)
- `kind` (`module` | `class` | `interface` | `function` | `method` | `variable` | `type` | `external`)
- `name`, `file`, `range` (start/end line)
- `type` (the symbol's declared type when the LSP exposes it; nullable)
- `exported` (bool), `stub` (bool — empty body / `TODO` / `throw not implemented`)

**Hyperedge** (a relationship; may connect >2 vertices):
- `id`, `kind` (`imports` | `calls` | `references` | `inherits` | `implements` | `defines` | `returns`)
- `members` (ordered vertex ids), `directed` (bool)
- `resolved` (bool — every member resolved to a known vertex)

**Surface** (an externally-reachable or trust-relevant point — feeds later RRT):
- `id`, `vertex_id`, `kind` (`entrypoint` | `external_call` | `public_api` | `trust_boundary`)

**Hypernetwork**: `{ schema_version, language, root, vertices[], hyperedges[], surfaces[], stats }`.

Vertex `type` and the typed-hyperedge notion are grounded in `math_hypernetwork.py` (typed
hypernetworks from the RRT papers); Phase 2's RRT layer consumes these types.

## 6. Completeness gate

Verifies the **mapping** is whole (not that the code is correct — that's a different concern).
Produces a `HypernetworkReport`:

- `resolution`: % of hyperedge members that resolve to a known vertex; lists unresolved refs.
- `dangling_edges`: hyperedges with ≥1 unresolved member.
- `unresolved_imports`: import edges whose target vertex is absent.
- `stubs`: vertices flagged `stub=true`.
- `surface_coverage`: surfaces discovered vs. expected entrypoints (heuristic per language).
- `diagnostics`: LSP-reported errors/warnings that indicate an incomplete build.
- `verdict`: `pass` | `partial` | `fail`, with the failing checks enumerated.

`solver` use (optional in Phase 1, behind the fallback in §9): coverage/ratio statistics and a
histogram of unresolved-reference clustering, to make the verdict thresholds principled rather than
arbitrary. If solver is unavailable, use plain ratios with documented thresholds.

A `fail` stops the pipeline with an exact list of what's incomplete. `partial` is allowed only when
the caller explicitly opts in (`--allow-partial`), and is recorded as such in recall.

## 7. recall persistence

Reuse the proven path (`recall_code_extract` + `recall_helper`), writing to a dedicated project DB.

- Vertices → cells (`kind: artifact`), tagged `topics:[code, <lang>, <vertex.kind>]`, entities
  `<lang>-sym:<name>`, `scope.project = <project>`.
- Hyperedges → recall hyperedges (typed: `code-imports`, `code-references`, `code-defined-in`,
  `code-method-of`, etc.), via `recall_code_link` conventions.
- `HypernetworkReport` → one `observation`/`verification_result` cell summarizing the gate verdict,
  linked to the run.
- Routing: writes go to a Lattice-owned recall project. Phase 1 registers `~/Lattice` as a recall
  project and **always passes `--db` explicitly** to the extractor/linker (see the routing gotcha:
  `--project` only tags; `--db`/cwd routes). Re-ingesting a target uses `--rebuild` so prior cells
  are superseded, not duplicated.

## 8. CLI entrypoint

```
lattice ingest <path> --lang ts [--project <slug>] [--allow-partial] [--out hypernetwork.json]
```
Runs ingest → build → gate → persist. Prints the report verdict and writes `hypernetwork.json` +
`hypernetwork-report.json`. Exit non-zero on `fail` (unless `--allow-partial`).

## 9. Error handling (no silent downgrades)

- LSP server missing/unstartable → clear error naming the server and how to install it; do **not**
  silently fall back to a weaker parser in Phase 1 (AST fallback is Phase 4).
- LSP query partial/timeouts → mark affected vertices/edges `resolved=false`; the gate surfaces them.
- solver unavailable → use documented plain-ratio thresholds, log a one-line warning.
- recall write failure → keep `hypernetwork.json` locally, flag the failure, exit non-zero.

## 10. Decisions & rationale

- **Substrate: Python-first** — LSP (`multilspy`), `math_hypernetwork.py`, and recall/solver helpers
  are all Python; defi-v2 (TS) is kept as reference + oracle, not extended.
- **Phase 1 language: TypeScript** — lets us cross-validate the hypernetwork against defi-v2's
  existing TS AST adapter output (a built-in oracle), and defi-v2 itself becomes a real test target.
  Python dogfooding is a fast-follow. *(Flagged for review — flip to Python-first target if preferred.)*
- **One DB per tool** — Lattice gets its own recall project DB, separate from `defi`.

## 11. Testing / success criteria

- **Unit (TDD):** `graph/builder` and `complete/gate` are pure functions — fixture-driven tests,
  including graphs with deliberate dangling edges, stubs, and unresolved imports.
- **Golden files:** `hypernetwork.json` for a small fixed TS sample repo; diffs are reviewed.
- **Oracle cross-check:** run Lattice ingestion on a TS project that defi-v2's AST adapter also
  ingests; assert the vertex/edge sets agree within a documented tolerance.
- **Integration:** `lattice ingest` on `defi-v2/src` produces a `pass` verdict and persists to recall;
  `recall --db <lattice-db> status` shows the expected node/hyperedge counts.

**Phase 1 is complete when:** pointing Lattice at a real TypeScript repo yields a complete,
recall-persisted hypernetwork with a `pass` completeness verdict, the oracle cross-check agrees, and
all unit/golden tests are green.

## 12. Open questions for review

1. Phase 1 language: TypeScript (oracle cross-check) vs Python (simpler, dogfood)? (§10)
2. Is `multilspy` acceptable as the LSP client dependency, or prefer a hand-rolled minimal LSP client?
3. Lattice recall project slug — `lattice`? And should it ever federate with the `defi` DB on reads?
