# Lattice MCP Server — design

**Date:** 2026-06-09
**Status:** approved, implementing

## Goal

Give an autonomous coding agent the structural feedback loop it lacks today:
**`impact` before an edit** (what does this change touch?) and **`hunt` after**
(did it break the structure?), backed by a persistent graph that is ingested once
and queried in milliseconds.

The thesis, measured: on the 1,497-vertex Lattice self-ingest, loading the cached
graph + running `hunt` is **22 ms**. Ingestion (the LSP pass) is minutes. So the
server is a *stateful cache* around Lattice's existing `load_network → analysis`
seam — ingest once, answer every query fast.

## Non-goals (v1)

- Recall / cross-session memory (documented v2 opt-in; v1 is filesystem-cache only,
  no recall dependency).
- Exposing every CLI analysis. v1 ships the agent-loop core (5 analyses + refresh).
- Fast incremental refresh for non-TS languages (staleness *detection* is universal;
  fast *refresh* via the LSP splice is TS-only, full re-ingest elsewhere — documented,
  not hidden).

## Architecture

New subpackage `src/lattice/mcp/`, three modules, one job each:

### `workspace.py` — stateful cache core (transport-agnostic; the unit-test target)

A `Workspace` keyed by resolved repo root holds:
- the built `Hypernetwork`,
- the source root + language,
- an mtime snapshot `{relpath: mtime_ns}` of every source file at ingest time,
- (TS only) the serialized `RawIngest` sidecar, to enable incremental refresh.

Cache persists under `<root>/.lattice/`:
- `graph.json` — the built hypernetwork (`Hypernetwork.to_dict`).
- `snapshot.json` — `{language, files: {relpath: mtime_ns}}`.
- `raw.json` — (TS) `raw_to_dict(RawIngest)` for the incremental splice.

Methods:
- `ensure(language="auto")` — load a valid cache, else ingest+build, snapshot, persist.
- `staleness()` — stat()-only rescan of source files vs snapshot →
  `{changed: [...], added: [...], removed: [...]}`. No parsing; cheap.
- `refresh()` — TS with a cached raw + only-changed files → `incremental_ingest`
  splice (fast); any failure or other language → full re-ingest via `load_network`.
  Rewrites graph/snapshot/raw.

Source-file discovery reuses `cache.detect_languages` and the per-language probe
globs so "source file" means exactly what ingest means.

### `server.py` — FastMCP server

Official `mcp` SDK (`mcp.server.fastmcp.FastMCP`), stdio transport. Tools are
decorator-wrapped **plain Python callables** so they unit-test directly without a
transport. A module-level workspace registry maps root → `Workspace` (lazy-created).

### `__main__.py` — entry point

`python -m lattice.mcp --root <repo> [--cache-dir DIR]`; console script `lattice-mcp`.
`--root` sets the default workspace; tools may override per-call.

## Tools (6)

Every tool response includes a **`freshness`** block:
`{stale: bool, changed_files: [...], hint: "call lattice_refresh to rebuild"}`.
The agent gets instant cached answers and knows when they are stale — it decides
when to pay the re-ingest. Honest-by-construction.

1. **`lattice_map(root=None, language="auto")`** — ingest-once / load-cache. Returns
   `{vertices, hyperedges, languages, verdict, resolution, public_surfaces: N}`.
   Establishes the workspace.

2. **`lattice_impact(query, root=None)`** — *the wedge.* `query` is a **symbol name
   or a file path**. For a file, unions the blast radius of every symbol defined in
   it. Returns `{targets, direct_dependents, transitive_dependents, affected_files,
   affected_public_api, blast_radius}`. Run before editing.

3. **`lattice_hunt(root=None, severity_min="low")`** — post-edit bug gate. Ranked
   findings (`public_path_to_stub`, `obstruction`, `called_stub`, `broken_reference`,
   `dead_code`, ...), filtered by min severity. The "did I break something" check.

4. **`lattice_secaudit(root=None)`** — attack surface + source→sink reachability with
   the honest `verified` / `not_verified` contract and TAINTED-vs-reachable labels.

5. **`lattice_triage(root=None)`** — prioritized worklist, `priority = severity ×
   (1 + blast_radius)`.

6. **`lattice_refresh(root=None)`** — explicit rebuild. Returns what changed and the
   new graph stats. The freshness escape hatch.

## Error handling

Structured results, never exceptions through the protocol:
- Unknown symbol → `{error, suggestions: [...]}` via `resolve_targets` substring match.
- Unmapped repo → lazy auto-`map` on first call, noted in the response.
- Missing optional deps (mcp / LSP binary) → actionable message naming what to install.

## Testing (TDD)

- `tests/test_mcp_workspace.py` — cache miss→build, cache hit→load, staleness fires on
  touch/add/remove, refresh rebuilds the snapshot, full-reingest fallback.
- `tests/test_mcp_tools.py` — call each tool callable against a tmp Python repo fixture;
  assert shapes, the freshness block, impact-by-file, unknown-symbol suggestions,
  severity filtering.
- One smoke test: the server object exposes exactly the six tools.

Fixtures use Python (`python_ingest`, no LSP binary needed) so tests run anywhere.

## Packaging

- `[project.optional-dependencies] mcp = ["mcp>=1.2"]`
- `[project.scripts] lattice-mcp = "lattice.mcp.__main__:main"`
- `.gitignore` gains `.lattice/`.

## Client registration (documented in README)

```json
{
  "mcpServers": {
    "lattice": { "command": "lattice-mcp", "args": ["--root", "/path/to/repo"] }
  }
}
```
