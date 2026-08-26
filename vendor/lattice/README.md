# Lattice

Multi-domain structural-analysis engine built on the RRT principles of defi-v2, generalized via LSP.

**Phase 1 (this milestone):** TypeScript/JavaScript, Python, Go, Rust, Ruby,
Solidity, C/C++/CUDA, shell, SQL, and IaC source -> a shared typed
hypernetwork -> mapping-completeness gate -> recall persistence.

## Usage
    .venv/bin/python -m lattice.cli.main ingest <path> --lang ts \
        --project lattice --db ~/.recall/db/lattice.sqlite3 --out hypernetwork.json

Outputs `hypernetwork.json` + `hypernetwork-report.json`; exits non-zero if the completeness gate fails (use `--allow-partial` to override). With `--db`, persists vertices + a completeness report to recall.

Install all optional Python legs with `pip install -e '.[dev,cpp,symbolic,mcp]'`.
Native frontends also require their matching runtime/toolchain on `PATH`: Go for
`go`, Cargo/Rust for `rs`, Ruby for `rb`, Node/npm plus
`typescript-language-server` for `ts`/`js`, and libclang for `c`/`cpp`/`cu`.

### Triage (`triage`) — prioritized worklist
    .venv/bin/python -m lattice.cli.main triage <path> --lang ts

Ranks every bug by **priority = severity × (1 + blast radius)** — severity says how
bad, impact analysis says how far it reaches. The ranking routes through the compute
seam (solver `triage`/`skim` when wired, local sort otherwise).

### Optimize (`optimize`) — structural improvement suggestions
    .venv/bin/python -m lattice.cli.main optimize <path> --lang ts

- **break_cycle** — minimal edges to remove to make a dependency cycle acyclic
  (minimum feedback arc set; the solver QUBO leg — `deadbolt`/`lockout` — gives the
  optimal cut, local gives a greedy one)
- **reduce_coupling** — high fan-in+fan-out hotspots worth splitting

Each suggestion carries `provenance` (`local` or `solver:deadbolt`) so you can see
which legs computed it. See `compute.py` for the solver seam.

**Solver legs.** Set `FOOTINGS_SOLVER=1` to route the hard combinatorial step
(minimum feedback arc set) to the gated `solver` suite on the z6 over SSH — an exact
QUBO solve (`deadbolt`) instead of the local greedy heuristic. The bridge
(`solver_bridge.py`) **verifies the solver's cut locally before trusting it** and
falls back to local if it doesn't break the cycle or the solver is unreachable —
the solver gives the optimal legs, Footings keeps the correctness guarantee.
Configure with `FOOTINGS_SOLVER_HOST` / `FOOTINGS_SOLVER_ROOT`.

### Bug hunter (`hunt`) — prioritized structural bugs
    .venv/bin/python -m lattice.cli.main hunt <path> --lang ts

Ranked bug findings (critical → low) from composed signals, merged with the logic
paradox audit:
- **public_path_to_stub** (critical) — an exported path reaches unimplemented code
- **obstruction** (high) — broken reference inside a dependency cycle (RRT H₁ witness)
- **called_stub** (high) — an unimplemented stub is referenced by callers
- **broken_reference** (high) — unresolved reference to an internal symbol
- **dead_branch / redundant_guard** (medium/low) — from the logic audit
- **dead_code** (low) — unreachable from any public API

The edge is the cross-signal patterns: `public_path_to_stub` is a real bug no single
diagnostic shows. `--fail-on-bugs` gates CI on any critical/high finding.

### Impact analysis (`impact`) — change blast radius
    .venv/bin/python -m lattice.cli.main impact <path> <symbol> --lang ts

Reverse-reachability over the graph: everything that transitively depends on a
symbol — the set of dependents, files, and **public-API surfaces** a change could
affect. Run it *before* editing. Flags when a change reaches an exported surface
(the external blast radius the graph can otherwise hide).

### Security audit (`secaudit`) — attack surface + source→sink reachability
    .venv/bin/python -m lattice.cli.main secaudit <path> --lang ts

Enumerates the attack surface (public_api / entrypoint / external_call / trust_boundary)
and reports which entrypoints can **reach** dangerous sinks (command exec, SQL, deserialize,
XSS, SSRF, file access — classified by name heuristic), with the path. Also flags
unimplemented code reachable from a public entrypoint. Names matching only the generic
word `query` (getQueryParams, useQuery, queryClient...) are reported as
`sql_injection_possible` at **low** severity — demoted, never dropped (FIRE=lead /
SILENCE≠proof) — while strong tokens (`rawSql`, `executeQuery`, a function literally
named `query`, ...) keep full severity.

Catches **external library-call sinks** (`spawn(cmd)`, `db.query(...)`, `eval(x)`) even
when the callee isn't a defined symbol, by scanning call sites and mapping them to the
enclosing function. Each finding is labeled **TAINTED** vs **reachable**:
*interprocedural taint* tracks whether the entrypoint's parameters (or request-source
identifiers, propagated through local assignments like `const id = req.body.id` and
across call edges via tainted parameters and returns) flow into the sink's arguments —
so a literal `spawn("ls")` reads as reachable, while `spawn(cmd)` reads as tainted.

**Honest by construction.** With source, the contract is
`verified: [call_reachability, attack_surface]` — plus `interprocedural_taint` once an
input flow is actually established — and `not_verified: [exploitability, input_validation]`.
Reachability/taint is still not proof of exploitability: it tells you where to look and
which paths carry input, not that a vuln is confirmed. Authorized/defensive use on your
own code.

For the complete Solidity detector suite, use `lattice intake <path> --lang sol`
(or `python -m lattice.cold_audit <path> --json`). The payload runs the structural,
typed, oracle-taint, donation-griefing, arbitrary-call, and AMM-invariant legs and
includes `analysis_coverage`. A failed or unavailable leg becomes an escalated blind
spot; it is never represented as an empty clean result.

### Follow (`follow`) — trace impact chains
    .venv/bin/python -m lattice.cli.main follow <path> <symbol> --lang ts

Shows *how* a change propagates, not just the set it reaches: the dependency chains
from a symbol outward to each top-level caller / public API (`bar → foo → handler`).

### Plan (`plan`) — ordered steps to land a change reliably
    .venv/bin/python -m lattice.cli.main plan <path> <symbol> --kind modify

RRT backward planning in structural form: from the goal (change landed + green),
collect the preconditions in safe order — implement-if-stub → change target →
**verify** → update dependents in reverse-dependency layers, with a verification gate
after each layer. Flags public-API crossings (external coordination needed) and
dependency-cycle risk (no clean order — must change together). Pairs with `verify`:
`plan` says what to do, `verify` confirms each step landed.

### Diagnostics (`diagnose`) — the structural microscope
    .venv/bin/python -m lattice.cli.main diagnose <path> --lang ts

Runs every structural signal over the graph and surfaces issues in one pass:
- **cycles** — circular import/call dependencies (Tarjan SCC)
- **dead_code** — symbols unreachable from any public_api / entrypoint surface
- **stubs** — unimplemented / TODO / empty-body symbols
- **hotspots** — highest-coupling symbols ranked by fan_in + fan_out
- **dangling_edges / unresolved_imports** — broken structure (from the completeness gate)
- **reconciliation_candidates** — cross-language `reconciles` proposals (confidence-tagged)

Informational by default (exit 0); pass `--fail-on-issues` to gate CI, `--out` to write the full JSON report. This is the layer that turns the hypernetwork from a map into an instrument.

### Exchange status (`exchange-status`) — StrayLight/Deck integration payload
    .venv/bin/python -m lattice.cli.main exchange-status <path> --lang auto --pretty

Emits an authority-neutral JSON status payload for Exchange and Deck:
- graph size and kind counts
- completeness verdict, resolution, and edge-recall coverage
- diagnostics counts: cycles, dead code, stubs, obstructions, hotspots
- surface inventory for public APIs, entrypoints, external calls, and trust boundaries

Every emitted surface is `observer_only`, `control_authority: false`, and `writes: []`.
Lattice reports structure; Exchange and Guard own action.

### Differential gate (`verify`) — self-verification for AI changes
    .venv/bin/python -m lattice.cli.main verify <path> --against HEAD --lang ts

Compares the **working tree** against a git ref (default `HEAD`) and reports only the structural regressions the change *caused* — not the absolute state of the whole tree. Exits non-zero (`--allow-regression` to override) when the change introduces any of:
- `new_unresolved_imports` — an import that resolves to nothing
- `new_dangling_edges` — a new unresolved internal reference
- `new_error_diagnostics` — a parser, bridge, or language-server failure introduced by the change
- `broken_by_removal` — deleted a symbol something still references
- `removed_public_api` — deleted an exported function/method (strict policy: `public_api` is the external surface the graph can't see callers of, so a deletion it can't prove safe is flagged rather than certified clean)

If an error diagnostic exists on both sides, the change did not cause it, but the
comparison still cannot establish a clean result; the verdict is `unverifiable` and
the command exits non-zero. The baseline is materialized in a throwaway detached git
worktree, so the working tree is never touched. The `DiffReport` carries an explicit
`verified: [structural_delta]` / `not_verified: [correctness, intent,
runtime_behavior]` contract — it certifies structural integrity of the delta, **not**
correctness.

## Languages

Full graph depth means: symbols with containment, import edges, call/reference
edges, exported flags, stub flags, inheritance, and entrypoint surfaces, so
hunt/triage/impact/optimize (including `public_path_to_stub`) work unchanged.

| `--lang` | frontend | depth |
| --- | --- | --- |
| `ts`, `js` | LSP (typescript-language-server) | full graph + dynamic dispatch |
| `py` | stdlib ast | full graph incl. stub detection |
| `go` | packaged `_bridges/goast` (go/parser, `-mode graph`) | full graph incl. stub detection |
| `rs` | packaged `_bridges/rustgraph` (syn) | full graph incl. stub detection |
| `rb` | packaged `_bridges/rubyast/ruby_graph.rb` (Ripper) | full graph incl. stub detection |
| `sol` | solc AST | full graph + dedicated audit suite |
| `cpp`, `cu`, `c` | libclang | full graph (no stub/export model yet) |
| `sh`, `sql`, `iac` | regex | partial structure |
| `auto` | detect + union | all of the above per detection |

Computed-member dynamic-dispatch discovery stays TS/JS-only for now (dispatch-site detection is
per-frontend by design). Bridge sources and dependency locks ship in the wheel;
Go/Rust binaries and locked Node dependencies are built lazily into a writable,
content-addressed user cache (override its location with `LATTICE_BRIDGE_CACHE`).
Ruby runs its packaged Ripper scripts directly.
The acceptance gate for the go/rs/rb/c depth is
`tests/acceptance/test_fixed_point_multilang.py`, hash-pinned in
`.fixed-point-multilang.sha`.

## MCP server — structural feedback for coding agents
    pip install -e '.[mcp]'
    lattice-mcp --root /path/to/repo          # or: python -m lattice.mcp --root <repo>

Exposes Lattice's analyses to any MCP-speaking agent (Claude Code, Cursor, …) over
stdio, backed by a graph **ingested once and queried in milliseconds**. The point is
the agent edit loop Lattice is built for: ask `lattice_impact` *before* an edit (what
does this touch?), gate with `lattice_hunt` *after* (did it break the structure?).

Six tools — `lattice_map` (ingest/load), `lattice_impact` (blast radius; takes a symbol
**or a file path**), `lattice_hunt` (ranked bugs, `severity_min` floor), `lattice_secaudit`,
`lattice_triage`, `lattice_refresh`. Every response carries a `freshness` block
(`stale`, `changed_files`, hint) so the agent serves cached answers instantly and knows
exactly when to call `lattice_refresh`. The graph caches under `<root>/.lattice/`
(git-ignored); analyses recover the source root from the cache, so taint/secaudit work
from the cache with no re-ingest.

Register it with a client:
```json
{ "mcpServers": {
    "lattice": { "command": "lattice-mcp", "args": ["--root", "/path/to/repo"] } } }
```

Freshness *detection* (mtime diff) covers source plus graph-affecting metadata such as
package.json, tsconfig/jsconfig, Cargo.toml, go.mod, and build manifests;
`lattice_refresh` is a full re-ingest in v1. Bug-hunt depth tracks ingest depth and is
richest on TypeScript/JavaScript; native frontends use conservative,
confidence-labeled fallbacks where receiver/type identity cannot be proven.
See `docs/superpowers/specs/2026-06-09-lattice-mcp-server-design.md`.

**Measured (defi-v2/src, 22 TS files, live over stdio):** cold ingest **3.7s** →
1624 vertices / 1094 edges; warm `map` from cache **6ms**, warm `hunt` **2ms** (a ~600×
gap — and it widens with repo size). `impact` before an edit returned real blast radii
(`relativeFile` → 26 dependents across 5 files; `GraphEdge` → 83) and a controlled
public-path-to-stub was caught as a `critical` `hunt` finding and ranked by `triage`.
Dogfooding the server against the real repo also surfaced and fixed short-language-code
normalization (`language:"ts"` -> `typescript`). LSP startup, shutdown, and requests
now have a finite `LATTICE_LSP_TIMEOUT` budget so a broken server fails explicitly
instead of hanging a long-lived agent.

## Status / acceptance
Run on `defi-v2/src` (22 TS files): **vertices=1497, hyperedges=1092, verdict=pass, resolution=1.000, coverage=1.00 (203/204 functions referenced)**. `hunt` reports **1 finding** — a genuinely dead `help()` function — down from 1518 before finding-precision fixes. Edge recall and finding precision were lifted by: ingesting function-valued consts, keeping all project buffers open during reference resolution, attributing top-level call sites to the module, filtering LSP synthetic symbols, and tightening the stub heuristic (a function that merely *throws* or has a `// TODO` is no longer a stub).

**Honest reading of these numbers:** `resolution=1.000` means every edge that *exists* resolves — it does **not** mean the graph is complete. `coverage=0.59` (195/331 functions have a detected inbound reference) is a recall indicator: a low value conflates genuinely-uncalled functions (dead/leaf/public-API exports) with real edge-recall misses, and the two can't be separated without ground truth. Measured edge recall against a (noisy, over-counting) grep proxy on an independent 50-file project was ~80%, with misses concentrated in class methods and common library-call names. Downstream analyses (impact, taint, obstruction) are only as complete as the edges — treat coverage as the foundation's confidence dial, not a guarantee.

## Architecture & roadmap
See `docs/superpowers/specs/2026-06-01-lattice-phase1-design.md` (design + 4-phase roadmap) and `docs/superpowers/plans/2026-06-01-lattice-phase1.md` (Phase 1 plan).

Phase 2+: RRT obstruction analysis, solver-backed scoring/calibration, witness families, multi-language adapters.

## Known Phase 1 limitations
- LSP-grade reference precision is TS/JS-only. Native/AST frontends resolve
  qualified identities when available and otherwise emit calibrated ambiguous
  dispatch/external leads; they do not claim the first same-named definition as a fact.
- Reflection, macro-generated code, runtime module loading, and receiver types the
  native bridges cannot infer remain explicit edge-recall limits.
- recall persistence admits one cell per vertex (subprocess each) — batch admit is a Phase 2 optimization.
- A relative import to a file with zero ingested symbols is flagged as a broken import (rare false-positive on symbol-less type-only files).
