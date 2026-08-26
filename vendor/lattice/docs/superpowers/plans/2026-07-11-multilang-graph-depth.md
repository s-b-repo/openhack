# Multi-language graph depth (Go, Rust, Ruby, C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring Go, Rust, Ruby, and bare C to full ts-equivalent hypernetwork depth (symbols, imports, call edges, exported flags, stub detection, entrypoints), and add stub detection to the Python frontend, so hunt/triage/impact/optimize work identically on those languages.

**Architecture:** One native-AST frontend per language emitting the universal RawIngest (the seam stated in cache.ingest_source: "you add ONE frontend here, nothing else changes"). Go extends the existing go/parser bridge additively with a graph mode; Rust gets a new syn-based crate (tools/rustgraph) because tools/rustast has uncommitted in-flight changes; Ruby gets a Ripper script beside the existing taint bridge; C is a glob fix routing into the existing libclang cpp frontend.

**Tech Stack:** Python 3.13 frontends, Go 1.25 bridge (stdlib go/parser), Rust crate (syn 2 + serde_json), Ruby stdlib Ripper, libclang. Tests with pytest, fixtures as real source trees.

## Global Constraints

- Branch `feat/multilang-graph-depth` in the worktree `/Users/hendrixx./Lattice-multilang`; never touch the main checkout at `/Users/hendrixx./Lattice` (it has uncommitted in-flight work).
- Do NOT touch files with in-flight changes: `taint_common.py` seams, `lsp_client._select_source_files` and `_entry_files_from_package_json` signatures, `cache._LANG_PROBES` javascript row (does not exist at HEAD; my additions are new rows only), `tools/rustast/**`, `mcp/workspace.py`.
- Every new frontend function signature: `X_ingest(root, language: str = "<canonical>") -> RawIngest`.
- Registration per language, five places: `cache.ingest_source` dispatch, `cache._LANG_ALIASES`, `cache._LANG_PROBES`, `cli/main.py::_LANG`, `builder._LANG_PREFIX` (explicit: go -> "go", rust -> "rs", ruby -> "rb"; the `language[:2]` fallback would collide rust/ruby).
- Tests fail first, observed red before implementation. Toolchain-dependent tests use `skipif` (repo convention, see tests/test_go_taint.py:14).
- Baseline before this work: 683 passed, 31 skipped, 16 deselected (with go bridge built and jsast npm ci done). That number may not regress.
- No em dash or en dash characters in any produced content. No AI-authorship trailers.
- Conventional-commit style messages matching repo history (`feat(ingest): ...`).

## The fixed point (Task 1, before all implementation)

`tests/acceptance/test_fixed_point_multilang.py`, hash-pinned in `.fixed-point-multilang.sha`, checked via `shasum -a 256 -c`. Written from user intent: "make Lattice as deep for the other languages as it is for TypeScript". It runs the REAL CLI (`sys.executable -m lattice.cli.main`) as a subprocess per language over planted-bug fixture trees and asserts the flagship cross-signal finding:

```text
Given a Go / Rust / Ruby fixture repo whose exported entry function
transitively calls an unimplemented stub through an internal helper,
when the developer runs `lattice hunt <fixture> --lang <go|rs|rb> --out bugs.json`,
then bugs.json contains a critical public_path_to_stub naming that stub,
and `lattice ingest` on the same fixture exits 0 with a graph containing
an imports edge, an entrypoint surface, and correct exported flags.
For C, `lattice ingest <fixture> --lang c` exits 0 with function symbols
and the serve -> process call edge (the cpp frontend has no stub model yet).
```

Fixtures: `tests/fixtures/go_deep/`, `rust_deep/`, `ruby_deep/`, `c_deep/`. Each plants: exported entry -> internal helper -> stub; one uncalled function; one cross-file import; one entrypoint marker (package main + func main / src/main.rs / shebang / main()).

## File structure

```
tools/goast/go_ast.go            MODIFY additively: -mode graph flag, graph JSON emitter
tools/rustgraph/Cargo.toml       NEW crate
tools/rustgraph/src/main.rs      NEW: syn walker -> graph JSON per file
tools/rubyast/ruby_graph.rb      NEW: Ripper walker -> graph JSON per file
src/lattice/ingest/go_graph.py   NEW: go_ingest(root) -> RawIngest
src/lattice/ingest/rust_graph.py NEW: rust_ingest(root) -> RawIngest
src/lattice/ingest/ruby_graph.py NEW: ruby_ingest(root) -> RawIngest
src/lattice/ingest/cpp.py        MODIFY: add "*.c" to _EXTS
src/lattice/ingest/python_ast.py MODIFY: is_stub detection
src/lattice/cache.py             MODIFY: dispatch + aliases + probes rows
src/lattice/cli/main.py          MODIFY: _LANG adds go, rs, rb, c
src/lattice/graph/builder.py     MODIFY: _LANG_PREFIX adds go/rs/rb
tests/acceptance/test_fixed_point_multilang.py   NEW, pinned
tests/fixtures/{go,rust,ruby,c}_deep/            NEW fixture trees
tests/test_go_graph.py           NEW
tests/test_rust_graph.py         NEW
tests/test_ruby_graph.py         NEW
tests/test_c_ingest.py           NEW
tests/test_python_stub.py        NEW
```

## Bridge JSON contract (go graph mode, rustgraph, ruby_graph all emit the same shape per file)

```json
{
  "package": "api",              // go only; rust/ruby omit
  "entry": true,                 // file is an entrypoint candidate
  "imports": [{"path": "example.com/deep/api", "line": 3}],
  "symbols": [{"name": "Serve", "kind": "function|method|class|interface",
                "container": null, "start": 5, "end": 9, "exported": true,
                "stub": false, "params": ["req"], "extends": [], "implements": []}],
  "calls": [{"from_line": 6, "name": "process"}]
}
```

The Python frontend maps this to RawSymbol/RawReference, resolves imports to in-repo files (go: go.mod module prefix to directory; rust: mod/use to .rs file; ruby: require_relative to file), anchors calls at the enclosing symbol start line (python_ast.py:82-88 pattern), sets entry_files, and returns RawIngest.

## Per-language semantics

- **Go** (canonical "go", alias "go"): exported = first rune uppercase. kind: struct/interface types -> class/interface; func with receiver -> method, container = receiver base type; embedded struct names -> extends. Stub: body empty, or single panic call whose literal contains TODO / not implemented / unimplemented (case-insensitive), or body contains a TODO/FIXME comment and nothing else meaningful. Entry: package main containing func main. Imports: only paths under the go.mod module resolve (to_file = first .go file in that dir); external stay unresolved.
- **Rust** (canonical "rust", aliases "rs", "rust"): exported = any `pub` visibility. struct/enum -> class, trait -> interface; `impl T` fn -> method container T; `impl Tr for T` -> T implements Tr and its fns are methods of T. Stub: body is exactly todo!()/unimplemented!() (statement or trailing expr) or empty. Entry: src/main.rs or src/bin/*.rs containing fn main. Imports: `mod x;` resolves to x.rs or x/mod.rs relative to the declaring file; `use crate::a::b` resolves to src/a/b.rs or src/a.rs when present.
- **Ruby** (canonical "ruby", aliases "rb", "ruby"): class -> class with superclass extends, `include M` -> implements; module -> class kind "class"; def -> method when inside class/module else function; `def self.x` container = enclosing class. exported = true until a bare `private`/`protected` marker appears in the class body, false after (public marker restores). Stub: body is exactly `raise NotImplementedError` or empty. Entry: shebang line or `if __FILE__ == $0` / `$PROGRAM_NAME`. Imports: require_relative resolved (append .rb); require unresolved reference.
- **C**: no new frontend. `_EXTS` gains `"*.c"`; probes gain the same; `_LANG["c"] = "cpp"` at the CLI (alias already exists in cache).
- **Python stub**: body consisting only of pass/Ellipsis/docstring, or a single `raise NotImplementedError`, or containing only a TODO/FIXME comment -> is_stub=True.

## Tasks

### Task 1: Fixed point, red
- [ ] Write the four fixture trees with planted signals (entry -> helper -> stub; uncalled fn; cross-file import; entrypoint marker).
- [ ] Write tests/acceptance/test_fixed_point_multilang.py running the real CLI per language; skipif toolchain missing.
- [ ] Run: every language case fails (unknown --lang value). Pin hash to .fixed-point-multilang.sha, add check to docs. Commit red.

### Task 2: Go graph depth
- [ ] tests/test_go_graph.py failing first: symbols with kinds/containers/exported, method receiver containment, stub via panic("not implemented"), imports edge resolved through go.mod, calls anchored at enclosing func, entry_files for package main, vertex prefix "go-sym:".
- [ ] Extend go_ast.go with -mode graph (default mode byte-identical for taint; assert via tests/test_go_taint.py still green). Implement go_graph.py with lazy `go build` of the bridge. Register in the five places. Green. Commit.

### Task 3: Rust graph depth
- [ ] tests/test_rust_graph.py failing first: pub fn exported, impl methods with container, trait impl -> implements, todo!() stub, mod/use import edges, src/main.rs entry, prefix "rs-sym:".
- [ ] Create tools/rustgraph crate (syn full features + serde_json), rust_graph.py with lazy `cargo build --release`, register. Green. Commit.

### Task 4: Ruby graph depth
- [ ] tests/test_ruby_graph.py failing first: class/module symbols, superclass extends, include -> implements, private visibility flips exported, raise NotImplementedError stub, require_relative import edge, shebang entry, prefix "rb-sym:".
- [ ] tools/rubyast/ruby_graph.rb (Ripper), ruby_graph.py, register. Green. Commit.

### Task 5: C ingestion + Python stubs
- [ ] tests/test_c_ingest.py failing first (bare .c fixture yields function symbols + call edge via --lang c path); tests/test_python_stub.py failing first (pass-only body, raise NotImplementedError, ... body, TODO-comment body all is_stub; a real body is not).
- [ ] Add "*.c" to cpp _EXTS + probes + CLI value; implement _is_stub in python_ast._visit_func. Green. Commit.

### Task 6: Fixed point green + audit + ship
- [ ] Run the pinned fixed point: all languages green. Verify pin unchanged.
- [ ] Full suite: baseline 683 passing tests still pass plus the new ones.
- [ ] Hand-mutation checks (mutmut is impractical here; say so): invert exported detection per language, disable stub detection per language, drop import resolution per language; each must kill at least one named test.
- [ ] Update README language table. Commit, push branch, open draft PR.

## Self-review notes

- Spec coverage: "as deep as ts" = the RawIngest capability matrix; dynamic dispatch stays TS-only by design (per docs/superpowers/specs/2026-06-13-lattice-dynamic-dispatch-recall-design.md: dispatch-site detection is per-frontend, out of scope here). Documented as such in the README table.
- Collision review: cache.py rows and _LANG additions are new lines adjacent to in-flight edits, mergeable; taint modules untouched; rustast untouched (new crate instead).
- Known simplifications recorded in each frontend docstring: name-level call resolution (same tier as python/solidity frontends), no cross-file type inference.
