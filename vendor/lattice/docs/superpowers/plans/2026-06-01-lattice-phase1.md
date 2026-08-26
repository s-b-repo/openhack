# Lattice Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn any TypeScript codebase into a verified, recall-persisted typed hypernetwork via LSP — the foundation the later RRT analysis phases reason over.

**Architecture:** A Python pipeline of small, single-responsibility layers: `ingest` (multilspy LSP → language-neutral `RawIngest`), `graph` (pure transform `RawIngest → Hypernetwork`), `complete` (pure gate `Hypernetwork → HypernetworkReport`), `memory` (persist to recall), and a thin `cli` orchestrator. The pure layers are TDD'd with fixtures; the two layers touching external systems (LSP, recall) have integration tests against a committed TS fixture and a temp recall DB.

**Tech Stack:** Python 3.13, multilspy (LSP client), typescript-language-server (already on PATH), pytest, recall CLI + `recall_helper.py`/`recall_code_link.py`.

---

## File structure

```
~/Lattice/
  pyproject.toml
  src/lattice/
    __init__.py
    ingest/__init__.py
    ingest/types.py          # RawSymbol, RawReference, RawIngest (LSP-agnostic)
    ingest/lsp_client.py     # multilspy → RawIngest (TypeScript)
    graph/__init__.py
    graph/models.py          # Vertex, Hyperedge, Surface, Hypernetwork
    graph/builder.py         # build(RawIngest) -> Hypernetwork  (pure)
    complete/__init__.py
    complete/report.py       # HypernetworkReport
    complete/gate.py         # check(Hypernetwork) -> HypernetworkReport  (pure)
    memory/__init__.py
    memory/recall_sink.py    # persist(Hypernetwork, report, db_path) via recall
    cli/__init__.py
    cli/main.py              # `lattice ingest <path> --lang ts`
  tests/
    fixtures/ts_sample/      # tiny TS repo with known symbols/refs/a stub
    test_models.py
    test_builder.py
    test_gate.py
    test_lsp_client.py       # integration (TS fixture)
    test_recall_sink.py      # integration (temp recall DB)
    test_cli.py              # integration (full pipeline on fixture)
```

Boundaries: `ingest/types.py` is the seam that decouples `graph/builder` from multilspy, so the builder and gate are pure and fully unit-testable without a language server.

---

## Task 0: Project scaffold + environment

**Files:**
- Create: `pyproject.toml`, `src/lattice/__init__.py`, all package `__init__.py` files
- Create: `.python-version` (optional)

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[project]
name = "lattice"
version = "0.1.0"
description = "Multi-domain structural-analysis engine (LSP hypernetwork + RRT)"
requires-python = ">=3.11"
dependencies = ["multilspy>=0.0.10"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
lattice = "lattice.cli.main:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
```

- [ ] **Step 2: Create package skeleton**

```bash
cd ~/Lattice
mkdir -p src/lattice/{ingest,graph,complete,memory,cli} tests/fixtures/ts_sample
for d in lattice lattice/ingest lattice/graph lattice/complete lattice/memory lattice/cli; do touch "src/$d/__init__.py"; done
```

- [ ] **Step 3: Create venv and install**

```bash
cd ~/Lattice
python3 -m venv .venv
.venv/bin/python -m pip install -q -e ".[dev]"
```
Expected: installs `lattice` (editable), `multilspy`, `pytest` with no errors.

- [ ] **Step 4: Verify multilspy API surface (do NOT assume — confirm against installed version)**

```bash
.venv/bin/python - <<'PY'
from multilspy import SyncLanguageServer
from multilspy.multilspy_config import MultilspyConfig
from multilspy.multilspy_logger import MultilspyLogger
print("create:", hasattr(SyncLanguageServer, "create"))
print("methods:", [m for m in dir(SyncLanguageServer) if m.startswith(("request","start"))])
PY
```
Expected: `create: True` and a list including `request_document_symbols`, `request_references`, `request_definition`, `start_server`. **If method names differ in the installed version, record the actual names and use them in Task 5** (this is the only place they're used).

- [ ] **Step 5: Register the Lattice recall project**

```bash
cd ~/Lattice && recall project init --slug lattice --description "Lattice structural-analysis hypernetworks"
recall project where   # expect: matched project 'lattice' -> ~/.recall/db/lattice.sqlite3
```

- [ ] **Step 6: Commit**

```bash
cd ~/Lattice && git add -A && git commit -m "chore: scaffold lattice package + env + recall project"
```

---

## Task 1: Raw ingest types (LSP-agnostic seam)

**Files:**
- Create: `src/lattice/ingest/types.py`
- Test: `tests/test_models.py` (shared with Task 2; create here, extend there)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
from lattice.ingest.types import RawSymbol, RawReference, RawIngest

def test_raw_ingest_round_trips():
    sym = RawSymbol(name="foo", kind="function", file="a.ts",
                    start_line=1, end_line=3, container=None,
                    type="() => void", exported=True, is_stub=False)
    ref = RawReference(kind="calls", from_file="a.ts", from_line=2,
                       to_file="b.ts", to_line=10, resolved=True)
    ing = RawIngest(language="typescript", root="/x", symbols=[sym],
                    references=[ref], diagnostics=[])
    assert ing.symbols[0].name == "foo"
    assert ing.references[0].kind == "calls"
    assert ing.language == "typescript"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_models.py::test_raw_ingest_round_trips -v`
Expected: FAIL with `ModuleNotFoundError` / `ImportError: cannot import name 'RawSymbol'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/lattice/ingest/types.py
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class RawSymbol:
    name: str
    kind: str                 # LSP-derived symbol kind, lowercased
    file: str                 # path relative to root
    start_line: int
    end_line: int
    container: str | None = None   # enclosing symbol name, if any
    type: str | None = None        # declared type / signature, if LSP exposes it
    exported: bool = False
    is_stub: bool = False          # empty body / TODO / "not implemented"

@dataclass
class RawReference:
    kind: str                 # "imports" | "calls" | "references"
    from_file: str
    from_line: int
    to_file: str | None = None
    to_line: int | None = None
    resolved: bool = False

@dataclass
class RawIngest:
    language: str
    root: str
    symbols: list[RawSymbol] = field(default_factory=list)
    references: list[RawReference] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_models.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/Lattice && git add -A && git commit -m "feat(ingest): add LSP-agnostic RawIngest types"
```

---

## Task 2: Hypernetwork model

**Files:**
- Create: `src/lattice/graph/models.py`
- Test: `tests/test_models.py` (extend)

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_models.py
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork, SCHEMA_VERSION

def test_hypernetwork_json_round_trips():
    v = Vertex(id="ts-sym:a.ts#foo", kind="function", name="foo", file="a.ts",
               start_line=1, end_line=3, type=None, exported=True, stub=False)
    e = Hyperedge(id="e1", kind="calls", members=["ts-sym:a.ts#foo", "ts-sym:b.ts#bar"],
                  directed=True, resolved=True)
    s = Surface(id="s1", vertex_id="ts-sym:a.ts#foo", kind="public_api")
    net = Hypernetwork(language="typescript", root="/x",
                       vertices=[v], hyperedges=[e], surfaces=[s])
    d = net.to_dict()
    assert d["schema_version"] == SCHEMA_VERSION
    net2 = Hypernetwork.from_dict(d)
    assert net2.vertices[0].id == v.id
    assert net2.hyperedges[0].members == e.members
    assert net2.surfaces[0].kind == "public_api"
    assert net2.stats["vertices"] == 1 and net2.stats["hyperedges"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_models.py::test_hypernetwork_json_round_trips -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/lattice/graph/models.py
from __future__ import annotations
from dataclasses import dataclass, field, asdict

SCHEMA_VERSION = "lattice.hypernetwork.v1"

@dataclass
class Vertex:
    id: str
    kind: str          # module|class|interface|function|method|variable|type|external
    name: str
    file: str
    start_line: int
    end_line: int
    type: str | None = None
    exported: bool = False
    stub: bool = False

@dataclass
class Hyperedge:
    id: str
    kind: str          # imports|calls|references|inherits|implements|defines|returns
    members: list[str]
    directed: bool = True
    resolved: bool = False

@dataclass
class Surface:
    id: str
    vertex_id: str
    kind: str          # entrypoint|external_call|public_api|trust_boundary

@dataclass
class Hypernetwork:
    language: str
    root: str
    vertices: list[Vertex] = field(default_factory=list)
    hyperedges: list[Hyperedge] = field(default_factory=list)
    surfaces: list[Surface] = field(default_factory=list)

    @property
    def stats(self) -> dict:
        return {"vertices": len(self.vertices),
                "hyperedges": len(self.hyperedges),
                "surfaces": len(self.surfaces)}

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "language": self.language,
            "root": self.root,
            "vertices": [asdict(v) for v in self.vertices],
            "hyperedges": [asdict(e) for e in self.hyperedges],
            "surfaces": [asdict(s) for s in self.surfaces],
            "stats": self.stats,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Hypernetwork":
        return cls(
            language=d["language"],
            root=d["root"],
            vertices=[Vertex(**v) for v in d.get("vertices", [])],
            hyperedges=[Hyperedge(**e) for e in d.get("hyperedges", [])],
            surfaces=[Surface(**s) for s in d.get("surfaces", [])],
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_models.py -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
cd ~/Lattice && git add -A && git commit -m "feat(graph): add typed Hypernetwork model with JSON contract"
```

---

## Task 3: Graph builder (pure transform)

**Files:**
- Create: `src/lattice/graph/builder.py`
- Test: `tests/test_builder.py`

Builder rules:
- Vertex id = `f"{lang_prefix}-sym:{file}#{qualified_name}"` where `qualified_name` joins container + name with `.`; `lang_prefix` = `ts` for typescript.
- Map each `RawSymbol` to a `Vertex`, copying `is_stub → stub`.
- Build a position index: for a `(file, line)`, find the smallest-range enclosing vertex.
- For each `RawReference`: `from` resolves to the enclosing vertex of `(from_file, from_line)`; `to` resolves to enclosing vertex of `(to_file, to_line)` when present. If `to` is missing or maps to no vertex, create/reuse an `external` placeholder vertex `ts-sym:<external>#<to_file or unknown>` and mark the edge `resolved=False`.
- Surfaces: exported vertices of kind `function`/`method` → `public_api`; edges to an `external` vertex → an `external_call` surface on the `from` vertex.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_builder.py
from lattice.ingest.types import RawSymbol, RawReference, RawIngest
from lattice.graph.builder import build

def _ingest():
    foo = RawSymbol(name="foo", kind="function", file="a.ts", start_line=1, end_line=5,
                    exported=True, is_stub=False)
    bar = RawSymbol(name="bar", kind="function", file="b.ts", start_line=1, end_line=4,
                    exported=False, is_stub=True)
    call = RawReference(kind="calls", from_file="a.ts", from_line=3,
                        to_file="b.ts", to_line=2, resolved=True)
    ext = RawReference(kind="calls", from_file="a.ts", from_line=4,
                       to_file=None, to_line=None, resolved=False)
    return RawIngest(language="typescript", root="/x",
                     symbols=[foo, bar], references=[call, ext], diagnostics=[])

def test_build_creates_vertices_edges_surfaces():
    net = build(_ingest())
    ids = {v.id for v in net.vertices}
    assert "ts-sym:a.ts#foo" in ids and "ts-sym:b.ts#bar" in ids
    # one resolved internal call edge
    resolved = [e for e in net.hyperedges if e.resolved and e.kind == "calls"]
    assert any(e.members == ["ts-sym:a.ts#foo", "ts-sym:b.ts#bar"] for e in resolved)
    # external ref produced an unresolved edge + external vertex
    assert any(v.kind == "external" for v in net.vertices)
    assert any(not e.resolved for e in net.hyperedges)
    # exported function -> public_api surface; external call -> external_call surface
    skinds = {s.kind for s in net.surfaces}
    assert "public_api" in skinds and "external_call" in skinds
    # stub propagated
    assert next(v for v in net.vertices if v.name == "bar").stub is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_builder.py -v`
Expected: FAIL with `ImportError: cannot import name 'build'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/lattice/graph/builder.py
from __future__ import annotations
from lattice.ingest.types import RawIngest, RawSymbol
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork

_LANG_PREFIX = {"typescript": "ts", "javascript": "js", "python": "py"}

def _qualified(sym: RawSymbol) -> str:
    return f"{sym.container}.{sym.name}" if sym.container else sym.name

def _vid(prefix: str, file: str, qualified: str) -> str:
    return f"{prefix}-sym:{file}#{qualified}"

def build(raw: RawIngest) -> Hypernetwork:
    prefix = _LANG_PREFIX.get(raw.language, raw.language[:2])
    vertices: dict[str, Vertex] = {}
    # symbols -> vertices
    for s in raw.symbols:
        vid = _vid(prefix, s.file, _qualified(s))
        vertices[vid] = Vertex(id=vid, kind=s.kind, name=s.name, file=s.file,
                               start_line=s.start_line, end_line=s.end_line,
                               type=s.type, exported=s.exported, stub=s.is_stub)
    # position index: file -> list of (start,end,vid) sorted by range size
    by_file: dict[str, list[tuple[int, int, str]]] = {}
    for v in vertices.values():
        by_file.setdefault(v.file, []).append((v.start_line, v.end_line, v.id))
    for lst in by_file.values():
        lst.sort(key=lambda t: (t[1] - t[0]))

    def enclosing(file: str | None, line: int | None) -> str | None:
        if file is None or line is None:
            return None
        for start, end, vid in by_file.get(file, []):
            if start <= line <= end:
                return vid
        return None

    hyperedges: list[Hyperedge] = []
    surfaces: list[Surface] = []
    ext_seen: set[str] = set()
    eid = 0
    for r in raw.references:
        src = enclosing(r.from_file, r.from_line)
        if src is None:
            continue  # reference not inside any known symbol
        tgt = enclosing(r.to_file, r.to_line)
        resolved = r.resolved and tgt is not None
        if tgt is None:
            key = r.to_file or "unknown"
            tgt = _vid(prefix, "<external>", key)
            if tgt not in ext_seen:
                ext_seen.add(tgt)
                vertices[tgt] = Vertex(id=tgt, kind="external", name=key,
                                       file="<external>", start_line=0, end_line=0)
            surfaces.append(Surface(id=f"surf-ext-{eid}", vertex_id=src,
                                    kind="external_call"))
        eid += 1
        hyperedges.append(Hyperedge(id=f"e{eid}", kind=r.kind,
                                    members=[src, tgt], directed=True, resolved=resolved))
    # public_api surfaces
    si = 0
    for v in vertices.values():
        if v.exported and v.kind in ("function", "method"):
            surfaces.append(Surface(id=f"surf-api-{si}", vertex_id=v.id, kind="public_api"))
            si += 1
    return Hypernetwork(language=raw.language, root=raw.root,
                        vertices=list(vertices.values()),
                        hyperedges=hyperedges, surfaces=surfaces)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_builder.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/Lattice && git add -A && git commit -m "feat(graph): build typed hypernetwork from RawIngest"
```

---

## Task 4: Completeness gate (pure)

**Files:**
- Create: `src/lattice/complete/report.py`, `src/lattice/complete/gate.py`
- Test: `tests/test_gate.py`

Gate thresholds (documented, plain-ratio; solver tightening is Phase 2):
- `resolution` = resolved edges / total edges (1.0 if no edges).
- `verdict = "fail"` if any `unresolved_imports`, else `"pass"` if `resolution >= 0.98` and no `dangling_edges` (excluding edges to `external` vertices), else `"partial"` if `resolution >= 0.85`, else `"fail"`.
- Stubs are reported but never fail the gate.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_gate.py
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.complete.gate import check

def _net(edges):
    vs = [Vertex(id="ts-sym:a.ts#foo", kind="function", name="foo", file="a.ts",
                 start_line=1, end_line=2, exported=True),
          Vertex(id="ts-sym:a.ts#imp", kind="external", name="lodash", file="<external>",
                 start_line=0, end_line=0)]
    return Hypernetwork(language="typescript", root="/x", vertices=vs, hyperedges=edges)

def test_clean_graph_passes():
    e = Hyperedge(id="e1", kind="calls", members=["ts-sym:a.ts#foo", "ts-sym:a.ts#foo"],
                  resolved=True)
    rep = check(_net([e]))
    assert rep.verdict == "pass"
    assert rep.resolution == 1.0

def test_unresolved_import_fails():
    e = Hyperedge(id="e1", kind="imports", members=["ts-sym:a.ts#foo", "ts-sym:missing#x"],
                  resolved=False)
    rep = check(_net([e]))
    assert rep.verdict == "fail"
    assert "ts-sym:missing#x" in str(rep.unresolved_imports)

def test_external_call_not_counted_dangling():
    e = Hyperedge(id="e1", kind="calls", members=["ts-sym:a.ts#foo", "ts-sym:a.ts#imp"],
                  resolved=False)
    rep = check(_net([e]))
    # target is an 'external' vertex -> not a hard failure
    assert rep.verdict in ("pass", "partial")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_gate.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/lattice/complete/report.py
from __future__ import annotations
from dataclasses import dataclass, field, asdict

@dataclass
class HypernetworkReport:
    resolution: float
    dangling_edges: list[str] = field(default_factory=list)
    unresolved_imports: list[str] = field(default_factory=list)
    stubs: list[str] = field(default_factory=list)
    surface_coverage: dict = field(default_factory=dict)
    diagnostics: list[dict] = field(default_factory=list)
    verdict: str = "fail"
    failing_checks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
```

```python
# src/lattice/complete/gate.py
from __future__ import annotations
from lattice.graph.models import Hypernetwork
from lattice.complete.report import HypernetworkReport

def check(net: Hypernetwork) -> HypernetworkReport:
    external_ids = {v.id for v in net.vertices if v.kind == "external"}
    known_ids = {v.id for v in net.vertices}
    total = len(net.hyperedges)
    resolved = sum(1 for e in net.hyperedges if e.resolved)
    resolution = 1.0 if total == 0 else resolved / total

    dangling, unresolved_imports = [], []
    for e in net.hyperedges:
        targets_external = any(m in external_ids for m in e.members)
        missing = [m for m in e.members if m not in known_ids]
        if e.kind == "imports" and (missing or not e.resolved):
            unresolved_imports.extend(missing or [m for m in e.members[1:]])
        elif not e.resolved and not targets_external:
            dangling.append(e.id)

    stubs = [v.id for v in net.vertices if v.stub]
    surface_coverage = {"public_api": sum(1 for s in net.surfaces if s.kind == "public_api"),
                        "external_call": sum(1 for s in net.surfaces if s.kind == "external_call")}

    failing = []
    if unresolved_imports:
        failing.append("unresolved_imports")
    if dangling:
        failing.append("dangling_edges")

    if unresolved_imports:
        verdict = "fail"
    elif resolution >= 0.98 and not dangling:
        verdict = "pass"
    elif resolution >= 0.85:
        verdict = "partial"
    else:
        verdict = "fail"

    return HypernetworkReport(resolution=resolution, dangling_edges=dangling,
                              unresolved_imports=unresolved_imports, stubs=stubs,
                              surface_coverage=surface_coverage,
                              diagnostics=net_diagnostics(net),
                              verdict=verdict, failing_checks=failing)

def net_diagnostics(net: Hypernetwork) -> list[dict]:
    return []  # populated from LSP diagnostics in Task 5 via builder passthrough (Phase 2 enriches)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_gate.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
cd ~/Lattice && git add -A && git commit -m "feat(complete): add mapping-completeness gate"
```

---

## Task 5: LSP ingestion via multilspy (integration)

**Files:**
- Create: `src/lattice/ingest/lsp_client.py`
- Create fixture: `tests/fixtures/ts_sample/{a.ts,b.ts,tsconfig.json}`
- Test: `tests/test_lsp_client.py`

- [ ] **Step 1: Create the TS fixture repo**

```bash
mkdir -p ~/Lattice/tests/fixtures/ts_sample
cat > ~/Lattice/tests/fixtures/ts_sample/b.ts <<'TS'
export function bar(x: number): number {
  return x + 1;
}
export function stubbed(): void {
  // TODO: not implemented
}
TS
cat > ~/Lattice/tests/fixtures/ts_sample/a.ts <<'TS'
import { bar } from "./b";
export function foo(): number {
  return bar(41);
}
TS
cat > ~/Lattice/tests/fixtures/ts_sample/tsconfig.json <<'JSON'
{ "compilerOptions": { "strict": true, "moduleResolution": "node", "target": "ES2020" }, "include": ["*.ts"] }
JSON
```

- [ ] **Step 2: Write the failing integration test**

```python
# tests/test_lsp_client.py
import pathlib, pytest
from lattice.ingest.lsp_client import ingest

FIX = pathlib.Path(__file__).parent / "fixtures" / "ts_sample"

@pytest.mark.integration
def test_ingest_ts_fixture():
    raw = ingest(FIX, "typescript")
    names = {s.name for s in raw.symbols}
    assert {"foo", "bar", "stubbed"} <= names
    # import edge a.ts -> b.ts
    assert any(r.kind == "imports" and r.from_file.endswith("a.ts") for r in raw.references)
    # stub detection
    assert next(s for s in raw.symbols if s.name == "stubbed").is_stub is True
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_lsp_client.py -v`
Expected: FAIL with `ImportError: cannot import name 'ingest'`.

- [ ] **Step 4: Write the implementation**

> Uses the method names confirmed in Task 0 Step 4. If they differed, substitute them here. The `_symbol_kind_name` and `_is_stub` helpers keep the LSP-specific decoding isolated.

```python
# src/lattice/ingest/lsp_client.py
from __future__ import annotations
import pathlib
from lattice.ingest.types import RawSymbol, RawReference, RawIngest
from multilspy import SyncLanguageServer
from multilspy.multilspy_config import MultilspyConfig
from multilspy.multilspy_logger import MultilspyLogger

# LSP SymbolKind (subset) -> our vertex kind
_KIND = {5: "class", 6: "method", 11: "interface", 12: "function",
         13: "variable", 8: "field", 26: "type", 2: "module"}

def _symbol_kind_name(k: int) -> str:
    return _KIND.get(k, "variable")

def _is_stub(root: pathlib.Path, file: str, start: int, end: int) -> bool:
    try:
        lines = (root / file).read_text(encoding="utf-8").splitlines()[start - 1:end]
    except OSError:
        return False
    body = "\n".join(lines).lower()
    if "todo" in body or "not implemented" in body or "throw new error" in body:
        return True
    # empty body: braces with only whitespace/comment between
    inner = body.split("{", 1)[-1].rsplit("}", 1)[0] if "{" in body else ""
    return inner.strip().lstrip("/").strip() == ""

def _flatten(symbols, file, out, container=None):
    for s in symbols:
        rng = s.get("range") or s.get("location", {}).get("range", {})
        start = rng.get("start", {}).get("line", 0) + 1
        end = rng.get("end", {}).get("line", start - 1) + 1
        out.append((s.get("name", "?"), s.get("kind", 13), start, end, container))
        for child in s.get("children", []) or []:
            _flatten([child], file, out, container=s.get("name"))

def ingest(root: pathlib.Path, language: str) -> RawIngest:
    root = pathlib.Path(root).resolve()
    config = MultilspyConfig.from_dict({"code_language": language})
    lsp = SyncLanguageServer.create(config, MultilspyLogger(), str(root))
    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    ts_files = [p for p in root.rglob("*.ts") if "node_modules" not in p.parts]
    with lsp.start_server():
        for path in ts_files:
            rel = str(path.relative_to(root))
            raw_syms = lsp.request_document_symbols(rel)
            flat: list = []
            _flatten(raw_syms if isinstance(raw_syms, list) else raw_syms[0], rel, flat)
            for name, kind, start, end, container in flat:
                symbols.append(RawSymbol(
                    name=name, kind=_symbol_kind_name(kind), file=rel,
                    start_line=start, end_line=end, container=container,
                    exported=_exported(root, rel, start),
                    is_stub=_is_stub(root, rel, start, end)))
            # imports: parse top-of-file import lines (LSP-independent, robust)
            for i, line in enumerate((root / rel).read_text(encoding="utf-8").splitlines(), 1):
                if line.strip().startswith("import ") and " from " in line:
                    target = line.split(" from ")[-1].strip().strip(';"\'')
                    references.append(RawReference(kind="imports", from_file=rel,
                                                   from_line=i,
                                                   to_file=_resolve_import(target, rel),
                                                   to_line=1,
                                                   resolved=_resolve_import(target, rel) is not None))
    return RawIngest(language=language, root=str(root), symbols=symbols,
                     references=references, diagnostics=[])

def _exported(root: pathlib.Path, file: str, start_line: int) -> bool:
    try:
        line = (root / file).read_text(encoding="utf-8").splitlines()[start_line - 1]
    except (OSError, IndexError):
        return False
    return line.lstrip().startswith("export")

def _resolve_import(target: str, from_file: str) -> str | None:
    if not target.startswith("."):
        return None  # external package
    base = (pathlib.Path(from_file).parent / target).as_posix().lstrip("./")
    return f"{base}.ts"
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_lsp_client.py -v -m integration`
Expected: PASS. If multilspy fails to launch the TS server, confirm `typescript-language-server --version` works and that `MultilspyConfig` accepts `code_language="typescript"`; adjust per the API confirmed in Task 0.

- [ ] **Step 6: Register the `integration` marker and commit**

```bash
printf '\n[tool.pytest.ini_options]\nmarkers = ["integration: touches external systems (LSP/recall)"]\n' >> ~/Lattice/pyproject.toml
# (merge into the existing [tool.pytest.ini_options] table rather than duplicating)
cd ~/Lattice && git add -A && git commit -m "feat(ingest): multilspy TS ingestion + fixture repo"
```

---

## Task 6: recall persistence (integration, temp DB)

**Files:**
- Create: `src/lattice/memory/recall_sink.py`
- Test: `tests/test_recall_sink.py`

Approach: reuse the proven recall write path. Build one proposal per vertex via `recall_helper.build_proposal` (entities include the symbol tag `ts-sym:<name>` and, for import targets, `ts-import:<module>`), admit each via `recall admit --json --db <db>`, then run the existing `recall_code_link.py --db <db> --apply` to materialize typed hyperedges from the entity tags. This reuses tooling already validated on the defi extraction.

- [ ] **Step 1: Write the failing integration test**

```python
# tests/test_recall_sink.py
import json, subprocess, tempfile, pathlib, pytest
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.complete.report import HypernetworkReport
from lattice.memory.recall_sink import persist

def _status_nodes(db):
    out = subprocess.run(["recall", "--db", db, "status"], capture_output=True, text=True).stdout
    return json.loads(out)["stats"]["nodes"]

@pytest.mark.integration
def test_persist_writes_cells(tmp_path):
    db = str(tmp_path / "lattice_test.sqlite3")
    subprocess.run(["recall", "init", "--db", db], check=True, capture_output=True)
    v = Vertex(id="ts-sym:a.ts#foo", kind="function", name="foo", file="a.ts",
               start_line=1, end_line=3, exported=True)
    net = Hypernetwork(language="typescript", root="/x", vertices=[v], hyperedges=[])
    rep = HypernetworkReport(resolution=1.0, verdict="pass")
    persist(net, rep, db_path=db, project="lattice-test")
    assert _status_nodes(db) >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_recall_sink.py -v -m integration`
Expected: FAIL with `ImportError: cannot import name 'persist'`.

- [ ] **Step 3: Verify the recall_helper import path, then implement**

Confirm the helper location used elsewhere in this machine: `/Users/hendrixx./.claude/skills/recall/scripts/recall_helper.py` (provides `build_proposal`). Implementation:

```python
# src/lattice/memory/recall_sink.py
from __future__ import annotations
import json, subprocess, sys, tempfile, pathlib
from lattice.graph.models import Hypernetwork
from lattice.complete.report import HypernetworkReport

_RECALL_SCRIPTS = "/Users/hendrixx./.claude/skills/recall/scripts"
sys.path.insert(0, _RECALL_SCRIPTS)
from recall_helper import build_proposal  # noqa: E402

_LANG_PREFIX = {"typescript": "ts", "javascript": "js", "python": "py"}

def _admit(proposal: dict, db_path: str) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(proposal, f)
        path = f.name
    r = subprocess.run(["recall", "--db", db_path, "admit", "--json", path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"recall admit failed: {r.stderr.strip()}")

def persist(net: Hypernetwork, report: HypernetworkReport, db_path: str,
            project: str = "lattice") -> None:
    prefix = _LANG_PREFIX.get(net.language, net.language[:2])
    for v in net.vertices:
        if v.kind == "external":
            continue
        entities = [f"{prefix}-sym:{v.name}"]
        body = (f"# {v.kind}: {v.name}\n\n**File:** `{v.file}` "
                f"(lines {v.start_line}-{v.end_line})\n**Type:** {v.type or 'n/a'}\n"
                f"**Exported:** {v.exported}  **Stub:** {v.stub}\n")
        prop = build_proposal(kind="artifact", title=f"{v.kind}: {v.file}::{v.name}",
                              body=body, confidence=0.9,
                              topics=["code", net.language, v.kind],
                              project=project)
        prop["tags"]["entities"] = list(set(prop["tags"].get("entities", []) + entities))
        _admit(prop, db_path)
    # report cell
    rep_body = (f"# Completeness report ({report.verdict})\n\n"
                f"resolution={report.resolution:.3f}; "
                f"unresolved_imports={len(report.unresolved_imports)}; "
                f"dangling={len(report.dangling_edges)}; stubs={len(report.stubs)}\n")
    rep_prop = build_proposal(kind="observation",
                              title=f"completeness: {net.root} [{report.verdict}]",
                              body=rep_body, confidence=0.95,
                              topics=["code", "completeness", net.language],
                              project=project)
    _admit(rep_prop, db_path)
    # materialize typed hyperedges from entity tags (reuse validated linker)
    subprocess.run([sys.executable, f"{_RECALL_SCRIPTS}/recall_code_link.py",
                    "--project", project, "--db", db_path, "--apply", "--skip-existing"],
                   capture_output=True, text=True)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_recall_sink.py -v -m integration`
Expected: PASS (nodes >= 1 in the temp DB).

- [ ] **Step 5: Commit**

```bash
cd ~/Lattice && git add -A && git commit -m "feat(memory): persist hypernetwork to recall via proven write path"
```

---

## Task 7: CLI orchestration (integration)

**Files:**
- Create: `src/lattice/cli/main.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
import json, subprocess, sys, pathlib, pytest
FIX = pathlib.Path(__file__).parent / "fixtures" / "ts_sample"

@pytest.mark.integration
def test_cli_ingest_runs(tmp_path):
    db = str(tmp_path / "cli.sqlite3")
    subprocess.run(["recall", "init", "--db", db], check=True, capture_output=True)
    out = tmp_path / "hypernetwork.json"
    r = subprocess.run([sys.executable, "-m", "lattice.cli.main", "ingest", str(FIX),
                        "--lang", "ts", "--project", "lattice-cli-test",
                        "--db", db, "--out", str(out)],
                       capture_output=True, text=True, cwd=str(pathlib.Path(FIX).parents[2]))
    assert r.returncode == 0, r.stderr
    net = json.loads(out.read_text())
    assert net["stats"]["vertices"] >= 3
    report = json.loads((out.parent / "hypernetwork-report.json").read_text())
    assert report["verdict"] in ("pass", "partial")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_cli.py -v -m integration`
Expected: FAIL (`No module named lattice.cli.main` has no `main`, or missing args).

- [ ] **Step 3: Write the implementation**

```python
# src/lattice/cli/main.py
from __future__ import annotations
import argparse, json, pathlib, sys
from lattice.ingest.lsp_client import ingest
from lattice.graph.builder import build
from lattice.complete.gate import check
from lattice.memory.recall_sink import persist

_LANG = {"ts": "typescript", "js": "javascript", "py": "python"}

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="lattice")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ing = sub.add_parser("ingest")
    ing.add_argument("path")
    ing.add_argument("--lang", default="ts", choices=list(_LANG))
    ing.add_argument("--project", default="lattice")
    ing.add_argument("--db", default=None, help="explicit recall DB path")
    ing.add_argument("--allow-partial", action="store_true")
    ing.add_argument("--out", default="hypernetwork.json")
    args = ap.parse_args(argv)

    language = _LANG[args.lang]
    root = pathlib.Path(args.path).resolve()
    raw = ingest(root, language)
    net = build(raw)
    report = check(net)

    out = pathlib.Path(args.out)
    out.write_text(json.dumps(net.to_dict(), indent=2))
    (out.parent / "hypernetwork-report.json").write_text(json.dumps(report.to_dict(), indent=2))
    print(f"[lattice] vertices={net.stats['vertices']} hyperedges={net.stats['hyperedges']} "
          f"verdict={report.verdict} resolution={report.resolution:.3f}")

    if report.verdict == "fail" and not args.allow_partial:
        print(f"[lattice] FAIL: {report.failing_checks}", file=sys.stderr)
        return 1
    if args.db:
        persist(net, report, db_path=args.db, project=args.project)
        print(f"[lattice] persisted to recall db {args.db}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Lattice && .venv/bin/pytest tests/test_cli.py -v -m integration`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `cd ~/Lattice && .venv/bin/pytest -v`
Expected: all unit tests PASS; integration tests PASS (or skip cleanly if `-m "not integration"`).

- [ ] **Step 6: Commit**

```bash
cd ~/Lattice && git add -A && git commit -m "feat(cli): wire ingest->build->gate->persist pipeline"
```

---

## Task 8: Acceptance — run on defi-v2 + oracle note

**Files:** none (verification + README)

- [ ] **Step 1: Run Lattice on a real TS repo (defi-v2/src)**

```bash
cd ~/Lattice
.venv/bin/python -m lattice.cli.main ingest /Users/hendrixx./Defi-github/defi-v2/src \
  --lang ts --project lattice --db ~/.recall/db/lattice.sqlite3 --out /tmp/defi-v2-net.json
```
Expected: prints `verdict=pass` (or `partial` with a specific reason), writes `/tmp/defi-v2-net.json`, persists to the lattice DB.

- [ ] **Step 2: Confirm persistence**

```bash
recall --db ~/.recall/db/lattice.sqlite3 status
recall --db ~/.recall/db/lattice.sqlite3 search "ts-sym:foo"
```
Expected: nodes > 0; search returns hits.

- [ ] **Step 3: Oracle cross-check note**

Compare vertex names from `/tmp/defi-v2-net.json` against the symbols defi-v2's own AST adapter reports for the same `src/` (the cells already in the `defi` recall DB are a convenient reference set). Document agreement / known gaps in `README.md`. A documented tolerance (e.g. "module + exported-function sets agree; local consts may differ") is acceptable for Phase 1.

- [ ] **Step 4: Write `README.md` and commit**

```bash
cat > ~/Lattice/README.md <<'MD'
# Lattice

Multi-domain structural-analysis engine. Phase 1: LSP -> typed hypernetwork -> completeness gate -> recall.

## Usage
    .venv/bin/python -m lattice.cli.main ingest <path> --lang ts --db ~/.recall/db/lattice.sqlite3

See docs/superpowers/specs/2026-06-01-lattice-phase1-design.md for the design and roadmap.
MD
cd ~/Lattice && git add -A && git commit -m "docs: phase 1 acceptance + README"
```

---

## Self-review notes

- **Spec coverage:** §4 layers → Tasks 1–7; §5 model → Task 2; §6 gate → Task 4; §7 recall → Task 6; §8 CLI → Task 7; §9 error handling → gate verdict/exit code (Task 7) + admit failure raise (Task 6) + LSP launch check (Task 5 Step 5); §11 testing → fixtures (Task 5), temp DB (Task 6), oracle (Task 8). solver is intentionally deferred (spec §6 says optional in Phase 1).
- **Type consistency:** `RawIngest`/`RawSymbol`/`RawReference` (Task 1) consumed by `build` (Task 3) and `ingest` (Task 5); `Hypernetwork`/`Vertex`/`Hyperedge`/`Surface` (Task 2) consumed by gate (Task 4), sink (Task 6), CLI (Task 7); `HypernetworkReport` (Task 4) consumed by sink + CLI. `persist(net, report, db_path, project)` signature consistent across Tasks 6–7.
- **Known external-API risk:** multilspy method names (Task 0 Step 4 verifies) and `recall admit`/`recall_code_link.py` flags (already validated this session). Both have explicit verification steps.
