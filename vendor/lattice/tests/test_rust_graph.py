# Unit tests for the Rust graph frontend (rust_graph.py + tools/rustgraph).
# The rust_deep fixture plants: pub serve -> process -> not_done (todo! stub),
# unused dead function, main.rs declaring mod api, fn main entrypoint.
from __future__ import annotations
import pathlib
import shutil

import pytest

pytestmark = pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")

REPO = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "rust_deep"


def _ingest(root=FIXTURE):
    from lattice.ingest.rust_graph import rust_ingest
    return rust_ingest(root)


def _sym(raw, name):
    matches = [s for s in raw.symbols if s.name == name]
    assert matches, f"symbol {name} not found in {[s.name for s in raw.symbols]}"
    return matches[0]


def test_language_files_and_entry():
    raw = _ingest()
    assert raw.language == "rust"
    assert "src/main.rs" in raw.files and "src/api.rs" in raw.files
    assert "src/main.rs" in raw.entry_files
    assert "src/api.rs" not in raw.entry_files


def test_pub_visibility_is_exported():
    raw = _ingest()
    assert _sym(raw, "serve").exported is True
    assert _sym(raw, "process").exported is False


def test_todo_macro_is_a_stub():
    raw = _ingest()
    assert _sym(raw, "not_done").is_stub is True
    assert _sym(raw, "process").is_stub is False


def test_mod_declaration_resolves_to_module_file():
    raw = _ingest()
    imports = [r for r in raw.references if r.kind == "imports"]
    assert any(r.from_file == "src/main.rs" and r.to_file == "src/api.rs" and r.resolved
               for r in imports), f"imports: {[(r.from_file, r.to_file) for r in imports]}"


def test_calls_resolve_by_name():
    raw = _ingest()
    calls = [r for r in raw.references if r.kind == "references"]
    process_line = _sym(raw, "process").start_line
    assert any(r.from_file == "src/api.rs" and r.to_line == process_line
               and r.name == "process" and r.resolved for r in calls)


def test_structs_traits_impls_and_methods(tmp_path):
    from lattice.ingest.rust_graph import rust_ingest
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text(
        "pub trait Greet {\n    fn hello(&self);\n}\n\n"
        "pub struct Person {\n    name: String,\n}\n\n"
        "impl Person {\n    pub fn rename(&mut self, n: String) {\n        self.name = n;\n    }\n"
        "    fn pending(&self) {\n        unimplemented!()\n    }\n}\n\n"
        "impl Greet for Person {\n    fn hello(&self) {\n        self.rename(String::new());\n    }\n}\n")
    raw = rust_ingest(tmp_path)
    by = {s.name: s for s in raw.symbols}
    assert by["Person"].kind == "class"
    assert by["Greet"].kind == "interface"
    assert "Greet" in by["Person"].implements
    assert by["rename"].kind == "method" and by["rename"].container == "Person"
    assert by["rename"].exported is True
    assert by["pending"].is_stub is True
    assert by["hello"].container == "Person"


def test_builder_prefixes_rust_vertices():
    from lattice.graph.builder import build
    net = build(_ingest())
    sym_ids = [v.id for v in net.vertices if v.kind not in ("module", "external")]
    assert sym_ids and all(i.startswith("rs-") for i in sym_ids), sym_ids[:5]


def test_cache_routes_rust():
    from lattice.cache import ingest_source, normalize_language
    assert normalize_language("rs") == "rust"
    raw = ingest_source(FIXTURE, "rust")
    assert raw.language == "rust" and raw.symbols
