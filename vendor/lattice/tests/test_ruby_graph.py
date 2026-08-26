# Unit tests for the Ruby graph frontend (ruby_graph.py + tools/rubyast/ruby_graph.rb).
# The ruby_deep fixture plants: public serve -> private process -> private not_done
# (raise NotImplementedError stub), an empty public helper, a require_relative
# import, and a shebang entrypoint.
from __future__ import annotations
import pathlib
import shutil

import pytest

pytestmark = pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby missing")

REPO = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "ruby_deep"


def _ingest(root=FIXTURE):
    from lattice.ingest.ruby_graph import ruby_ingest
    return ruby_ingest(root)


def _sym(raw, name):
    matches = [s for s in raw.symbols if s.name == name]
    assert matches, f"symbol {name} not found in {[s.name for s in raw.symbols]}"
    return matches[0]


def test_language_files_and_entry():
    raw = _ingest()
    assert raw.language == "ruby"
    assert "app.rb" in raw.files and "lib/api.rb" in raw.files
    assert "app.rb" in raw.entry_files
    assert "lib/api.rb" not in raw.entry_files


def test_private_marker_flips_exported():
    raw = _ingest()
    assert _sym(raw, "serve").exported is True
    assert _sym(raw, "unused_helper").exported is True
    assert _sym(raw, "process").exported is False
    assert _sym(raw, "not_done").exported is False


def test_stub_detection():
    raw = _ingest()
    assert _sym(raw, "not_done").is_stub is True        # raise NotImplementedError
    assert _sym(raw, "unused_helper").is_stub is True   # empty body
    assert _sym(raw, "process").is_stub is False


def test_methods_carry_their_class_container():
    raw = _ingest()
    assert _sym(raw, "serve").kind == "method"
    assert _sym(raw, "serve").container == "Api"


def test_require_relative_resolves():
    raw = _ingest()
    imports = [r for r in raw.references if r.kind == "imports"]
    assert any(r.from_file == "app.rb" and r.to_file == "lib/api.rb" and r.resolved
               for r in imports), f"imports: {[(r.from_file, r.to_file) for r in imports]}"


def test_calls_resolve_by_name_and_constructor_maps_to_class():
    raw = _ingest()
    calls = [r for r in raw.references if r.kind == "references"]
    process_line = _sym(raw, "process").start_line
    assert any(r.from_file == "lib/api.rb" and r.to_line == process_line
               and r.name == "process" and r.resolved for r in calls)
    api_line = _sym(raw, "Api").start_line
    assert any(r.from_file == "app.rb" and r.to_file == "lib/api.rb"
               and r.to_line == api_line and r.name == "Api" for r in calls), (
        "Api.new should resolve to the Api class")


def test_inheritance_and_include(tmp_path):
    from lattice.ingest.ruby_graph import ruby_ingest
    (tmp_path / "zoo.rb").write_text(
        "module Walkable\n  def walk\n    step\n  end\nend\n\n"
        "class Animal\nend\n\n"
        "class Dog < Animal\n  include Walkable\n\n  def bark\n    walk\n  end\nend\n")
    raw = ruby_ingest(tmp_path)
    by = {s.name: s for s in raw.symbols}
    assert by["Dog"].extends == ["Animal"]
    assert "Walkable" in by["Dog"].implements
    assert by["walk"].container == "Walkable"


def test_builder_prefixes_ruby_vertices():
    from lattice.graph.builder import build
    net = build(_ingest())
    sym_ids = [v.id for v in net.vertices if v.kind not in ("module", "external")]
    assert sym_ids and all(i.startswith("rb-") for i in sym_ids), sym_ids[:5]


def test_cache_routes_ruby():
    from lattice.cache import ingest_source, normalize_language
    assert normalize_language("rb") == "ruby"
    raw = ingest_source(FIXTURE, "ruby")
    assert raw.language == "ruby" and raw.symbols
