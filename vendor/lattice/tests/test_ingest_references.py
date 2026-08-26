# tests/test_ingest_references.py
import pathlib
import pytest

from lattice.ingest.lsp_client import _ref_edges, _location_site, ingest
from lattice.graph.builder import build
from lattice.graph.query import GraphView

FIX = pathlib.Path(__file__).parent / "fixtures" / "ts_sample"


# --- pure helpers (no LSP) ---

def test_ref_edges_skips_self_references():
    # bar is declared at b.ts lines 1-3; a reference at a.ts:3 is a real caller,
    # a "reference" inside bar's own body (b.ts:2) is the declaration/self -> skipped.
    sites = [("b.ts", 1), ("b.ts", 2), ("a.ts", 3)]
    edges = _ref_edges("b.ts", 1, 3, sites)
    assert len(edges) == 1
    e = edges[0]
    assert e.kind == "references"
    assert e.from_file == "a.ts" and e.from_line == 3
    assert e.to_file == "b.ts" and e.to_line == 1
    assert e.resolved is True


def test_location_site_parses_relative_path():
    root = pathlib.Path("/proj")
    loc = {"relativePath": "src/a.ts", "range": {"start": {"line": 4, "character": 2}}}
    assert _location_site(loc, root) == ("src/a.ts", 5)   # 0-based -> 1-based


def test_location_site_parses_file_uri():
    root = pathlib.Path("/proj")
    loc = {"uri": "file:///proj/src/b.ts", "range": {"start": {"line": 0, "character": 0}}}
    assert _location_site(loc, root) == ("src/b.ts", 1)


def test_location_site_rejects_outside_root():
    root = pathlib.Path("/proj")
    loc = {"uri": "file:///other/x.ts", "range": {"start": {"line": 0, "character": 0}}}
    assert _location_site(loc, root) is None


# --- end-to-end on the real fixture (needs typescript-language-server) ---

@pytest.mark.integration
def test_symbol_reference_edges_enable_refactor_query():
    net = build(ingest(FIX, "typescript"))
    g = GraphView(net)
    bar = "ts-sym:b.ts#bar"
    foo = "ts-sym:a.ts#foo"
    # foo() calls bar(41) -> a 'references' edge foo -> bar must exist,
    # so the refactor blast-radius query finds foo as a user of bar.
    assert foo in g.references_to(bar, kinds="references")
