# tests/test_gate.py
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.complete.gate import check
from lattice.ingest.types import RawSymbol, RawReference, RawIngest
from lattice.graph.builder import build

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
    assert rep.verdict in ("pass", "partial")

def test_internal_unresolved_edge_is_dangling():
    # edge between two INTERNAL vertices, unresolved -> dangling -> fail
    e = Hyperedge(id="e1", kind="calls",
                  members=["ts-sym:a.ts#foo", "ts-sym:a.ts#foo"], resolved=False)
    rep = check(_net([e]))
    assert "e1" in rep.dangling_edges
    assert rep.verdict == "fail"

def test_partial_verdict():
    # 9 resolved internal edges + 1 unresolved internal edge => resolution 0.9, dangling present => partial
    edges = [Hyperedge(id=f"r{i}", kind="calls",
                       members=["ts-sym:a.ts#foo", "ts-sym:a.ts#foo"], resolved=True)
             for i in range(9)]
    edges.append(Hyperedge(id="u1", kind="calls",
                           members=["ts-sym:a.ts#foo", "ts-sym:a.ts#foo"], resolved=False))
    rep = check(_net(edges))
    assert 0.85 <= rep.resolution < 0.98
    assert rep.verdict == "partial"
    assert "u1" in rep.dangling_edges

def test_broken_relative_import_fails():
    """Relative import to a file not in the ingest (to_file set, no module vertex) -> verdict fail."""
    # a.ts has function foo; imports reference points at missing.ts (not ingested)
    foo = RawSymbol(name="foo", kind="function", file="a.ts", start_line=1, end_line=5,
                    exported=True, is_stub=False)
    broken_imp = RawReference(kind="imports", from_file="a.ts", from_line=1,
                              to_file="missing.ts", to_line=None, resolved=True)
    raw = RawIngest(language="typescript", root="/x",
                    symbols=[foo], references=[broken_imp], diagnostics=[])
    net = build(raw)
    rep = check(net)
    assert rep.verdict == "fail", f"expected fail, got {rep.verdict}"
    # the broken target id should appear in unresolved_imports
    unresolved_str = str(rep.unresolved_imports)
    assert "missing.ts" in unresolved_str, (
        f"expected 'missing.ts' in unresolved_imports, got: {rep.unresolved_imports}"
    )


def test_external_package_import_passes():
    """External package import (to_file=None) -> verdict pass/partial, unresolved_imports empty."""
    foo = RawSymbol(name="foo", kind="function", file="a.ts", start_line=1, end_line=5,
                    exported=True, is_stub=False)
    ext_imp = RawReference(kind="imports", from_file="a.ts", from_line=1,
                           to_file=None, to_line=None, resolved=False)
    raw = RawIngest(language="typescript", root="/x",
                    symbols=[foo], references=[ext_imp], diagnostics=[])
    net = build(raw)
    rep = check(net)
    assert rep.verdict in ("pass", "partial"), f"expected pass/partial, got {rep.verdict}"
    assert rep.unresolved_imports == [], (
        f"expected no unresolved_imports, got: {rep.unresolved_imports}"
    )


def test_stub_reported_but_not_failing():
    from lattice.graph.models import Vertex, Hypernetwork
    v = Vertex(id="ts-sym:a.ts#foo", kind="function", name="foo", file="a.ts",
               start_line=1, end_line=2, exported=True, stub=True)
    net = Hypernetwork(language="typescript", root="/x", vertices=[v], hyperedges=[])
    rep = check(net)
    assert "ts-sym:a.ts#foo" in rep.stubs
    assert rep.verdict == "pass"   # no edges, no imports -> resolution 1.0 -> pass; stub does not fail
