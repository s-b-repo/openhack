# tests/test_coverage.py
# The gate must distinguish resolution (edges that exist resolve) from coverage
# (fraction of functions with any detected inbound reference — a recall INDICATOR).
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.complete.gate import check


def _fn(vid):
    return Vertex(id=vid, kind="function", name=vid, file="f", start_line=1, end_line=2)


def test_report_includes_coverage_indicator():
    vs = [_fn("a"), _fn("b")]                       # b is referenced, a is not
    es = [Hyperedge(id="e", kind="references", members=["a", "b"], resolved=True)]
    rep = check(Hypernetwork(language="ts", root="/x", vertices=vs, hyperedges=es))
    assert rep.coverage["functions_total"] == 2
    assert rep.coverage["functions_with_inbound_refs"] == 1
    assert rep.coverage["ratio"] == 0.5
    assert "recall" in rep.coverage["note"].lower()   # explicitly labeled as an indicator


def test_resolution_and_coverage_are_independent():
    # all edges resolve (resolution=1.0) yet coverage can be < 1.0 — the exact gap
    # the defi-v2 "resolution=1.000" claim hides.
    vs = [_fn("a"), _fn("b"), _fn("c")]
    es = [Hyperedge(id="e", kind="references", members=["a", "b"], resolved=True)]
    rep = check(Hypernetwork(language="ts", root="/x", vertices=vs, hyperedges=es))
    assert rep.resolution == 1.0
    assert rep.coverage["ratio"] < 1.0
