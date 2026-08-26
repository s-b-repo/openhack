from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.blindspots import blindspots


def _v(vid, name, kind="function", **kw):
    return Vertex(id=vid, kind=kind, name=name, file=kw.get("file", "a.ts"),
                  start_line=1, end_line=2, exported=kw.get("exported", False))


def test_blindspots_enumerate_where_path_following_goes_dark():
    """The keystone: surface every place the map goes dark, by category — paths leaving
    to unmapped code, paths to nothing, and code no followed path reaches. Known-unknowns
    as an output, so an agent knows where to trust the map vs look itself."""
    net = Hypernetwork(language="ts", root="/x", vertices=[
        _v("a#caller", "caller", exported=True),
        _v("a#orphan", "orphan"),                       # no inbound ref -> unreached
        _v("<external>#libcall", "libcall", kind="external"),  # leaves to unmapped code
    ], hyperedges=[
        # caller -> external lib (a path exiting to code we don't have)
        Hyperedge(id="e1", kind="references", members=["a#caller", "<external>#libcall"],
                  directed=True, resolved=True),
        # a broken import -> nothing (resolved=False, internal)
        Hyperedge(id="e2", kind="imports", members=["a#caller", "a#ghost"],
                  directed=True, resolved=False),
    ], surfaces=[])
    b = blindspots(net)
    assert b.summary["leaves_to_unmapped"] >= 1, b.summary
    assert b.summary["unresolved"] >= 1, b.summary
    assert any("orphan" in u for u in b.unreached), b.unreached


def test_clean_graph_has_no_blindspots():
    net = Hypernetwork(language="ts", root="/x", vertices=[
        _v("a#main", "main", exported=True),
        _v("a#helper", "helper"),
    ], hyperedges=[
        Hyperedge(id="e", kind="references", members=["a#main", "a#helper"],
                  directed=True, resolved=True),
    ], surfaces=[])
    b = blindspots(net)
    assert b.summary["leaves_to_unmapped"] == 0 and b.summary["unresolved"] == 0
    assert not b.unreached      # helper is reached by main; main is exported
