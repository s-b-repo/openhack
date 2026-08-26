# tests/test_reconcile.py
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.graph.merge import merge
from lattice.reconcile.engine import reconcile


def _v(vid, kind="class", exported=True, name=None):
    return Vertex(id=vid, kind=kind, name=name or vid.split("#")[-1], file="f",
                  start_line=1, end_line=2, exported=exported)


def _net(lang, vertices, edges=None, surfaces=None):
    return Hypernetwork(language=lang, root="/" + lang, vertices=vertices,
                        hyperedges=edges or [], surfaces=surfaces or [])


# --- model: edges carry confidence + provenance ---

def test_hyperedge_defaults_are_fact_grade():
    e = Hyperedge(id="e1", kind="calls", members=["a", "b"])
    assert e.confidence == 1.0
    assert e.provenance == "ingest"


# --- merge: union of per-language graphs ---

def test_merge_unions_namespaced_graphs():
    ts = _net("typescript", [_v("ts-sym:a.ts#User")],
              edges=[Hyperedge(id="e1", kind="calls", members=["ts-sym:a.ts#User", "x"])])
    py = _net("python", [_v("py-sym:m.py#User")])
    m = merge([ts, py])
    ids = {v.id for v in m.vertices}
    assert ids == {"ts-sym:a.ts#User", "py-sym:m.py#User"}
    assert m.language == "multi"
    assert len(m.hyperedges) == 1


# --- reconcile: cross-language candidate edges ---

def test_nominal_matches_same_named_type_across_languages():
    net = _net("multi", [_v("ts-sym:a.ts#User", kind="interface"),
                         _v("py-sym:m.py#User", kind="class")])
    cands = reconcile(net)
    assert len(cands) == 1
    e = cands[0]
    assert e.kind == "reconciles"
    assert set(e.members) == {"ts-sym:a.ts#User", "py-sym:m.py#User"}
    assert e.directed is False
    assert e.resolved is False           # a candidate, not a confirmed fact
    assert 0 < e.confidence < 1.0        # heuristic, not certain
    assert e.provenance == "nominal"


def test_does_not_reconcile_within_one_language():
    net = _net("multi", [_v("ts-sym:a.ts#User", kind="interface"),
                         _v("ts-sym:b.ts#User", kind="class")])
    assert reconcile(net) == []          # same language is not cross-language reconciliation


def test_does_not_reconcile_non_exported():
    net = _net("multi", [_v("ts-sym:a.ts#User", kind="interface", exported=False),
                         _v("py-sym:m.py#User", kind="class", exported=False)])
    assert reconcile(net) == []


def test_callable_and_type_are_different_categories():
    # a function named User and a class named User should NOT reconcile.
    net = _net("multi", [_v("ts-sym:a.ts#User", kind="function"),
                         _v("py-sym:m.py#User", kind="class")])
    assert reconcile(net) == []
