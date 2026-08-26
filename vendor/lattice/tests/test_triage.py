# tests/test_triage.py
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.triage import triage


def _v(vid, stub=False, exported=False):
    return Vertex(id=vid, kind="function", name=vid, file="f", start_line=1, end_line=2,
                  stub=stub, exported=exported)


def _e(a, b, resolved=True):
    return Hyperedge(id=a + b, kind="references", members=[a, b], resolved=resolved)


def _net():
    # api (public) -> helper -> impl(stub); api -> impl too.  orphan is dead.
    vs = [_v("api", exported=True), _v("helper"), _v("impl", stub=True), _v("orphan")]
    es = [_e("api", "helper"), _e("helper", "impl"), _e("api", "impl")]
    surf = [Surface(id="s", vertex_id="api", kind="public_api")]
    return Hypernetwork(language="ts", root="/x", vertices=vs, hyperedges=es, surfaces=surf)


def test_triage_ranks_by_priority_desc():
    items = triage(_net())
    prios = [t.priority for t in items]
    assert prios == sorted(prios, reverse=True)


def test_triage_critical_high_blast_beats_low():
    items = triage(_net())
    top = items[0]
    assert top.kind == "public_path_to_stub"     # critical, and impl has dependents
    assert top.priority > items[-1].priority


def test_triage_priority_uses_blast_radius():
    items = triage(_net())
    stub_item = next(t for t in items if t.kind == "public_path_to_stub")
    # impl is referenced by api and helper -> blast radius 2 -> priority = 8 * (1+2)
    assert stub_item.blast_radius == 2
    assert stub_item.priority == 24


def test_triage_clean_graph_empty():
    net = Hypernetwork(language="ts", root="/x",
                       vertices=[_v("api", exported=True), _v("h")],
                       hyperedges=[_e("api", "h")],
                       surfaces=[Surface(id="s", vertex_id="api", kind="public_api")])
    assert triage(net) == []
