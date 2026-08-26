# tests/test_query.py
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.graph.query import GraphView

A = "ts-sym:a.ts#A"
B = "ts-sym:a.ts#B"
C = "ts-sym:a.ts#C"
D = "ts-sym:a.ts#D"
O = "ts-sym:a.ts#O"          # orphan / dead code
EXT = "ts-sym:<external>#x"


def _fn(vid):
    return Vertex(id=vid, kind="function", name=vid.split("#")[-1], file="a.ts",
                  start_line=1, end_line=2)


def _graph():
    vs = [_fn(A), _fn(B), _fn(C), _fn(D), _fn(O),
          Vertex(id=EXT, kind="external", name="x", file="<external>",
                 start_line=0, end_line=0)]
    es = [
        Hyperedge(id="e1", kind="calls", members=[A, B], resolved=True),
        Hyperedge(id="e2", kind="calls", members=[B, C], resolved=True),
        Hyperedge(id="e3", kind="calls", members=[C, A], resolved=True),  # cycle A,B,C
        Hyperedge(id="e4", kind="calls", members=[A, D], resolved=True),
        Hyperedge(id="e5", kind="calls", members=[D, EXT], resolved=True),
    ]
    surf = [Surface(id="s1", vertex_id=A, kind="public_api")]
    return GraphView(Hypernetwork(language="typescript", root="/x",
                                  vertices=vs, hyperedges=es, surfaces=surf))


def test_references_to_finds_inbound_callers():
    g = _graph()
    assert set(g.references_to(A)) == {C}     # only C -> A
    assert set(g.references_to(B)) == {A}


def test_out_neighbors():
    g = _graph()
    assert set(g.out_neighbors(A)) == {B, D}


def test_reachable_from_excludes_seed_includes_transitive():
    g = _graph()
    assert g.reachable_from(A) == {B, C, D, EXT}
    assert O not in g.reachable_from(A)


def test_shortest_path():
    g = _graph()
    assert g.shortest_path(A, B) == [A, B]            # direct
    assert g.shortest_path(A, "ts-sym:a.ts#C".replace("C", "c") if False else C) == [A, B, C]
    assert g.shortest_path(A, O) is None              # unreachable
    assert g.shortest_path(A, A) == [A]


def test_paths_capped_to_avoid_explosion():
    g = _graph()
    # paths() must accept a max_paths cap so dense graphs can't explode
    out = g.paths(A, C, max_paths=1)
    assert len(out) <= 1


def test_reaches():
    g = _graph()
    assert g.reaches(A, C) is True
    assert g.reaches(C, D) is True            # C -> A -> D
    assert g.reaches(D, B) is False
    assert g.reaches(A, O) is False


def test_paths_enumerates_a_concrete_path():
    g = _graph()
    ps = g.paths(A, C)
    assert (A, B, C) in ps


def test_fan_in_out():
    g = _graph()
    assert g.fan_in(A) == 1
    assert g.fan_out(A) == 2


def test_surfaces_query():
    g = _graph()
    assert [s.vertex_id for s in g.surfaces("public_api")] == [A]
    assert g.surfaces("trust_boundary") == []


def test_surfaces_reaching_target():
    g = _graph()
    # which public_api surfaces can reach D?  A -> D, and A is a public_api.
    assert g.surfaces_reaching(D, surface_kind="public_api") == [A]
    assert g.surfaces_reaching(O, surface_kind="public_api") == []


def test_find_cycles():
    g = _graph()
    cycles = g.find_cycles()
    assert frozenset({A, B, C}) in cycles


def test_dead_code_from_public_api_roots():
    g = _graph()
    dead = set(g.dead_code())
    assert O in dead                          # unreachable from any public_api
    assert B not in dead and D not in dead    # reachable from A
    assert EXT not in dead                    # external never counted
