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
