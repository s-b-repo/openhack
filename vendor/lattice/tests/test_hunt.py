# tests/test_hunt.py
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.hunt import hunt


def _v(vid, stub=False, exported=False, kind="function"):
    return Vertex(id=vid, kind=kind, name=vid, file="f", start_line=1, end_line=2,
                  stub=stub, exported=exported)


def _e(a, b, resolved=True, kind="references"):
    return Hyperedge(id=a + b, kind=kind, members=[a, b], resolved=resolved)


def _net(vs, es, surfaces=None):
    return Hypernetwork(language="ts", root="/x", vertices=vs, hyperedges=es,
                        surfaces=surfaces or [])


def test_called_stub_is_a_bug():
    net = _net([_v("caller"), _v("impl", stub=True)], [_e("caller", "impl")])
    bugs = hunt(net)
    assert any(b.kind == "called_stub" and b.symbol == "impl" for b in bugs)


def test_public_path_to_stub_is_critical_and_subsumes_called_stub():
    net = _net([_v("api", exported=True), _v("impl", stub=True)],
               [_e("api", "impl")],
               surfaces=[Surface(id="s", vertex_id="api", kind="public_api")])
    bugs = hunt(net)
    kinds = {b.kind for b in bugs}
    assert "public_path_to_stub" in kinds
    assert not any(b.kind == "called_stub" and b.symbol == "impl" for b in bugs)
    assert bugs[0].severity == "critical"     # ranked first


def test_broken_reference_is_a_bug():
    net = _net([_v("a"), _v("b")], [_e("a", "b", resolved=False)])
    assert any(b.kind == "broken_reference" for b in hunt(net))


def test_obstruction_is_a_bug_and_suppresses_bare_broken_ref():
    net = _net([_v("a"), _v("b"), _v("c")],
               [_e("a", "b", resolved=False), _e("b", "c"), _e("c", "a")])
    bugs = hunt(net)
    assert any(b.kind == "obstruction" for b in bugs)
    # the broken a-b edge is reported as the (richer) obstruction, not also as a bare broken_reference
    assert not any(b.kind == "broken_reference" for b in bugs)


def test_clean_graph_has_no_bugs():
    net = _net([_v("api", exported=True), _v("h")], [_e("api", "h")],
               surfaces=[Surface(id="s", vertex_id="api", kind="public_api")])
    assert hunt(net) == []


def test_cli_hunt_exit_codes(tmp_path, monkeypatch, capsys):
    from lattice.cli import main as cli
    from lattice.ingest.types import RawIngest, RawSymbol, RawReference
    raw = RawIngest(
        language="typescript", root=str(tmp_path),
        symbols=[RawSymbol(name="caller", kind="function", file="a.ts", start_line=1, end_line=2),
                 RawSymbol(name="impl", kind="function", file="a.ts", start_line=3, end_line=4,
                           is_stub=True)],
        references=[RawReference(kind="references", from_file="a.ts", from_line=1,
                                 to_file="a.ts", to_line=3, resolved=True)],
        files=["a.ts"])
    from lattice.graph.builder import build as _build
    import pathlib as _pl
    monkeypatch.setattr(cli, "load_network", lambda path, language="typescript": (_build(raw), _pl.Path(path)))
    assert cli.main(["hunt", str(tmp_path)]) == 0                 # informational by default
    assert "called_stub" in capsys.readouterr().out
    assert cli.main(["hunt", str(tmp_path), "--fail-on-bugs"]) == 1  # a high-sev bug -> non-zero


def test_bugs_sorted_by_severity():
    net = _net([_v("api", exported=True), _v("impl", stub=True), _v("x"), _v("y")],
               [_e("api", "impl"), _e("x", "y", resolved=False)],
               surfaces=[Surface(id="s", vertex_id="api", kind="public_api")])
    sev = [b.severity for b in hunt(net)]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert sev == sorted(sev, key=lambda s: order[s])    # non-decreasing severity
