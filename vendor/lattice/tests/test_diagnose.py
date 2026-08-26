# tests/test_diagnose.py
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.diagnose import diagnose

PUB = "ts-sym:a.ts#pub"
A = "ts-sym:a.ts#a"
B = "ts-sym:a.ts#b"
ORPHAN = "ts-sym:a.ts#orphan"
STUBBY = "ts-sym:a.ts#stubby"


def _fn(vid, exported=False, stub=False):
    return Vertex(id=vid, kind="function", name=vid.split("#")[-1], file="a.ts",
                  start_line=1, end_line=2, exported=exported, stub=stub)


def _net():
    vs = [_fn(PUB, exported=True), _fn(A), _fn(B), _fn(ORPHAN), _fn(STUBBY, stub=True)]
    es = [
        Hyperedge(id="e1", kind="calls", members=[PUB, A], resolved=True),
        Hyperedge(id="e2", kind="calls", members=[A, B], resolved=True),
        Hyperedge(id="e3", kind="calls", members=[B, A], resolved=True),   # cycle a<->b
        Hyperedge(id="e4", kind="calls", members=[PUB, STUBBY], resolved=True),
    ]
    surf = [Surface(id="s1", vertex_id=PUB, kind="public_api")]
    return Hypernetwork(language="typescript", root="/x", vertices=vs,
                        hyperedges=es, surfaces=surf)


def test_diagnose_surfaces_cycles():
    d = diagnose(_net())
    assert any(set(c) == {A, B} for c in d.cycles)


def test_diagnose_surfaces_dead_code():
    d = diagnose(_net())
    assert ORPHAN in d.dead_code          # unreachable from the public_api root
    assert A not in d.dead_code           # reachable via pub -> a


def test_diagnose_surfaces_stubs():
    d = diagnose(_net())
    assert STUBBY in d.stubs


def test_diagnose_ranks_hotspots():
    d = diagnose(_net())
    # `a` has the highest coupling: fan_in 2 (pub->a, b->a) + fan_out 1 (a->b) = 3
    assert d.hotspots[0]["id"] == A
    assert d.hotspots[0]["fan_in"] == 2


def test_diagnose_summary_flags_issues():
    d = diagnose(_net())
    assert d.summary["verdict"] == "issues"
    assert d.summary["cycles"] >= 1
    assert d.summary["dead_code"] >= 1
    assert d.summary["stubs"] >= 1


def test_cli_diagnose_runs_and_reports(tmp_path, monkeypatch, capsys):
    from lattice.cli import main as cli
    from lattice.ingest.types import RawIngest, RawSymbol, RawReference
    raw = RawIngest(
        language="typescript", root=str(tmp_path),
        symbols=[RawSymbol(name="pub", kind="function", file="a.ts", start_line=1,
                           end_line=4, exported=True),
                 RawSymbol(name="stubbed", kind="function", file="a.ts", start_line=5,
                           end_line=7, exported=True, is_stub=True)],
        references=[], files=["a.ts"])
    from lattice.graph.builder import build as _build
    import pathlib as _pl
    monkeypatch.setattr(cli, "load_network", lambda path, language="typescript": (_build(raw), _pl.Path(path)))
    rc = cli.main(["diagnose", str(tmp_path)])
    assert rc == 0                                    # diagnostics are informational by default
    out = capsys.readouterr().out
    assert "stubs" in out.lower() or "diagnose" in out.lower()


def test_cli_diagnose_fail_on_issues(tmp_path, monkeypatch):
    from lattice.cli import main as cli
    from lattice.ingest.types import RawIngest, RawSymbol
    raw = RawIngest(language="typescript", root=str(tmp_path),
                    symbols=[RawSymbol(name="s", kind="function", file="a.ts",
                                       start_line=1, end_line=2, is_stub=True)],
                    references=[], files=["a.ts"])
    from lattice.graph.builder import build as _build
    import pathlib as _pl
    monkeypatch.setattr(cli, "load_network", lambda path, language="typescript": (_build(raw), _pl.Path(path)))
    rc = cli.main(["diagnose", str(tmp_path), "--fail-on-issues"])
    assert rc == 1                                    # a stub is an issue -> non-zero when asked


def test_clean_graph_summary_is_clean():
    vs = [_fn(PUB, exported=True), _fn(A)]
    es = [Hyperedge(id="e1", kind="calls", members=[PUB, A], resolved=True)]
    surf = [Surface(id="s1", vertex_id=PUB, kind="public_api")]
    net = Hypernetwork(language="typescript", root="/x", vertices=vs,
                       hyperedges=es, surfaces=surf)
    d = diagnose(net)
    assert d.summary["verdict"] == "clean"
    assert d.to_dict()["summary"]["verdict"] == "clean"
