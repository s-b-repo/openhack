# tests/test_impact.py
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.graph.query import GraphView
from lattice.impact import impact, resolve_targets

LIB = "ts-sym:lib.ts#lib"
MID = "ts-sym:mid.ts#mid"
APP = "ts-sym:app.ts#app"
OTHER = "ts-sym:other.ts#other"


def _v(vid, file, exported=False):
    return Vertex(id=vid, kind="function", name=vid.split("#")[-1], file=file,
                  start_line=1, end_line=2, exported=exported)


def _e(a, b):
    return Hyperedge(id=f"{a}->{b}", kind="references", members=[a, b], resolved=True)


def _net():
    vs = [_v(LIB, "lib.ts"), _v(MID, "mid.ts"), _v(APP, "app.ts", exported=True),
          _v(OTHER, "other.ts")]
    # mid uses lib, app uses mid, other uses lib  =>  changing lib ripples up
    es = [_e(MID, LIB), _e(APP, MID), _e(OTHER, LIB)]
    surf = [Surface(id="s1", vertex_id=APP, kind="public_api")]
    return Hypernetwork(language="typescript", root="/x", vertices=vs,
                        hyperedges=es, surfaces=surf)


# --- the new lens primitive: transitive reverse reachability ---

def test_dependents_transitive():
    g = GraphView(_net())
    assert g.dependents(LIB) == {MID, OTHER, APP}     # app reaches lib via mid
    assert g.dependents(APP) == set()                 # nothing depends on app


# --- impact report ---

def test_impact_direct_and_transitive():
    r = impact(_net(), LIB)
    assert set(r.direct_dependents) == {MID, OTHER}
    assert set(r.transitive_dependents) == {MID, OTHER, APP}
    assert r.blast_radius == 3


def test_impact_affected_files_and_public_api():
    r = impact(_net(), LIB)
    assert set(r.affected_files) == {"mid.ts", "other.ts", "app.ts"}
    assert r.affected_public_api == [APP]              # changing lib reaches a public API


def test_impact_leaf_has_no_blast_radius():
    r = impact(_net(), APP)
    assert r.blast_radius == 0


def test_resolve_targets_by_name():
    assert resolve_targets(_net(), "lib") == [LIB]     # exact name match wins over substring


def test_follow_traces_impact_chains():
    from lattice.impact import follow
    paths = follow(_net(), LIB)
    assert (LIB, MID, APP) in paths      # lib change ripples up through mid to app
    assert (LIB, OTHER) in paths         # and directly to other


def test_cli_impact_runs(tmp_path, monkeypatch, capsys):
    from lattice.cli import main as cli
    from lattice.ingest.types import RawIngest, RawSymbol, RawReference
    raw = RawIngest(
        language="typescript", root=str(tmp_path),
        symbols=[RawSymbol(name="lib", kind="function", file="lib.ts", start_line=1,
                           end_line=2, exported=True),
                 RawSymbol(name="mid", kind="function", file="mid.ts", start_line=1,
                           end_line=2, exported=True)],
        references=[RawReference(kind="references", from_file="mid.ts", from_line=1,
                                 to_file="lib.ts", to_line=1, resolved=True)],
        files=["lib.ts", "mid.ts"])
    from lattice.graph.builder import build as _build
    import pathlib as _pl
    monkeypatch.setattr(cli, "load_network", lambda path, language="typescript": (_build(raw), _pl.Path(path)))
    rc = cli.main(["impact", str(tmp_path), "lib"])
    assert rc == 0
    assert "mid" in capsys.readouterr().out.lower()
