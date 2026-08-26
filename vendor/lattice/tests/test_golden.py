import json, pathlib, pytest
from lattice.ingest.lsp_client import ingest
from lattice.graph.builder import build

FIX = pathlib.Path(__file__).parent / "fixtures" / "ts_sample"
GOLDEN = pathlib.Path(__file__).parent / "fixtures" / "ts_sample_golden.json"


def _projection(net):
    return {
        "vertices": sorted([v.id + "|" + v.kind + "|" + str(v.exported) + "|" + str(v.stub)
                            for v in net.vertices]),
        "edges": sorted([e.kind + "|" + str(e.resolved) + "|" + ">".join(e.members)
                         for e in net.hyperedges]),
    }


@pytest.mark.integration
def test_fixture_matches_golden():
    proj = _projection(build(ingest(FIX, "typescript")))
    if not GOLDEN.exists():
        GOLDEN.write_text(json.dumps(proj, indent=2))
        pytest.skip("golden file generated; re-run to assert")
    assert proj == json.loads(GOLDEN.read_text())
