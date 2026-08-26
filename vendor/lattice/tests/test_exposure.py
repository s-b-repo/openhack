import pathlib
from lattice.graph.models import Vertex, Hypernetwork, Surface
from lattice.exposure import library_exposure


def _net(tmp_path, vertices, surfaces=None):
    return Hypernetwork(language="ts", root=str(tmp_path), vertices=vertices,
                        hyperedges=[], surfaces=surfaces or [])


def test_library_call_surfaces_what_crosses_the_boundary(tmp_path):
    """Outbound boundary: at a call into an external library, surface WHAT'S ACCESSIBLE
    to that library — the args/handles that cross. Untrusted args are flagged. This is
    the bounded worst-case reach, readable without any visibility into the library."""
    (tmp_path / "app.ts").write_text(
        "import { spawn } from 'child_process'\n"
        "export function run(userInput: string) {\n"
        "  const token = loadToken()\n"
        "  spawn(userInput, token)\n"
        "}\n")
    net = _net(tmp_path, [
        Vertex(id="ts:app.ts#run", kind="function", name="run", exported=True,
               file="app.ts", start_line=2, end_line=5),
        Vertex(id="ts:app.ts", kind="module", name="app.ts", file="app.ts",
               start_line=1, end_line=5),
    ], surfaces=[Surface(id="s", vertex_id="ts:app.ts#run", kind="entrypoint")])
    exp = library_exposure(net, str(tmp_path))
    ce = [e for e in exp if e.library == "child_process"]
    assert ce, f"library handoff not surfaced; got {exp}"
    assert set(ce[0].accessible) >= {"userInput", "token"}, ce[0].accessible
    assert "userInput" in ce[0].tainted, f"untrusted arg not flagged: {ce[0]}"


def test_relative_imports_are_not_library_boundaries(tmp_path):
    """A relative import is internal code we trace through — not a library handoff."""
    (tmp_path / "a.ts").write_text(
        "import { helper } from './util'\n"
        "export function run() {\n  helper(1)\n}\n")
    net = _net(tmp_path, [
        Vertex(id="ts:a.ts#run", kind="function", name="run", exported=True,
               file="a.ts", start_line=2, end_line=4),
        Vertex(id="ts:a.ts", kind="module", name="a.ts", file="a.ts", start_line=1, end_line=4),
    ])
    assert not library_exposure(net, str(tmp_path))
