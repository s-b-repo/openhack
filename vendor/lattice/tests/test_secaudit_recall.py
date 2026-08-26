import pathlib
from lattice.graph.models import Vertex, Hypernetwork
from lattice.security import audit


def _net(tmp_path, vertices, surfaces=None):
    return Hypernetwork(language="ts", root=str(tmp_path), vertices=vertices,
                        hyperedges=[], surfaces=surfaces or [])


def test_dangerous_sink_in_unreachable_code_is_not_silently_dropped(tmp_path):
    """A spawn() whose enclosing function isn't provably reachable from an entrypoint
    must STILL be reported — the call graph has holes (e.g. JSX <Component/> creates no
    call edge), so 'not provably reachable' != 'safe'. Silently dropping it hides a real
    command-exec sink, the catastrophic false-negative for a security tool."""
    (tmp_path / "comp.tsx").write_text(
        "import { spawn } from 'child_process'\n"
        "function Widget() {\n"
        "  spawn('ls', [])\n"            # real command-exec sink
        "}\n")
    net = _net(tmp_path, [
        Vertex(id="ts:comp.tsx#Widget", kind="function", name="Widget",
               file="comp.tsx", start_line=2, end_line=4),
        Vertex(id="ts:comp.tsx", kind="module", name="comp.tsx",
               file="comp.tsx", start_line=1, end_line=4),
    ])  # NO surfaces -> Widget is unreachable by the call graph
    rep = audit(net, source_root=str(tmp_path))
    ce = [f for f in rep.findings if f.kind == "command_exec" and "comp.tsx" in f.sink]
    assert ce, "command_exec sink in unreachable code was silently dropped"
    # but it must be honestly distinguished from an entrypoint-reachable sink
    assert ce[0].taint == "unverified_reach", f"expected reachability-unverified marker, got {ce[0].taint!r}"


def test_reachable_sink_keeps_its_reachable_status(tmp_path):
    """Regression: a sink genuinely reachable from an entrypoint stays 'reachable'."""
    from lattice.graph.models import Surface
    (tmp_path / "m.tsx").write_text(
        "import { spawn } from 'child_process'\n"
        "export function main() {\n"
        "  spawn('ls', [])\n"
        "}\n")
    net = _net(tmp_path, [
        Vertex(id="ts:m.tsx#main", kind="function", name="main", exported=True,
               file="m.tsx", start_line=2, end_line=4),
        Vertex(id="ts:m.tsx", kind="module", name="m.tsx", file="m.tsx",
               start_line=1, end_line=4),
    ], surfaces=[Surface(id="s", vertex_id="ts:m.tsx#main", kind="entrypoint")])
    rep = audit(net, source_root=str(tmp_path))
    ce = [f for f in rep.findings if f.kind == "command_exec" and "m.tsx" in f.sink]
    assert ce and ce[0].taint in ("reachable", "argument_flow")


def test_dangerous_calls_in_test_files_are_excluded(tmp_path):
    """Test files aren't shipped — their spawn/exec calls are not attack surface.
    hunt excludes tests; a security audit must too, or it floods with non-vulns."""
    (tmp_path / "handler.test.ts").write_text(
        "import { spawn } from 'child_process'\n"
        "export function testThing() {\n"
        "  spawn('ls', [])\n"
        "}\n")
    net = _net(tmp_path, [
        Vertex(id="ts:handler.test.ts#testThing", kind="function", name="testThing",
               exported=True, file="handler.test.ts", start_line=2, end_line=4),
        Vertex(id="ts:handler.test.ts", kind="module", name="handler.test.ts",
               file="handler.test.ts", start_line=1, end_line=4),
    ])
    rep = audit(net, source_root=str(tmp_path))
    assert not any("handler.test.ts" in f.sink for f in rep.findings), \
        "a spawn() in a test file was reported as a security finding"
