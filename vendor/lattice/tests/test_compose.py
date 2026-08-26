from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.graph.query import GraphView
from lattice.compose import link


def _v(vid, name, kind="function", exported=False, file="a.ts", s=1, e=3):
    return Vertex(id=vid, kind=kind, name=name, file=file, start_line=s, end_line=e,
                  exported=exported)


def test_join_links_host_call_to_library_entrypoint_so_reachability_crosses(tmp_path):
    """The join edge: a host call into a library that HAS a graph stops being a trace
    loss and becomes a hop. After linking, reachability follows the path THROUGH the
    library to its internal endpoints — a composed path neither graph shows alone."""
    (tmp_path / "app.ts").write_text(
        "import { danger } from 'libx'\n"
        "export function run(x: string) {\n  danger(x)\n}\n")
    host = Hypernetwork(language="ts", root=str(tmp_path), vertices=[
        _v("ts:app.ts#run", "run", exported=True, file="app.ts"),
        _v("ts:app.ts", "app.ts", kind="module", file="app.ts"),
    ], hyperedges=[], surfaces=[Surface(id="s", vertex_id="ts:app.ts#run", kind="entrypoint")])

    # library X's own graph: exported danger() -> an internal spawn sink
    libx = Hypernetwork(language="ts", root="/libx", vertices=[
        _v("lx:index.ts#danger", "danger", exported=True, file="index.ts"),
        _v("lx:index.ts#runShell", "runShell", file="index.ts"),
    ], hyperedges=[Hyperedge(id="le", kind="references",
                             members=["lx:index.ts#danger", "lx:index.ts#runShell"],
                             directed=True, resolved=True)], surfaces=[])

    composed = link(host, str(tmp_path), {"libx": libx})
    g = GraphView(composed)
    reach = g.reachable_from("ts:app.ts#run")
    assert any("danger" in r for r in reach), f"join to library entrypoint missing: {reach}"
    assert any("runShell" in r for r in reach), \
        f"reachability did not cross into the library's internals: {reach}"


def test_no_graph_no_join_stays_a_trace_loss(tmp_path):
    """A library with no graph available is NOT joined — it honestly stays a trace loss."""
    (tmp_path / "app.ts").write_text(
        "import { danger } from 'libx'\n"
        "export function run(x: string) {\n  danger(x)\n}\n")
    host = Hypernetwork(language="ts", root=str(tmp_path), vertices=[
        _v("ts:app.ts#run", "run", exported=True, file="app.ts"),
        _v("ts:app.ts", "app.ts", kind="module", file="app.ts"),
    ], hyperedges=[], surfaces=[])
    composed = link(host, str(tmp_path), {})        # no library graphs supplied
    assert not [e for e in composed.hyperedges if e.kind == "links"]


def test_broken_link_when_library_does_not_export_the_called_symbol(tmp_path):
    """The join contract verified: host calls libx.gone(), but libx's graph exports no
    'gone' (renamed/removed across a version). That's a broken link — the symbol-level
    version skew that a module-level import check can't see. Surface it, don't skip it."""
    (tmp_path / "app.ts").write_text(
        "import { gone } from 'libx'\n"
        "export function run(x: string) {\n  gone(x)\n}\n")
    host = Hypernetwork(language="ts", root=str(tmp_path), vertices=[
        _v("ts:app.ts#run", "run", exported=True, file="app.ts"),
        _v("ts:app.ts", "app.ts", kind="module", file="app.ts"),
    ], hyperedges=[], surfaces=[])
    libx = Hypernetwork(language="ts", root="/libx", vertices=[
        _v("lx:i.ts#present", "present", exported=True, file="i.ts"),   # exports present, NOT gone
    ], hyperedges=[], surfaces=[])
    from lattice.compose import broken_links
    bl = broken_links(host, str(tmp_path), {"libx": libx})
    assert len(bl) == 1 and bl[0].callee == "gone" and bl[0].reason == "no_such_export", bl


def test_no_broken_link_when_export_is_present_even_as_a_const(tmp_path):
    """A symbol exported as ANY kind (incl. a function-valued const) is present -> no break."""
    (tmp_path / "app.ts").write_text(
        "import { present } from 'libx'\n"
        "export function run(x: string) {\n  present(x)\n}\n")
    host = Hypernetwork(language="ts", root=str(tmp_path), vertices=[
        _v("ts:app.ts#run", "run", exported=True, file="app.ts"),
        _v("ts:app.ts", "app.ts", kind="module", file="app.ts"),
    ], hyperedges=[], surfaces=[])
    libx = Hypernetwork(language="ts", root="/libx", vertices=[
        _v("lx:i.ts#present", "present", kind="variable", exported=True, file="i.ts"),
    ], hyperedges=[], surfaces=[])
    from lattice.compose import broken_links
    assert broken_links(host, str(tmp_path), {"libx": libx}) == []


def test_no_broken_link_when_library_has_no_graph(tmp_path):
    """No graph for the library -> honest trace loss, NOT a broken link."""
    (tmp_path / "app.ts").write_text(
        "import { gone } from 'libx'\n"
        "export function run(x: string) {\n  gone(x)\n}\n")
    host = Hypernetwork(language="ts", root=str(tmp_path), vertices=[
        _v("ts:app.ts#run", "run", exported=True, file="app.ts"),
        _v("ts:app.ts", "app.ts", kind="module", file="app.ts"),
    ], hyperedges=[], surfaces=[])
    from lattice.compose import broken_links
    assert broken_links(host, str(tmp_path), {}) == []


def test_broken_link_arity_mismatch_too_many_args(tmp_path):
    """Arity shape-mismatch: host passes more args than the library entrypoint accepts
    (no rest param) — the signature changed across versions. A graph-level fact once the
    library's params are captured."""
    (tmp_path / "app.ts").write_text(
        "import { foo } from 'libx'\n"
        "export function run(a: string, b: string, c: string) {\n  foo(a, b, c)\n}\n")
    host = Hypernetwork(language="ts", root=str(tmp_path), vertices=[
        _v("ts:app.ts#run", "run", exported=True, file="app.ts"),
        _v("ts:app.ts", "app.ts", kind="module", file="app.ts"),
    ], hyperedges=[], surfaces=[])
    foo = _v("lx:i#foo", "foo", exported=True, file="i.ts")
    foo.params = ["x"]                                  # foo(x) — one param, no rest
    libx = Hypernetwork(language="ts", root="/libx", vertices=[foo], hyperedges=[], surfaces=[])
    from lattice.compose import broken_links
    bl = broken_links(host, str(tmp_path), {"libx": libx})
    assert any(b.reason == "arity_mismatch" for b in bl), bl


def test_no_arity_break_with_a_rest_param(tmp_path):
    """A variadic entrypoint (...args) accepts any count — no arity break."""
    (tmp_path / "app.ts").write_text(
        "import { foo } from 'libx'\n"
        "export function run(a: string) {\n  foo(a, a, a)\n}\n")
    host = Hypernetwork(language="ts", root=str(tmp_path), vertices=[
        _v("ts:app.ts#run", "run", exported=True, file="app.ts"),
        _v("ts:app.ts", "app.ts", kind="module", file="app.ts"),
    ], hyperedges=[], surfaces=[])
    foo = _v("lx:i#foo", "foo", exported=True, file="i.ts")
    foo.params = ["...args"]
    libx = Hypernetwork(language="ts", root="/libx", vertices=[foo], hyperedges=[], surfaces=[])
    from lattice.compose import broken_links
    assert not any(b.reason == "arity_mismatch"
                   for b in broken_links(host, str(tmp_path), {"libx": libx}))
