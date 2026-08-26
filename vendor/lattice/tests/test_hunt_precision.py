# tests/test_hunt_precision.py
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork, Surface
from lattice.hunt import hunt


def _v(vid, name, file, exported=False, stub=False):
    return Vertex(id=vid, kind="function", name=name, file=file,
                  start_line=1, end_line=2, exported=exported, stub=stub)


def _net(vs, es=None):
    return Hypernetwork(language="ts", root="/x", vertices=vs, hyperedges=es or [])


def test_real_uncalled_function_is_still_dead():
    assert any(b.kind == "dead_code" and b.symbol == "h"
               for b in hunt(_net([_v("h", "unusedHelper", "src/foo.ts")])))


def test_test_file_functions_are_not_dead_code():
    # `.test.` naming and a tests/ directory are both test code (mocks/fixtures)
    assert not any(b.kind == "dead_code"
                   for b in hunt(_net([_v("h", "mockThing", "src/foo.test.ts")])))
    assert not any(b.kind == "dead_code"
                   for b in hunt(_net([_v("h", "fixture", "tests/setup.ts")])))
    assert not any(b.kind == "dead_code"
                   for b in hunt(_net([_v("h", "helper", "src/__tests__/x.ts")])))


def test_event_handlers_are_not_dead_code():
    assert not any(b.kind == "dead_code"
                   for b in hunt(_net([_v("h", "onmessage", "src/ws.ts")])))
    assert not any(b.kind == "dead_code"
                   for b in hunt(_net([_v("h", "onError", "src/ws.ts")])))   # camelCase


def test_framework_hooks_are_not_dead_code():
    for hook in ("configureServer", "resolveId", "load", "transformIndexHtml"):
        assert not any(b.kind == "dead_code"
                       for b in hunt(_net([_v("h", hook, "src/vite-plugin.ts")]))), hook


def test_node_stream_methods_are_not_dead_code():
    # _read/_write/_final/... are invoked by the Node streams runtime when you implement a
    # Readable/Writable/Transform — never referenced by name, so not dead.
    for m in ("_read", "_write", "_final", "_transform", "_flush", "_destroy", "_writev"):
        assert not any(b.kind == "dead_code"
                       for b in hunt(_net([_v("h", m, "src/stream.ts")]))), m
    # a genuinely uncalled underscore helper is still a lead (not every _foo is a hook)
    assert any(b.kind == "dead_code"
               for b in hunt(_net([_v("h", "_privateHelper", "src/x.ts")])))


def test_stub_in_test_file_is_not_called_stub():
    net = _net([_v("c", "caller", "src/x.test.ts"),
                _v("m", "mockConnect", "src/x.test.ts", stub=True)],
               [Hyperedge(id="e", kind="references", members=["c", "m"], resolved=True)])
    assert not any(b.kind == "called_stub" for b in hunt(net))


def test_empty_method_in_a_mock_class_is_not_called_stub():
    # MockStitchMCPClient#connect — an intentional empty override, not a bug
    mid = "ts-sym:src/MockClient.ts#MockClient.connect"
    mv = Vertex(id=mid, kind="method", name="connect", file="src/MockClient.ts",
                start_line=1, end_line=2, stub=True)
    net = _net([_v("c", "caller", "src/svc.ts"), mv],
               [Hyperedge(id="e", kind="references", members=["c", mid], resolved=True)])
    assert not any(b.kind == "called_stub" for b in hunt(net))


def test_public_method_of_exported_class_is_not_dead_code():
    # ProcessPromise.pipe (google/zx): a public method of an exported class is the
    # library's public API, consumed by external callers the graph cannot see — not dead.
    # It carries a public_api surface (builder Pass 4), and that, not raw v.exported,
    # is what excludes it from the dead-code lead.
    mid = "ts-sym:src/core.ts#ProcessPromise.pipe"
    mv = Vertex(id=mid, kind="method", name="pipe", file="src/core.ts",
                start_line=1, end_line=2)
    net = Hypernetwork(language="ts", root="/x", vertices=[mv],
                       surfaces=[Surface(id="s", vertex_id=mid, kind="public_api")])
    assert not any(b.kind == "dead_code" for b in hunt(net))


def test_method_without_public_api_surface_is_still_dead_code():
    # The precision fix must not swallow a genuinely uncalled internal method: a method
    # NOT backed by a public_api surface (e.g. on a non-exported class) stays a dead lead.
    mid = "ts-sym:src/core.ts#Internal.helper"
    mv = Vertex(id=mid, kind="method", name="helper", file="src/core.ts",
                start_line=1, end_line=2)
    net = Hypernetwork(language="ts", root="/x", vertices=[mv])  # no surface
    assert any(b.kind == "dead_code" and b.symbol == mid for b in hunt(net))
