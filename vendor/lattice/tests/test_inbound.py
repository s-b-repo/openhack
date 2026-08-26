import pathlib
from lattice.graph.models import Vertex, Hypernetwork, Surface
from lattice.inbound import entrypoint_surface


def _net(tmp_path, vertices, surfaces):
    return Hypernetwork(language="ts", root=str(tmp_path), vertices=vertices,
                        hyperedges=[], surfaces=surfaces)


def test_entrypoint_asks_for_its_inputs_and_flags_no_bound_at_the_point(tmp_path):
    """Inbound boundary: an exported entry that accepts input but has NO explicit guard
    in its own body is unbounded AT THE POINT — surface what it asks for and that the
    bound is missing here (a guard 3 calls downstream is still a hole at the entry)."""
    (tmp_path / "api.ts").write_text(
        "export function deleteUser(userId: string, force: boolean) {\n"
        "  db.remove(userId)\n"
        "}\n")
    net = _net(tmp_path, [
        Vertex(id="ts:api.ts#deleteUser", kind="function", name="deleteUser",
               exported=True, file="api.ts", start_line=1, end_line=3),
    ], [Surface(id="s", vertex_id="ts:api.ts#deleteUser", kind="public_api")])
    eps = entrypoint_surface(net, str(tmp_path))
    ep = next(e for e in eps if e.symbol.endswith("deleteUser"))
    assert set(ep.asks_for) == {"userId", "force"}, ep.asks_for
    assert not ep.bounded and not ep.gates_at_point, "unbounded entry not flagged"


def test_entrypoint_with_an_explicit_guard_at_the_point_is_bounded(tmp_path):
    """An entry that calls a guard (authorize/validate/...) in its own body is bounded."""
    (tmp_path / "api.ts").write_text(
        "export function deleteUser(userId: string) {\n"
        "  authorize(userId)\n"
        "  db.remove(userId)\n"
        "}\n")
    net = _net(tmp_path, [
        Vertex(id="ts:api.ts#deleteUser", kind="function", name="deleteUser",
               exported=True, file="api.ts", start_line=1, end_line=4),
    ], [Surface(id="s", vertex_id="ts:api.ts#deleteUser", kind="public_api")])
    ep = next(e for e in entrypoint_surface(net, str(tmp_path))
              if e.symbol.endswith("deleteUser"))
    assert ep.bounded and "authorization" in ep.gates_at_point
