# tests/test_plan.py
# Change planner — the RRT backward half: from the goal (change landed + green),
# collect preconditions (dependents updated) in safe order with verification gates.
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.plan import plan


def _v(vid, stub=False, exported=False):
    return Vertex(id=vid, kind="function", name=vid, file="f", start_line=1, end_line=2,
                  stub=stub, exported=exported)


def _e(a, b):
    return Hyperedge(id=a + b, kind="references", members=[a, b], resolved=True)


LIB, MID, APP = "lib", "mid", "app"


def _net(lib_stub=False):
    vs = [_v(LIB, stub=lib_stub), _v(MID), _v(APP, exported=True)]
    es = [_e(MID, LIB), _e(APP, MID)]              # app -> mid -> lib
    surf = [Surface(id="s", vertex_id=APP, kind="public_api")]
    return Hypernetwork(language="ts", root="/x", vertices=vs, hyperedges=es, surfaces=surf)


def test_plan_changes_target_then_propagates_outward():
    p = plan(_net(), LIB)
    actions = [(s.action, s.target) for s in p.steps]
    assert ("change", LIB) in actions
    assert ("update", MID) in actions
    assert ("update", APP) in actions
    # target changes before its dependents are updated
    change_o = next(s.order for s in p.steps if s.action == "change")
    first_update = min(s.order for s in p.steps if s.action == "update")
    assert change_o < first_update


def test_plan_inserts_verification_gates():
    p = plan(_net(), LIB)
    assert any(s.action == "verify" for s in p.steps)


def test_plan_flags_public_api_crossing():
    p = plan(_net(), LIB)
    assert APP in p.crosses_public_api


def test_plan_implements_stub_first():
    p = plan(_net(lib_stub=True), LIB)
    assert p.steps[0].action == "implement" and p.steps[0].target == LIB


def test_plan_flags_cycle_risk():
    net = Hypernetwork(language="ts", root="/x",
                       vertices=[_v("a"), _v("b")],
                       hyperedges=[_e("a", "b"), _e("b", "a")])
    p = plan(net, "a")
    assert p.has_cycle_risk is True
