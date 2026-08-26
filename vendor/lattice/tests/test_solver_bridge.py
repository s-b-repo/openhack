# tests/test_solver_bridge.py
# Deterministic tests for the solver bridge — no SSH. The live z6 path is exercised
# manually; here we pin the QUBO encoding and the correctness guard with a fake `call`.
import lattice.solver_bridge as sb


def test_disabled_returns_none(monkeypatch):
    monkeypatch.delenv("FOOTINGS_SOLVER", raising=False)
    assert sb.min_feedback_arc_set({"a", "b", "c"},
                                   [("a", "b"), ("b", "c"), ("c", "a")]) is None


def test_qubo_is_symmetric():
    Q, _ = sb._min_fas_qubo(["a", "b", "c"], [("a", "b"), ("b", "c"), ("c", "a")])
    n = len(Q)
    assert all(abs(Q[i][j] - Q[j][i]) < 1e-9 for i in range(n) for j in range(n))


def test_good_solver_answer_is_accepted(monkeypatch):
    monkeypatch.setattr(sb, "enabled", lambda: True)
    # valid ordering a<b<c  => only c->a is a back edge
    def fake_call(name, params, timeout=20):
        x = [0] * 9
        x[0] = 1   # a at pos 0
        x[4] = 1   # b at pos 1
        x[8] = 1   # c at pos 2
        return {"x": x}
    monkeypatch.setattr(sb, "call", fake_call)
    cut = sb.min_feedback_arc_set(["a", "b", "c"],
                                  [("a", "b"), ("b", "c"), ("c", "a")])
    assert cut == [("c", "a")]


def test_bad_solver_answer_falls_back(monkeypatch):
    monkeypatch.setattr(sb, "enabled", lambda: True)
    monkeypatch.setattr(sb, "call", lambda *a, **k: {"x": [1] * 9})  # not one-hot -> invalid
    # guard rejects it -> None -> caller uses local greedy
    assert sb.min_feedback_arc_set(["a", "b", "c"],
                                   [("a", "b"), ("b", "c"), ("c", "a")]) is None


def test_solver_unreachable_returns_none(monkeypatch):
    monkeypatch.setattr(sb, "enabled", lambda: True)
    monkeypatch.setattr(sb, "call", lambda *a, **k: None)   # ssh failed / offline
    assert sb.min_feedback_arc_set(["a", "b", "c"],
                                   [("a", "b"), ("b", "c"), ("c", "a")]) is None
