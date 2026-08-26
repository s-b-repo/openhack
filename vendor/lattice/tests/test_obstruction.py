# tests/test_obstruction.py
# Footings port of the RRT obstruction theorem (01b_obstruction_theorem):
#   obstruction  <=>  beta_1 > 0  AND  a cycle carries an unsatisfied constraint.
# A witness is the MINIMAL inconsistent subnetwork (shortest cycle through a break).
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.obstruction.homology import betti
from lattice.obstruction.witness import extract_witnesses


def _v(vid, kind="function", stub=False):
    return Vertex(id=vid, kind=kind, name=vid, file="f", start_line=1, end_line=2, stub=stub)


def _net(vertices, edges):
    return Hypernetwork(language="ts", root="/x", vertices=vertices, hyperedges=edges)


def _e(a, b, resolved=True):
    return Hyperedge(id=f"{a}{b}", kind="calls", members=[a, b], resolved=resolved)


# --- homology: first Betti number beta_1 = E - V + components ---

def test_betti_triangle_has_one_cycle():
    net = _net([_v("a"), _v("b"), _v("c")], [_e("a", "b"), _e("b", "c"), _e("c", "a")])
    h = betti(net)
    assert h["b0"] == 1
    assert h["b1"] == 1            # 3 edges - 3 vertices + 1 component


def test_betti_tree_has_no_cycle():
    net = _net([_v("a"), _v("b"), _v("c")], [_e("a", "b"), _e("b", "c")])
    assert betti(net)["b1"] == 0   # 2 - 3 + 1


# --- the load-bearing distinction: a CLEAN cycle is NOT an obstruction ---

def test_clean_cycle_is_not_a_witness():
    net = _net([_v("a"), _v("b"), _v("c")],
               [_e("a", "b"), _e("b", "c"), _e("c", "a")])   # all resolved
    assert extract_witnesses(net) == []   # beta_1=1 but no broken constraint -> no obstruction


def test_broken_edge_in_a_cycle_is_a_minimal_witness():
    # a-b is broken, but a-c-b is an alternate path -> the cycle carries the break.
    net = _net([_v("a"), _v("b"), _v("c")],
               [_e("a", "b", resolved=False), _e("b", "c"), _e("c", "a")])
    ws = extract_witnesses(net)
    assert len(ws) == 1
    w = ws[0]
    assert set(w.cycle) == {"a", "b", "c"}
    assert w.broken_edge == ("a", "b")
    assert w.kind == "contradiction"


def test_broken_bridge_is_not_an_h1_witness():
    # a-b broken with NO alternate path -> a bridge -> beta_1 contribution 0 ->
    # this is a destruction (beta_0) failure, not an H1 contradiction witness.
    net = _net([_v("a"), _v("b"), _v("c"), _v("d")],
               [_e("a", "b", resolved=False), _e("b", "c"), _e("c", "d")])
    assert extract_witnesses(net) == []


def test_minimal_witness_picks_shortest_cycle():
    # a-b broken; two alternate paths exist (a-c-b length2, a-d-e-b length3).
    # the witness must be the SHORTEST cycle (minimal subnetwork).
    net = _net([_v("a"), _v("b"), _v("c"), _v("d"), _v("e")],
               [_e("a", "b", resolved=False), _e("a", "c"), _e("c", "b"),
                _e("a", "d"), _e("d", "e"), _e("e", "b")])
    ws = extract_witnesses(net)
    assert len(ws) == 1
    assert set(ws[0].cycle) == {"a", "b", "c"}   # the length-3 cycle, not the length-4
