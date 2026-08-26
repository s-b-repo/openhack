from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.hunt import hunt


def _v(vid, name, kind, file="f"):
    return Vertex(id=vid, kind=kind, name=name, file=file, start_line=1, end_line=2)


def _e(a, b):
    return Hyperedge(id=a + b, kind="references", members=[a, b], resolved=True)


def test_unused_class_aggregates_to_one_finding():
    # class Q with 2 dead methods, Q itself referenced nowhere -> ONE dead_class finding
    net = Hypernetwork(language="ts", root="/x", vertices=[
        _v("ts:f#Q", "Q", "class"),
        _v("ts:f#Q.add", "add", "method"),
        _v("ts:f#Q.run", "run", "method"),
    ], hyperedges=[])
    bugs = hunt(net)
    dc = [b for b in bugs if b.kind == "dead_class"]
    assert len(dc) == 1 and dc[0].symbol == "ts:f#Q"
    assert not any(b.kind == "dead_code" and "Q." in b.symbol for b in bugs)   # methods folded in


def test_dead_method_of_a_used_class_stays_individual():
    # Q is used (referenced); one method unused -> individual dead_code, NOT dead_class
    net = Hypernetwork(language="ts", root="/x", vertices=[
        _v("ts:f#Q", "Q", "class"),
        _v("ts:f#Q.used", "used", "method"),
        _v("ts:f#Q.unused", "unused", "method"),
        _v("ts:f#client", "client", "function"),
    ], hyperedges=[_e("ts:f#client", "ts:f#Q"), _e("ts:f#client", "ts:f#Q.used")])
    bugs = hunt(net)
    assert not any(b.kind == "dead_class" for b in bugs)
    assert any(b.kind == "dead_code" and b.symbol == "ts:f#Q.unused" for b in bugs)
