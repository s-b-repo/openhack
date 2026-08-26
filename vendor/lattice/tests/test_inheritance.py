from lattice.ingest.types import RawIngest, RawSymbol
from lattice.graph.builder import build


def test_inherits_and_implements_edges_from_class_declaration():
    """`class C extends Base implements Iface` must produce an inherits edge C->Base and
    an implements edge C->Iface — a fundamental relationship the graph was missing, so
    a base class's blast radius can finally reach its subclasses."""
    raw = RawIngest(language="ts", root="/x", symbols=[
        RawSymbol(name="Base", kind="class", file="a.ts", start_line=1, end_line=2),
        RawSymbol(name="Iface", kind="interface", file="a.ts", start_line=3, end_line=4),
        RawSymbol(name="C", kind="class", file="a.ts", start_line=5, end_line=6,
                  extends=["Base"], implements=["Iface"]),
    ], references=[], files=["a.ts"])
    net = build(raw)
    inh = [e for e in net.hyperedges if e.kind == "inherits"]
    impl = [e for e in net.hyperedges if e.kind == "implements"]
    assert any(e.members[-1].endswith("#Base") for e in inh), [e.members for e in inh]
    assert any(e.members[-1].endswith("#Iface") for e in impl), [e.members for e in impl]


def test_unresolved_supertype_does_not_crash_and_is_skipped():
    """A base class from a library (no local vertex) shouldn't crash the build."""
    raw = RawIngest(language="ts", root="/x", symbols=[
        RawSymbol(name="C", kind="class", file="a.ts", start_line=1, end_line=2,
                  extends=["ExternalBase"]),
    ], references=[], files=["a.ts"])
    net = build(raw)
    assert net is not None      # ExternalBase has no local vertex -> just no edge


def test_dispatch_fans_interface_method_call_to_all_implementors():
    """One call, many endpoints: a call landing on interface method I.run must fan out to
    every implementor's run() — the multi-endpoint completion. Built on the implements
    edge (fact) + the implementor having a same-named method (fact), not name-guessing."""
    from lattice.graph.query import GraphView
    raw = RawIngest(language="ts", root="/x", symbols=[
        RawSymbol(name="I", kind="interface", file="i.ts", start_line=1, end_line=3),
        RawSymbol(name="run", kind="method", file="i.ts", start_line=2, end_line=2, container="I"),
        RawSymbol(name="A", kind="class", file="a.ts", start_line=1, end_line=4, implements=["I"]),
        RawSymbol(name="run", kind="method", file="a.ts", start_line=2, end_line=3, container="A"),
        RawSymbol(name="B", kind="class", file="b.ts", start_line=1, end_line=4, implements=["I"]),
        RawSymbol(name="run", kind="method", file="b.ts", start_line=2, end_line=3, container="B"),
    ], references=[], files=["i.ts", "a.ts", "b.ts"])
    net = build(raw)
    disp = [e for e in net.hyperedges if e.kind == "dispatch"]
    targets = {e.members[-1].split("#")[-1] for e in disp if e.members[0].endswith("#I.run")}
    assert {"A.run", "B.run"} <= targets, [e.members for e in disp]
    # reachability now crosses from the interface method to every implementation
    reach = GraphView(net).reachable_from("ts-sym:i.ts#I.run")
    assert any("A.run" in r for r in reach) and any("B.run" in r for r in reach), reach


def test_dispatch_reached_method_is_not_flagged_dead_or_unreached():
    """Consistency: a method reached ONLY via polymorphic dispatch (interface call) is
    reached — reachability already fans out to it, so dead-code/blindspots must NOT call
    it dead. Otherwise adding dispatch edges regresses dead-code precision."""
    from lattice.ingest.types import RawReference
    from lattice.hunt import hunt
    from lattice.blindspots import blindspots
    raw = RawIngest(language="ts", root="/x", symbols=[
        RawSymbol(name="main", kind="function", file="m.ts", start_line=1, end_line=3, exported=True),
        RawSymbol(name="I", kind="interface", file="i.ts", start_line=1, end_line=3),
        RawSymbol(name="run", kind="method", file="i.ts", start_line=2, end_line=2, container="I"),
        RawSymbol(name="A", kind="class", file="a.ts", start_line=1, end_line=4, implements=["I"]),
        RawSymbol(name="run", kind="method", file="a.ts", start_line=2, end_line=3, container="A"),
    ], references=[
        RawReference(kind="references", from_file="m.ts", from_line=2,
                     to_file="i.ts", to_line=2, resolved=True),
    ], files=["m.ts", "i.ts", "a.ts"])
    net = build(raw)
    assert not [b for b in hunt(net) if b.kind == "dead_code" and "A.run" in b.symbol], \
        "dispatch-reached method falsely flagged dead"
    assert not any("A.run" in u for u in blindspots(net).unreached), \
        "dispatch-reached method falsely listed as unreached"
