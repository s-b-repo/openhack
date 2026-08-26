from lattice.ingest.types import RawSymbol, RawReference, RawIngest
from lattice.graph.builder import build
from lattice.complete.gate import check


def test_import_to_symbolless_ingested_file_resolves():
    # a.ts has a function and imports ./b ; b.ts was ingested (in files) but has NO symbols
    foo = RawSymbol(name="foo", kind="function", file="a.ts", start_line=2, end_line=4, exported=True)
    imp = RawReference(kind="imports", from_file="a.ts", from_line=1, to_file="b.ts", to_line=1, resolved=True)
    raw = RawIngest(language="typescript", root="/x", symbols=[foo], references=[imp],
                    diagnostics=[], files=["a.ts", "b.ts"])
    net = build(raw)
    # b.ts has a module vertex even though it had no symbols
    assert any(v.kind == "module" and v.file == "b.ts" for v in net.vertices)
    # the import resolves and the gate does not flag it
    rep = check(net)
    assert rep.unresolved_imports == []
    assert rep.verdict in ("pass", "partial")


def test_import_to_uningested_file_still_fails():
    foo = RawSymbol(name="foo", kind="function", file="a.ts", start_line=2, end_line=4, exported=True)
    imp = RawReference(kind="imports", from_file="a.ts", from_line=1, to_file="ghost.ts", to_line=1, resolved=True)
    raw = RawIngest(language="typescript", root="/x", symbols=[foo], references=[imp],
                    diagnostics=[], files=["a.ts"])  # ghost.ts NOT ingested
    net = build(raw)
    rep = check(net)
    assert rep.verdict == "fail"
