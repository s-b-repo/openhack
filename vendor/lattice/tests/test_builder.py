# tests/test_builder.py
from lattice.ingest.types import RawSymbol, RawReference, RawIngest
from lattice.graph.builder import build
from lattice.complete.gate import check

def _ingest():
    foo = RawSymbol(name="foo", kind="function", file="a.ts", start_line=1, end_line=5,
                    exported=True, is_stub=False)
    bar = RawSymbol(name="bar", kind="function", file="b.ts", start_line=1, end_line=4,
                    exported=False, is_stub=True)
    call = RawReference(kind="calls", from_file="a.ts", from_line=3,
                        to_file="b.ts", to_line=2, resolved=True)
    ext = RawReference(kind="calls", from_file="a.ts", from_line=4,
                       to_file=None, to_line=None, resolved=False)
    return RawIngest(language="typescript", root="/x",
                     symbols=[foo, bar], references=[call, ext], diagnostics=[])

def test_build_creates_vertices_edges_surfaces():
    net = build(_ingest())
    ids = {v.id for v in net.vertices}
    assert "ts-sym:a.ts#foo" in ids and "ts-sym:b.ts#bar" in ids
    resolved = [e for e in net.hyperedges if e.resolved and e.kind == "calls"]
    assert any(e.members == ["ts-sym:a.ts#foo", "ts-sym:b.ts#bar"] for e in resolved)
    assert any(v.kind == "external" for v in net.vertices)
    assert any(not e.resolved for e in net.hyperedges)
    skinds = {s.kind for s in net.surfaces}
    assert "public_api" in skinds and "external_call" in skinds
    assert next(v for v in net.vertices if v.name == "bar").stub is True


def _ingest_with_imports():
    """Ingest with: a.ts has foo, b.ts has bar, an import a->b, and a call a->b."""
    foo = RawSymbol(name="foo", kind="function", file="a.ts", start_line=2, end_line=5,
                    exported=True, is_stub=False)
    bar = RawSymbol(name="bar", kind="function", file="b.ts", start_line=1, end_line=4,
                    exported=True, is_stub=False)
    imp = RawReference(kind="imports", from_file="a.ts", from_line=1,
                       to_file="b.ts", to_line=1, resolved=True)
    call = RawReference(kind="calls", from_file="a.ts", from_line=3,
                        to_file="b.ts", to_line=2, resolved=True)
    return RawIngest(language="typescript", root="/x",
                     symbols=[foo, bar], references=[imp, call], diagnostics=[])


def test_module_vertices_exist():
    """Build should synthesize a module vertex for each file that has symbols."""
    net = build(_ingest_with_imports())
    ids = {v.id for v in net.vertices}
    assert "ts-sym:a.ts#<module>" in ids
    assert "ts-sym:b.ts#<module>" in ids
    mod_verts = [v for v in net.vertices if v.kind == "module"]
    mod_files = {v.name for v in mod_verts}
    assert "a.ts" in mod_files and "b.ts" in mod_files


def test_imports_edge_connects_modules_resolved():
    """The imports hyperedge must connect module vertices and be resolved=True."""
    net = build(_ingest_with_imports())
    imports_edges = [e for e in net.hyperedges if e.kind == "imports"]
    assert imports_edges, "expected at least one imports hyperedge"
    e = imports_edges[0]
    assert e.members == ["ts-sym:a.ts#<module>", "ts-sym:b.ts#<module>"]
    assert e.resolved is True


def test_call_edge_resolves_to_function_vertices_not_modules():
    """call/reference edges should still resolve to the enclosing function vertices."""
    net = build(_ingest_with_imports())
    call_edges = [e for e in net.hyperedges if e.kind == "calls" and e.resolved]
    assert call_edges, "expected at least one resolved calls hyperedge"
    # members must be function ids, not module ids
    assert any(
        e.members == ["ts-sym:a.ts#foo", "ts-sym:b.ts#bar"]
        for e in call_edges
    ), f"no calls edge between foo and bar; edges: {[e.members for e in call_edges]}"


def test_public_methods_of_exported_class_get_public_api_surfaces():
    """A TS class method never individually carries `export` — only the class does.
    A *public* method of an exported class is still public API (external callers reach
    it), so Pass 4 must give it a public_api surface; `_`/`#`-prefixed members and
    methods of non-exported classes must not get one."""
    cls = RawSymbol(name="Svc", kind="class", file="svc.ts", start_line=1, end_line=20,
                    exported=True)
    run = RawSymbol(name="run", kind="method", file="svc.ts", start_line=2, end_line=4,
                    container="Svc", exported=False)
    helper = RawSymbol(name="_helper", kind="method", file="svc.ts", start_line=5,
                       end_line=7, container="Svc", exported=False)
    secret = RawSymbol(name="#secret", kind="method", file="svc.ts", start_line=8,
                       end_line=10, container="Svc", exported=False)
    intern = RawSymbol(name="Internal", kind="class", file="svc.ts", start_line=21,
                       end_line=30, exported=False)
    lonely = RawSymbol(name="lonely", kind="method", file="svc.ts", start_line=22,
                       end_line=24, container="Internal", exported=False)
    net = build(RawIngest(language="typescript", root="/x",
                          symbols=[cls, run, helper, secret, intern, lonely],
                          files=["svc.ts"]))
    api = {s.vertex_id for s in net.surfaces if s.kind == "public_api"}
    assert "ts-sym:svc.ts#Svc.run" in api            # public method of exported class
    assert "ts-sym:svc.ts#Svc._helper" not in api    # convention-internal
    assert "ts-sym:svc.ts#Svc.#secret" not in api    # hard-private
    assert "ts-sym:svc.ts#Internal.lonely" not in api  # method of non-exported class


# --- cross-language name-based call-edge recall (shared builder pass) ---------

def _named_ref(from_file, from_line, name, to_file=None, to_line=None, resolved=False):
    return RawReference(kind="references", from_file=from_file, from_line=from_line,
                        to_file=to_file, to_line=to_line, resolved=resolved, name=name)


def test_name_match_recovers_single_candidate_call():
    caller = RawSymbol(name="caller", kind="function", file="a.ts", start_line=1,
                       end_line=5, exported=True)
    target = RawSymbol(name="target", kind="function", file="b.ts", start_line=1, end_line=3)
    net = build(RawIngest(language="typescript", root="/x", symbols=[caller, target],
                          references=[_named_ref("a.ts", 3, "target")],
                          files=["a.ts", "b.ts"]))
    e = [x for x in net.hyperedges
         if x.members == ["ts-sym:a.ts#caller", "ts-sym:b.ts#target"]]
    assert e and e[0].resolved and e[0].provenance == "name-match"


def test_name_match_ambiguous_emits_dispatch_to_all():
    caller = RawSymbol(name="caller", kind="function", file="a.ts", start_line=1,
                       end_line=5, exported=True)
    cA = RawSymbol(name="A", kind="class", file="b.ts", start_line=1, end_line=10)
    rA = RawSymbol(name="run", kind="method", file="b.ts", start_line=2, end_line=4,
                   container="A")
    cB = RawSymbol(name="B", kind="class", file="c.ts", start_line=1, end_line=10)
    rB = RawSymbol(name="run", kind="method", file="c.ts", start_line=2, end_line=4,
                   container="B")
    net = build(RawIngest(language="typescript", root="/x",
                          symbols=[caller, cA, rA, cB, rB],
                          references=[_named_ref("a.ts", 3, "run")],
                          files=["a.ts", "b.ts", "c.ts"]))
    disp = [e for e in net.hyperedges if e.kind == "dispatch" and e.provenance == "name-match"]
    tgts = {e.members[-1] for e in disp}
    assert "ts-sym:b.ts#A.run" in tgts and "ts-sym:c.ts#B.run" in tgts
    assert all(e.confidence < 1.0 for e in disp)


def test_name_match_no_candidate_is_unchanged():
    caller = RawSymbol(name="caller", kind="function", file="a.ts", start_line=1,
                       end_line=5, exported=True)
    net = build(RawIngest(language="typescript", root="/x", symbols=[caller],
                          references=[_named_ref("a.ts", 3, "nonexistent")],
                          files=["a.ts"]))
    assert not any(e.provenance == "name-match" for e in net.hyperedges)
    assert any(s.kind == "external_call" for s in net.surfaces)


def test_reference_without_name_never_triggers_pass():
    # Safety property protecting the baseline: a ref with name=None is the old behavior.
    caller = RawSymbol(name="caller", kind="function", file="a.ts", start_line=1,
                       end_line=5, exported=True)
    target = RawSymbol(name="target", kind="function", file="b.ts", start_line=1, end_line=3)
    net = build(RawIngest(language="typescript", root="/x", symbols=[caller, target],
                          references=[RawReference(kind="references", from_file="a.ts",
                                                   from_line=3, to_file=None, resolved=False)],
                          files=["a.ts", "b.ts"]))
    assert not any(e.provenance == "name-match" for e in net.hyperedges)


def test_name_match_adds_sibling_dispatch_when_already_resolved():
    # Frontend resolved caller->A.run by location; name "run" also matches B.run, so the
    # pass adds a dispatch edge to the sibling while keeping the resolved edge intact.
    caller = RawSymbol(name="caller", kind="function", file="a.ts", start_line=1,
                       end_line=5, exported=True)
    cA = RawSymbol(name="A", kind="class", file="b.ts", start_line=1, end_line=10)
    rA = RawSymbol(name="run", kind="method", file="b.ts", start_line=2, end_line=4,
                   container="A")
    cB = RawSymbol(name="B", kind="class", file="c.ts", start_line=1, end_line=10)
    rB = RawSymbol(name="run", kind="method", file="c.ts", start_line=2, end_line=4,
                   container="B")
    net = build(RawIngest(language="typescript", root="/x",
                          symbols=[caller, cA, rA, cB, rB],
                          references=[_named_ref("a.ts", 3, "run", to_file="b.ts",
                                                 to_line=2, resolved=True)],
                          files=["a.ts", "b.ts", "c.ts"]))
    assert any(e.members == ["ts-sym:a.ts#caller", "ts-sym:b.ts#A.run"]
               and e.resolved and e.kind == "references" for e in net.hyperedges)
    assert any(e.kind == "dispatch" and e.members[-1] == "ts-sym:c.ts#B.run"
               and e.provenance == "name-match" for e in net.hyperedges)


def test_name_match_is_language_agnostic():
    # The same pass fires regardless of language prefix (cs-wide).
    caller = RawSymbol(name="caller", kind="function", file="a.py", start_line=1,
                       end_line=5, exported=True)
    target = RawSymbol(name="target", kind="function", file="b.py", start_line=1, end_line=3)
    net = build(RawIngest(language="python", root="/x", symbols=[caller, target],
                          references=[_named_ref("a.py", 3, "target")],
                          files=["a.py", "b.py"]))
    assert any(e.members == ["py-sym:a.py#caller", "py-sym:b.py#target"]
               and e.provenance == "name-match" for e in net.hyperedges)


def test_containment_links_object_literal_members_via_line_nesting():
    # LSP flattens object-literal members to container-less module-level methods; line
    # nesting recovers the `defines` link to their container (the zx `formatters` case).
    fmt = RawSymbol(name="formatters", kind="variable", file="log.ts", start_line=1,
                    end_line=10, exported=True)
    cmd = RawSymbol(name="cmd", kind="method", file="log.ts", start_line=2, end_line=3)
    out = RawSymbol(name="stdout", kind="method", file="log.ts", start_line=4, end_line=5)
    net = build(RawIngest(language="typescript", root="/x", symbols=[fmt, cmd, out],
                          files=["log.ts"]))
    defines = {(e.members[0], e.members[-1]) for e in net.hyperedges if e.kind == "defines"}
    assert ("ts-sym:log.ts#formatters", "ts-sym:log.ts#cmd") in defines
    assert ("ts-sym:log.ts#formatters", "ts-sym:log.ts#stdout") in defines


def test_dyn_dispatch_emits_dispatch_edges_to_container_members():
    # A dyn_dispatch ref (frontend-flagged `formatters[k]()`) -> dispatch edges from the
    # enclosing fn to every member of the named container, with dynamic-dispatch provenance.
    fmt = RawSymbol(name="formatters", kind="variable", file="log.ts", start_line=1,
                    end_line=10, exported=True)
    cmd = RawSymbol(name="cmd", kind="method", file="log.ts", start_line=2, end_line=3)
    out = RawSymbol(name="stdout", kind="method", file="log.ts", start_line=4, end_line=5)
    printer = RawSymbol(name="printLog", kind="function", file="log.ts", start_line=15,
                        end_line=25, exported=True)
    ref = RawReference(kind="dyn_dispatch", from_file="log.ts", from_line=20,
                       name="formatters")
    net = build(RawIngest(language="typescript", root="/x",
                          symbols=[fmt, cmd, out, printer], references=[ref],
                          files=["log.ts"]))
    dd = {(e.members[0], e.members[-1]) for e in net.hyperedges
          if e.kind == "dispatch" and e.provenance == "dynamic-dispatch"}
    assert ("ts-sym:log.ts#printLog", "ts-sym:log.ts#cmd") in dd
    assert ("ts-sym:log.ts#printLog", "ts-sym:log.ts#stdout") in dd


def test_dyn_dispatch_unknown_base_emits_nothing():
    printer = RawSymbol(name="printLog", kind="function", file="log.ts", start_line=15,
                        end_line=25, exported=True)
    ref = RawReference(kind="dyn_dispatch", from_file="log.ts", from_line=20,
                       name="nonexistent")
    net = build(RawIngest(language="typescript", root="/x", symbols=[printer],
                          references=[ref], files=["log.ts"]))
    assert not any(e.provenance == "dynamic-dispatch" for e in net.hyperedges)


def test_class_symbol_not_clobbered_by_same_named_variable():
    # zod: `export class ZodArray` collides on vertex id with the enum member
    # `ZodArray = "ZodArray"` (a non-exported variable). The class must win regardless of
    # symbol order, else Pass-1 last-writer-wins destroys it and its methods leak as dead.
    cls = RawSymbol(name="ZodArray", kind="class", file="t.ts", start_line=10,
                    end_line=50, exported=True)
    member = RawSymbol(name="ZodArray", kind="variable", file="t.ts", start_line=100,
                       end_line=100, exported=False)
    for order in ([cls, member], [member, cls]):
        net = build(RawIngest(language="typescript", root="/x", symbols=list(order),
                              files=["t.ts"]))
        collided = [x for x in net.vertices if x.name == "ZodArray"]
        assert {v.kind for v in collided} == {"class", "variable"}, order
        assert next(v for v in collided if v.kind == "class").exported
        assert all("@S" in v.id for v in collided)


def test_collided_exported_class_still_exposes_its_public_method():
    cls = RawSymbol(name="ZodArray", kind="class", file="t.ts", start_line=10,
                    end_line=30, exported=True)
    member = RawSymbol(name="ZodArray", kind="variable", file="t.ts", start_line=100,
                       end_line=100)
    method = RawSymbol(name="parse", kind="method", file="t.ts", start_line=15,
                       end_line=20, container="ZodArray", exported=False)
    net = build(RawIngest(language="typescript", root="/x",
                          symbols=[cls, member, method], files=["t.ts"]))
    method_id = next(v.id for v in net.vertices if v.name == "parse")

    assert method_id in {s.vertex_id for s in net.surfaces if s.kind == "public_api"}


def test_distinct_colliding_definitions_remain_ambiguous_and_duplicates_dedupe():
    caller = RawSymbol(name="invoke", kind="method", file="a.ts", start_line=20,
                       end_line=24, container="Caller")
    first = RawSymbol(name="run", kind="method", file="a.ts", start_line=2,
                      end_line=3, container="LostNamespace")
    second = RawSymbol(name="run", kind="method", file="a.ts", start_line=8,
                       end_line=9, container="LostNamespace")
    raw = RawIngest(
        language="typescript", root="/x", files=["a.ts"],
        symbols=[caller, first, first, second],
        references=[_named_ref("a.ts", 22, "run")],
    )
    net = build(raw)
    runs = [v for v in net.vertices if v.name == "run"]
    run_ids = {v.id for v in runs}
    target_edges = [e for e in net.hyperedges if e.members[-1] in run_ids]

    assert len(runs) == 2
    assert all("@S" in v.id for v in runs)
    assert {v.start_line for v in runs} == {2, 8}
    assert target_edges
    assert all(e.kind == "dispatch" and e.provenance == "name-match"
               and e.confidence < 1.0 for e in target_edges)


def test_intended_internal_target_is_never_recovered_to_unrelated_unique_name():
    caller = RawSymbol(name="caller", kind="function", file="caller.py",
                       start_line=1, end_line=4)
    unrelated = RawSymbol(name="helper", kind="function", file="other.py",
                          start_line=1, end_line=2)
    raw = RawIngest(
        language="python", root="/x", files=["caller.py", "other.py"],
        symbols=[caller, unrelated],
        references=[RawReference(
            kind="references", from_file="caller.py", from_line=2,
            to_file="missing.py", resolved=False, name="helper",
        )],
    )
    net = build(raw)
    helper_id = next(v.id for v in net.vertices if v.name == "helper")
    call_edges = [e for e in net.hyperedges if e.members[0].endswith("#caller")]

    assert call_edges and all(not e.resolved for e in call_edges)
    assert not any(e.members[-1] == helper_id for e in call_edges)
    assert "dangling_edges" in check(net).failing_checks


def test_ambiguous_same_span_target_never_falls_back_to_module_vertex():
    caller = RawSymbol(name="caller", kind="function", file="caller.py",
                       start_line=1, end_line=4)
    first = RawSymbol(name="run", kind="method", file="target.py",
                      start_line=5, end_line=8, container="Lost", params=["x"])
    second = RawSymbol(name="run", kind="method", file="target.py",
                       start_line=5, end_line=8, container="Lost", params=["x", "y"])
    raw = RawIngest(
        language="python", root="/x", files=["caller.py", "target.py"],
        symbols=[caller, first, second],
        references=[RawReference(
            kind="references", from_file="caller.py", from_line=2,
            to_file="target.py", to_line=6, resolved=True, name="run",
        )],
    )
    net = build(raw)
    module_id = "py-sym:target.py#<module>"
    call_edges = [e for e in net.hyperedges if e.members[0].endswith("#caller")]

    assert call_edges and all(not e.resolved for e in call_edges)
    assert not any(e.members[-1] == module_id for e in call_edges)
    assert "dangling_edges" in check(net).failing_checks


def test_containment_no_defines_for_top_level_function():
    f = RawSymbol(name="helper", kind="function", file="a.ts", start_line=1, end_line=3,
                  exported=True)
    net = build(RawIngest(language="typescript", root="/x", symbols=[f], files=["a.ts"]))
    assert not any(e.kind == "defines" for e in net.hyperedges)


def test_name_match_dispatch_is_method_only():
    # Free functions sharing a name across modules are namespacing coincidences, not
    # polymorphic dispatch — no dispatch edges. (A *unique* function name still recovers.)
    caller = RawSymbol(name="caller", kind="function", file="a.ts", start_line=1,
                       end_line=5, exported=True)
    f1 = RawSymbol(name="dfs", kind="function", file="b.ts", start_line=1, end_line=3)
    f2 = RawSymbol(name="dfs", kind="function", file="c.ts", start_line=1, end_line=3)
    net = build(RawIngest(language="typescript", root="/x", symbols=[caller, f1, f2],
                          references=[_named_ref("a.ts", 3, "dfs")],
                          files=["a.ts", "b.ts", "c.ts"]))
    assert not any(e.kind == "dispatch" and e.provenance == "name-match"
                   for e in net.hyperedges)


def test_name_match_skips_high_fanout_common_names():
    # A ubiquitous name (to_dict on many classes) must NOT explode into N low-confidence
    # dispatch edges — too ambiguous to be a useful lead (SILENCE != proof). Measured on
    # lattice's own source: unguarded dispatch-to-all made to_dict a 20-way fan-out.
    syms = [RawSymbol(name="caller", kind="function", file="a.ts", start_line=1,
                      end_line=5, exported=True)]
    files = ["a.ts"]
    for i in range(8):
        syms.append(RawSymbol(name=f"C{i}", kind="class", file=f"c{i}.ts",
                              start_line=1, end_line=4))
        syms.append(RawSymbol(name="to_dict", kind="method", file=f"c{i}.ts",
                              start_line=2, end_line=3, container=f"C{i}"))
        files.append(f"c{i}.ts")
    net = build(RawIngest(language="typescript", root="/x", symbols=syms,
                          references=[_named_ref("a.ts", 3, "to_dict")], files=files))
    assert not any(e.provenance == "name-match" for e in net.hyperedges)


def test_module_vertices_not_in_public_api_surfaces():
    """module vertices must not produce public_api surfaces."""
    net = build(_ingest_with_imports())
    api_vertex_ids = {s.vertex_id for s in net.surfaces if s.kind == "public_api"}
    module_ids = {v.id for v in net.vertices if v.kind == "module"}
    overlap = api_vertex_ids & module_ids
    assert not overlap, f"module vertices appear in public_api surfaces: {overlap}"


def test_cpp_namespace_separators_preserve_method_ownership_and_dispatch():
    base = RawSymbol(name="Base", kind="class", file="api.cpp", start_line=1,
                     end_line=10, container="ns", exported=True)
    base_run = RawSymbol(name="run", kind="method", file="api.cpp", start_line=3,
                         end_line=5, container="ns::Base")
    derived = RawSymbol(name="Derived", kind="class", file="api.cpp", start_line=20,
                        end_line=30, container="ns", exported=True,
                        extends=["ns::Base"])
    derived_run = RawSymbol(name="run", kind="method", file="api.cpp", start_line=23,
                            end_line=25, container="ns::Derived")

    net = build(RawIngest(language="cpp", root="/x", files=["api.cpp"],
                          symbols=[base, base_run, derived, derived_run]))
    base_id = next(v.id for v in net.vertices if v.name == "run" and "ns.Base" in v.id)
    derived_id = next(v.id for v in net.vertices if v.name == "run" and "ns.Derived" in v.id)

    assert any(e.kind == "inherits" for e in net.hyperedges)
    assert any(e.kind == "dispatch" and e.members == [base_id, derived_id]
               for e in net.hyperedges)
