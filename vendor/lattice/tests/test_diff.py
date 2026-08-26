# tests/test_diff.py
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork, Surface
from lattice.graph.builder import build
from lattice.ingest.types import RawIngest, RawSymbol
from lattice.complete.diff import diff


def _v(vid, file="a.ts", kind="function", **kw):
    return Vertex(id=vid, kind=kind, name=vid.split("#")[-1], file=file,
                  start_line=1, end_line=2, **kw)


def _net(vertices, edges):
    return Hypernetwork(language="typescript", root="/x",
                        vertices=vertices, hyperedges=edges)


FOO = "ts-sym:a.ts#foo"
BAR = "ts-sym:a.ts#bar"
EXT = "ts-sym:<external>#unknown"


def _ext_v():
    return Vertex(id=EXT, kind="external", name="unknown", file="<external>",
                  start_line=0, end_line=0)


def test_identical_networks_are_clean():
    net = _net([_v(FOO)],
               [Hyperedge(id="e1", kind="calls", members=[FOO, FOO], resolved=True)])
    d = diff(net, net)
    assert d.verdict == "clean"
    assert d.added_vertices == [] and d.removed_vertices == []
    assert d.new_dangling_edges == [] and d.new_unresolved_imports == []


def test_added_clean_edge_is_clean():
    before = _net([_v(FOO)], [])
    after = _net([_v(FOO), _v(BAR)],
                 [Hyperedge(id="e1", kind="calls", members=[FOO, BAR], resolved=True)])
    d = diff(before, after)
    assert BAR in d.added_vertices
    assert d.verdict == "clean"
    assert d.new_dangling_edges == []


def test_new_unresolved_import_is_a_regression():
    before = _net([_v(FOO)], [])
    after = _net([_v(FOO)],
                 [Hyperedge(id="e1", kind="imports",
                            members=[FOO, "ts-sym:missing.ts#<module>"], resolved=False)])
    d = diff(before, after)
    assert d.new_unresolved_imports
    assert d.verdict == "regressed"


def test_preexisting_break_is_NOT_blamed_on_the_change():
    # The whole point of differential: if the broken import was ALREADY broken
    # before the agent touched anything, the diff must stay clean.
    broken = Hyperedge(id="e1", kind="imports",
                       members=[FOO, "ts-sym:missing.ts#<module>"], resolved=False)
    before = _net([_v(FOO)], [broken])
    after = _net([_v(FOO)], [broken])
    d = diff(before, after)
    assert d.new_unresolved_imports == []
    assert d.verdict == "clean"


def test_new_error_diagnostic_is_a_regression_but_preexisting_identical_is_not():
    diagnostic = {"severity": "error", "kind": "parse_error", "file": "broken.py",
                  "message": "invalid syntax"}
    before = _net([_v(FOO)], [])
    after = _net([_v(FOO)], [])
    after.diagnostics = [diagnostic]

    introduced = diff(before, after)
    assert introduced.error_diagnostics == [diagnostic]
    assert introduced.new_error_diagnostics == [diagnostic]
    assert introduced.verdict == "regressed"
    assert "new_error_diagnostics" in introduced.regressions

    preexisting = diff(after, Hypernetwork.from_dict(after.to_dict()))
    assert preexisting.error_diagnostics == [diagnostic]
    assert preexisting.new_error_diagnostics == []
    assert preexisting.regressions == []
    assert preexisting.verdict == "unverifiable"
    assert preexisting.verified == []
    assert "structural_delta" in preexisting.not_verified


def test_incomplete_baseline_remains_unverifiable_when_error_disappears():
    diagnostic = {"severity": "error", "kind": "parse_error", "file": "broken.py",
                  "message": "invalid syntax"}
    before = _net([_v(FOO)], [])
    before.diagnostics = [diagnostic]
    after = _net([_v(FOO)], [])

    report = diff(before, after)

    assert report.baseline_error_diagnostics == [diagnostic]
    assert report.error_diagnostics == []
    assert report.verdict == "unverifiable"
    assert report.verified == []
    assert "structural_delta" in report.not_verified


def test_new_warning_diagnostic_is_not_a_structural_regression():
    before = _net([_v(FOO)], [])
    after = _net([_v(FOO)], [])
    after.diagnostics = [{"severity": "warning", "kind": "partial", "message": "lead"}]
    report = diff(before, after)

    assert report.new_error_diagnostics == []
    assert report.verdict == "clean"


def test_preexisting_error_makes_other_structural_delta_unverifiable():
    diagnostic = {"severity": "error", "kind": "bridge_error", "message": "tool missing"}
    before = _net([_v(FOO, exported=True)], [])
    before.diagnostics = [diagnostic]
    after = _net([], [])
    after.diagnostics = [diagnostic]

    report = diff(before, after)

    assert report.removed_public_api == [FOO]
    assert "removed_public_api" in report.regressions
    assert report.new_error_diagnostics == []
    assert report.verdict == "unverifiable"


def test_preexisting_diagnostic_checkout_paths_do_not_look_new():
    before = Hypernetwork(
        language="go", root="/tmp/lattice-base-123/tree",
        diagnostics=[{
            "severity": "error", "kind": "parse_error", "file": "broken.go",
            "message": "/tmp/lattice-base-123/tree/broken.go:2: expected declaration",
        }],
    )
    after = Hypernetwork(
        language="go", root="/work/project",
        diagnostics=[{
            "severity": "error", "kind": "parse_error", "file": "broken.go",
            "message": "/work/project/broken.go:2: expected declaration",
        }],
    )

    report = diff(before, after)

    assert report.new_error_diagnostics == []
    assert report.verdict == "unverifiable"


def test_removing_a_referenced_vertex_breaks_downstream():
    # Agent deletes foo, but an edge from bar still points at it.
    edge = Hyperedge(id="e1", kind="calls", members=[BAR, FOO], resolved=True)
    before = _net([_v(FOO), _v(BAR)], [edge])
    # after: foo deleted, the edge still references it
    after = _net([_v(BAR)], [edge])
    d = diff(before, after)
    assert FOO in d.removed_vertices
    assert FOO in str(d.broken_by_removal)
    assert d.verdict == "regressed"


def test_removing_an_exported_public_api_is_a_regression():
    # Strict policy: deleting an exported function/method is a regression even with
    # zero in-repo references — public_api is the external surface the graph can't see.
    before = _net([_v(FOO, exported=True)], [])
    after = _net([], [])
    d = diff(before, after)
    assert FOO in d.removed_public_api
    assert "removed_public_api" in d.regressions
    assert d.verdict == "regressed"


def test_removing_a_private_symbol_is_not_a_public_api_regression():
    # Non-exported symbol with no references -> clean (internal, no external surface).
    before = _net([_v(BAR, exported=False)], [])
    after = _net([], [])
    d = diff(before, after)
    assert d.removed_public_api == []
    assert d.verdict == "clean"


def test_public_to_private_and_surface_removal_is_a_regression():
    before = _net([_v(FOO, exported=True)], [])
    before.surfaces = [Surface(id="s1", vertex_id=FOO, kind="public_api")]
    after = _net([_v(FOO, exported=False)], [])

    report = diff(before, after)

    assert report.removed_public_api == [FOO]
    assert report.removed_surfaces
    assert report.verdict == "regressed"


def test_public_signature_change_is_a_regression_without_id_churn():
    before_vertex = _v(FOO, exported=True, type="(string)->void")
    after_vertex = _v(FOO, exported=True, type="(number)->void")
    surface = Surface(id="s1", vertex_id=FOO, kind="public_api")

    report = diff(
        Hypernetwork("typescript", "/x", [before_vertex], [], [surface]),
        Hypernetwork("typescript", "/x", [after_vertex], [], [surface]),
    )

    assert report.changed_vertices == [FOO]
    assert report.changed_public_api == [FOO]
    assert report.verdict == "regressed"


def test_edge_confidence_or_fact_provenance_downgrade_is_a_regression():
    def network(confidence, provenance):
        return _net([_v(FOO), _v(BAR)], [
            Hyperedge(id="e", kind="calls", members=[FOO, BAR], resolved=True,
                      confidence=confidence, provenance=provenance),
        ])

    confidence = diff(network(1.0, "ingest"), network(0.25, "ingest"))
    provenance = diff(network(1.0, "ingest"), network(1.0, "ambiguous-name"))

    assert confidence.downgraded_edges and confidence.verdict == "regressed"
    assert provenance.downgraded_edges and provenance.verdict == "regressed"


def test_resolving_a_previously_broken_import_is_an_improvement_not_regression():
    broken = Hyperedge(id="e1", kind="imports",
                       members=[FOO, "ts-sym:b.ts#<module>"], resolved=False)
    fixed = Hyperedge(id="e1", kind="imports",
                      members=[FOO, "ts-sym:b.ts#<module>"], resolved=True)
    before = _net([_v(FOO)], [broken])
    after = _net([_v(FOO), _v("ts-sym:b.ts#<module>", file="b.ts", kind="module")], [fixed])
    d = diff(before, after)
    assert d.new_unresolved_imports == []
    assert d.verdict == "clean"


def test_comment_line_shift_does_not_delete_collided_public_api():
    def network(offset):
        return build(RawIngest(
            language="typescript",
            root="/x",
            files=["api.ts"],
            symbols=[
                RawSymbol(name="run", kind="function", file="api.ts",
                          start_line=10 + offset, end_line=12 + offset,
                          type="(value: string) => void", exported=True,
                          params=["value"]),
                RawSymbol(name="run", kind="function", file="api.ts",
                          start_line=20 + offset, end_line=22 + offset,
                          type="(value: number) => void", exported=True,
                          params=["value"]),
            ],
        ))

    report = diff(network(0), network(1))

    assert report.verdict == "clean"
    assert report.added_vertices == []
    assert report.removed_vertices == []
    assert report.removed_public_api == []
