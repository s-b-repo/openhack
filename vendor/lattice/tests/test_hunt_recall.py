"""RECALL tests for the Wave-4 structural-detector tightening.

Companion to tests/test_hunt_precision.py. Each Wave-4 change closes a specific
recall gap; every gap gets a FIRES test (asserts the previously-missed case now
gets a finding) and a SILENT test (asserts a nearby non-vulnerable idiom still
stays quiet — the precision floor is not compromised).

Structure mirrors test_hunt_precision.py's helpers: build a minimal
Hypernetwork by hand and invoke `hunt()` on it, so every case is fully-
controlled and reproducible.
"""
from lattice.graph.models import Hypernetwork, Vertex, Hyperedge, Surface
from lattice.hunt import hunt


def _hn(vertices, edges, surfaces=()):
    return Hypernetwork(language="test", root=".",
                        vertices=list(vertices),
                        hyperedges=list(edges),
                        surfaces=list(surfaces))


def _v(vid, kind="function", *, exported=False, stub=False, file="src/a.ts",
       name=None, start_line=1, end_line=1):
    return Vertex(id=vid, kind=kind, name=name or vid.split("#")[-1],
                  file=file, start_line=start_line, end_line=end_line,
                  exported=exported, stub=stub)


_EDGE_COUNTER = [0]


def _e(kind, a, b, resolved=True):
    _EDGE_COUNTER[0] += 1
    return Hyperedge(id=f"edge#{_EDGE_COUNTER[0]}", kind=kind,
                     members=[a, b], resolved=resolved)


# ─── called_stub via dispatch — recall ───────────────────────────────────────

def test_called_stub_via_dispatch_FIRES():
    """A stub reached only via `dispatch` (polymorphic call) previously showed fan_in==0
    on the default `references` kinds and got demoted to dead_code — losing the
    higher-severity 'called_stub' classification. With INBOUND_FLOW_KINDS in fan_in,
    the dispatch edge counts and the stub is reported at HIGH."""
    net = _hn(
        [_v("caller"), _v("stub", stub=True)],
        [_e("dispatch", "caller", "stub")],
    )
    bugs = hunt(net)
    kinds = [b.kind for b in bugs]
    assert "called_stub" in kinds, f"dispatch-only stub not classified as called_stub: {kinds}"


def test_called_stub_via_links_FIRES():
    """A stub reached via a cross-graph `links` join (polyglot codebase) is also
    reached — INBOUND_FLOW_KINDS includes `links`."""
    net = _hn(
        [_v("caller"), _v("stub", stub=True)],
        [_e("links", "caller", "stub")],
    )
    bugs = hunt(net)
    assert any(b.kind == "called_stub" for b in bugs)


def test_called_stub_via_only_type_reference_SILENT():
    """A stub referenced ONLY as a type (no runtime call) is NOT called at runtime —
    fan_in over INBOUND_FLOW_KINDS should be 0, so it drops to dead_code, not
    called_stub."""
    net = _hn(
        [_v("caller"), _v("stub", stub=True)],
        [_e("type_reference", "caller", "stub")],
    )
    bugs = hunt(net)
    stub_bugs = [b for b in bugs if b.symbol == "stub"]
    assert not any(b.kind == "called_stub" for b in stub_bugs), \
        f"type-only reference must not upgrade stub to called_stub: {stub_bugs}"


# ─── broken_reference — precision (type-only filter) ─────────────────────────

def test_broken_type_only_reference_SILENT():
    """A broken `type_reference` (a dangling TypeScript type import) is a compile-time
    noise — do not add it to the high-severity broken_reference list where it would
    drown genuine call-graph breaks. The Wave-4 filter suppresses it."""
    net = _hn(
        [_v("caller"), _v("nonexistent")],
        [_e("type_reference", "caller", "nonexistent", resolved=False)],
    )
    bugs = hunt(net)
    assert not any(b.kind == "broken_reference" for b in bugs), \
        "type_reference dangler must not be reported as broken_reference"


def test_broken_call_reference_still_FIRES():
    """A broken CALL reference is a real bug — the precision floor must not push
    genuine broken calls into silence."""
    net = _hn(
        [_v("caller"), _v("nonexistent")],
        [_e("references", "caller", "nonexistent", resolved=False)],
    )
    bugs = hunt(net)
    assert any(b.kind == "broken_reference" for b in bugs)


def test_broken_reference_evidence_includes_origin_edge_kind():
    """Wave-4 evidence dict change: reviewers need `origin_edge_kind` to triage a broken
    ref by whether it's a call, inheritance, or import."""
    net = _hn(
        [_v("caller"), _v("nonexistent")],
        [_e("references", "caller", "nonexistent", resolved=False)],
    )
    for b in hunt(net):
        if b.kind == "broken_reference":
            assert "origin_edge_kind" in b.evidence, b.evidence
            assert b.evidence["origin_edge_kind"] == "references"
            return
    raise AssertionError("no broken_reference emitted")


# ─── logic paradox — literal-atom recall ─────────────────────────────────────

def test_if_false_is_contradiction_FIRES():
    from lattice.logic.audit import audit_condition
    f = audit_condition("false")
    assert f is not None, "`if (false)` must be a contradiction"
    assert f["kind"] == "contradiction"


def test_if_true_is_tautology_FIRES():
    from lattice.logic.audit import audit_condition
    f = audit_condition("true")
    assert f is not None, "`if (true)` must be a tautology"
    assert f["kind"] == "tautology"


def test_if_zero_is_contradiction_FIRES():
    from lattice.logic.audit import audit_condition
    f = audit_condition("0")
    assert f is not None and f["kind"] == "contradiction"


def test_if_null_is_contradiction_FIRES():
    from lattice.logic.audit import audit_condition
    for lit in ("null", "undefined", "None"):
        f = audit_condition(lit)
        assert f is not None and f["kind"] == "contradiction", lit


def test_not_true_is_contradiction_FIRES():
    from lattice.logic.audit import audit_condition
    f = audit_condition("!true")
    assert f is not None and f["kind"] == "contradiction"


def test_not_false_is_tautology_FIRES():
    from lattice.logic.audit import audit_condition
    f = audit_condition("!false")
    assert f is not None and f["kind"] == "tautology"


def test_variable_named_false_is_still_opaque_atom_SILENT():
    """A variable named `false` (which SHOULDN'T exist but might in obfuscated code)
    would be identical in string form to the literal. Documented as a known
    limitation: we treat it as a contradiction — the FIRE=lead / SILENCE≠proof
    principle applies (better to fire on a benign shadowing than silently miss
    every real `if (false)`)."""
    # This test asserts the current (aggressive) behavior — if we ever want to
    # exempt shadowing, that's a language-specific decision made in the ingest.
    from lattice.logic.audit import audit_condition
    f = audit_condition("false")
    assert f is not None                    # asserts the aggressive rule holds


def test_contingent_expression_still_SILENT():
    from lattice.logic.audit import audit_condition
    assert audit_condition("a && b") is None
    assert audit_condition("x > 5") is None
    assert audit_condition("isReady(u) || retry") is None


def test_true_and_contingent_reduces_to_contingent_SILENT():
    from lattice.logic.audit import audit_condition
    # `true && x` is neither a tautology nor a contradiction — it depends on x.
    assert audit_condition("true && x") is None


def test_false_or_contingent_reduces_to_contingent_SILENT():
    from lattice.logic.audit import audit_condition
    assert audit_condition("false || x") is None


def test_true_or_contingent_is_tautology_FIRES():
    from lattice.logic.audit import audit_condition
    # `true || x` is always true regardless of x — tautology.
    f = audit_condition("true || x")
    assert f is not None and f["kind"] == "tautology"


def test_false_and_contingent_is_contradiction_FIRES():
    from lattice.logic.audit import audit_condition
    # `false && x` is always false — contradiction.
    f = audit_condition("false && x")
    assert f is not None and f["kind"] == "contradiction"
