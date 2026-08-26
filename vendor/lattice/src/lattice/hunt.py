# src/lattice/hunt.py
"""Bug hunter — prioritized structural bug detection.

Footings finds *structural* bugs (not logic/runtime), and its edge is composing
signals into patterns no single diagnostic shows. The highest-signal one:
a stub reachable from a public API = a user-facing path into unimplemented code.

Detectors are composable and each emits ranked Bug findings (critical -> low):
  public_path_to_stub  CRITICAL  exported path leads to an unimplemented stub
  obstruction          HIGH      broken edge inside a dependency cycle (RRT H1)
  called_stub          HIGH      an unimplemented stub is referenced by callers
  broken_reference     HIGH      an unresolved reference to an internal symbol
  dead_code            LOW       defined but unreachable from any public API
"""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView
from lattice.obstruction.witness import extract_witnesses

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Test code (mocks, fixtures) and runtime-invoked callbacks are "uncalled by name"
# but are NOT dead — they're called by a test framework or a runtime. Excluding them
# is what keeps dead-code / stub findings from drowning in false positives.
_TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec)/|\.(test|spec)\.[jt]sx?$|\.(test|spec)\.")

# Edge kinds that mean control/data FLOWS INTO a symbol — i.e. it's reached. A method
# reached only via polymorphic dispatch or a cross-graph join is reached, not dead;
# counting just "references" here would re-introduce the FPs dispatch/link edges fix.
INBOUND_FLOW_KINDS = ("references", "dispatch", "links")
# A type is also "used" if it's extended/implemented, not only called.
_TYPE_USE_KINDS = INBOUND_FLOW_KINDS + ("inherits", "implements")

# Functions invoked by a runtime/framework, never referenced by name: DOM/Node event
# handlers and common bundler (Vite/Rollup) plugin hooks.
_RUNTIME_CALLBACKS = {
    "onmessage", "onerror", "onclose", "onopen", "onconnect", "ondata", "onend",
    "ondrain", "ontimeout", "onabort", "onload", "onclick", "onchange", "onsubmit",
    "configureserver", "load", "resolveid", "transform", "transformindexhtml",
    "buildstart", "buildend", "handlehotupdate", "generatebundle", "renderchunk",
    "closebundle", "options", "outputoptions", "resolvedynamicimport", "moduleparsed",
    "config", "configresolved",
}

# Node streams runtime-invoked methods: implementing a Readable/Writable/Transform means
# defining these, which the stream machinery calls — never referenced by name. Distinctive
# (underscore + known names), so safe to exclude without over-suppressing (unlike bare Proxy
# trap names get/set/apply, which need structural detection — a separate follow-up).
_RUNTIME_METHODS = {
    "_read", "_write", "_writev", "_final", "_destroy", "_construct",
    "_transform", "_flush",
}


_MOCK = re.compile(r"(?i)^(mock|fake|stub|dummy)")


def _is_test(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


def _is_mock(vid: str, path: str) -> bool:
    """A symbol in a mock/fake/stub/dummy file or class — its empty methods are
    intentional doubles, not unimplemented bugs."""
    base = path.rsplit("/", 1)[-1]
    container = vid.split("#")[-1].split(".")[0] if "#" in vid else ""
    return "__mocks__" in path or bool(_MOCK.match(base)) or bool(_MOCK.match(container))


def _is_runtime_callback(name: str) -> bool:
    low = name.lower()
    return (low in _RUNTIME_CALLBACKS or low in _RUNTIME_METHODS
            or bool(re.match(r"on[A-Z]", name)))


@dataclass
class Bug:
    kind: str
    severity: str
    symbol: str
    detail: str
    evidence: dict

    def to_dict(self) -> dict:
        return asdict(self)


def hunt(net: Hypernetwork) -> list[Bug]:
    g = GraphView(net)
    vmap = {v.id: v for v in net.vertices}
    external = {v.id for v in net.vertices if v.kind == "external"}
    bugs: list[Bug] = []

    # --- reachability from the legitimate ways in ---
    roots = [s.vertex_id for s in net.surfaces if s.kind in ("public_api", "entrypoint")]
    # public_api surfaces now cover public methods of exported classes too (builder
    # Pass 4) — the graph's notion of "externally reachable". A symbol so backed is not
    # dead even with zero in-repo callers (its callers are external consumers).
    public_api_ids = {s.vertex_id for s in net.surfaces if s.kind == "public_api"}
    reach_by_root = {r: g.reachable_from(r) for r in roots}   # one BFS per root, reused below
    public_reach: set[str] = set(roots)
    for r in roots:
        public_reach |= reach_by_root[r]

    stubs = {v.id for v in net.vertices if v.stub}

    # CRITICAL: a stub on a user-facing path
    public_stubs = stubs & public_reach
    for sid in sorted(public_stubs):
        bugs.append(Bug("public_path_to_stub", "critical", sid,
                        "reachable from a public API but unimplemented (user-facing dead end)",
                        {"reachable_from": [r for r in roots if sid in reach_by_root[r] or sid == r]}))

    # HIGH: a stub that's called but not on a public path (subsumed by the above).
    # Skip test files — an empty mock method ("connect() {}") is intentional, not a bug.
    # Use INBOUND_FLOW_KINDS explicitly (same set the dead-code check at line 142 uses):
    # otherwise a stub reached ONLY via dispatch or a cross-graph link is misclassified as
    # dead code below and gets no called_stub finding (a stub-precision regression). Keeping
    # the two fan-in calls symmetric is what preserves the FIRE=lead / SILENCE≠proof rule
    # across BOTH tables.
    for sid in sorted(stubs - public_stubs):
        v = vmap.get(sid)
        if v is not None and (_is_test(v.file) or _is_mock(sid, v.file)):
            continue
        fi = g.fan_in(sid, kinds=INBOUND_FLOW_KINDS)
        if fi > 0:
            bugs.append(Bug("called_stub", "high", sid,
                            f"unimplemented function is referenced by {fi} caller(s)",
                            {"fan_in": fi}))

    # HIGH: obstructions (broken edge in a cycle) — RRT H1 witnesses
    witness_edges: set[frozenset] = set()
    for w in extract_witnesses(net):
        witness_edges.add(frozenset(w.broken_edge))
        bugs.append(Bug("obstruction", "high", str(w.broken_edge),
                        f"broken reference inside a dependency cycle {w.cycle}",
                        {"cycle": w.cycle, "energy": w.energy}))

    # HIGH: bare broken references not already explained by an obstruction. Skip
    # type-only edges (`type_reference`, `imports_type`) — a broken TypeScript type import
    # is a compile-time noise, not a runtime bug; folding it in floods higher-severity
    # findings. `origin_edge_kind` is echoed into evidence for triage so a reviewer can
    # spot at a glance whether this is a call reference or a class inheritance dangler.
    _TYPE_ONLY_KINDS = {"type_reference", "imports_type", "type_alias"}
    for e in net.hyperedges:
        if e.resolved or len(e.members) < 2:
            continue
        if e.kind in _TYPE_ONLY_KINDS:
            continue
        a, b = e.members[0], e.members[-1]
        if a == b or a in external or b in external:
            continue
        if frozenset((a, b)) in witness_edges:
            continue
        bugs.append(Bug("broken_reference", "high", f"({a}, {b})",
                        "unresolved reference to an internal symbol",
                        {"edge": [a, b], "edge_kind": e.kind, "origin_edge_kind": e.kind}))

    # LOW: dead code — a NON-EXPORTED function with zero inbound references is
    # genuinely uncalled. ("Zero callers" is the precise, low-false-positive rule;
    # reachability-from-public-API over-reports via entry points / `this.` chains.)
    dead = [v for v in net.vertices
            if v.kind in ("function", "method") and not v.exported and not v.stub
            and v.id not in public_api_ids
            and v.id not in public_stubs
            and not _is_test(v.file) and not _is_runtime_callback(v.name)
            and g.fan_in(v.id, kinds=INBOUND_FLOW_KINDS) == 0]

    # Aggregate: dead methods of an UNREFERENCED class are one "dead class", not N
    # method findings (an unused class shouldn't flood the report with its members).
    folded: set[str] = set()
    by_class: dict[str, list] = {}
    for v in dead:
        qual = v.id.split("#")[-1]
        if v.kind == "method" and "." in qual:
            by_class.setdefault(v.id.rsplit(".", 1)[0], []).append(v)
    for cvid, methods in by_class.items():
        cls = vmap.get(cvid)
        if cls is not None and cls.kind == "class" and g.fan_in(cvid, kinds=_TYPE_USE_KINDS) == 0:
            bugs.append(Bug("dead_class", "low", cvid,
                            f"class with no references and {len(methods)} unused method(s) "
                            f"(likely dead)", {"methods": [m.id for m in methods]}))
            folded.update(m.id for m in methods)

    for v in dead:
        if v.id not in folded:
            bugs.append(Bug("dead_code", "low", v.id,
                            "non-exported function with no callers (likely dead)", {}))

    bugs.sort(key=lambda b: (_SEV[b.severity], b.symbol))
    return bugs
