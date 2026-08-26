# src/lattice/compose.py
"""Graph-of-graphs composition — joining a host graph to its dependencies' graphs.

A path that hands off to a library is a trace loss only because the other side is dark.
If the library has its OWN graph, the boundary becomes a JOIN: the host's outbound
endpoint (a call into the library) links to the library's inbound entrypoint (the
exported symbol it calls), and the path continues THROUGH the library to its real
endpoints. Reachability and taint then walk across the join like any other edge — so a
composed path (untrusted host input -> library entrypoint -> library's internal sink)
becomes followable, though neither graph reveals it alone.

The join schema is the inbound/outbound duality: what's accessible to the library on the
host side (exposure.py) maps onto what the library's entrypoint asks for. Libraries are
referenced by name, their graphs merged once under an `@module:` namespace — the
"addressable, write once, reference" principle at ecosystem scale.
"""
from __future__ import annotations
from dataclasses import dataclass, field, replace

from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.exposure import library_exposure


@dataclass
class BrokenLink:
    host_caller: str        # the host function whose call fails to join
    library: str            # the dependency module
    callee: str             # the symbol the host calls
    reason: str             # "no_such_export"  (arity_mismatch: future, needs param capture)
    location: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {"host_caller": self.host_caller, "library": self.library,
                "callee": self.callee, "reason": self.reason,
                "location": self.location, "detail": self.detail}


def broken_links(host: Hypernetwork, source_root, libraries: dict) -> list[BrokenLink]:
    """Verify the join contract: a host call into a library that HAS a graph but exports
    no such symbol is a broken link — symbol-level version skew a module-level import
    check can't see (entrypoint renamed/removed). Existence is checked against ALL exported
    names (any kind), so a function-valued const export doesn't false-flag. A library with
    no graph is an honest trace loss, not a break."""
    exports = {mod: {v.name: v for v in net.vertices if v.exported}
               for mod, net in libraries.items()}
    out: list[BrokenLink] = []
    seen: set = set()
    for h in library_exposure(host, source_root):
        if h.library not in libraries:
            continue                                  # no graph -> trace loss, not a break
        callee = h.callee.split(".")[-1]
        entry = exports[h.library].get(callee)
        key = (h.enclosing, h.library, callee)
        if key in seen:
            continue
        seen.add(key)
        if entry is None:
            out.append(BrokenLink(
                host_caller=h.enclosing, library=h.library, callee=callee,
                reason="no_such_export", location=h.location,
                detail=f"calls {h.library}.{callee}, but {h.library}'s graph exports no such "
                       f"symbol (renamed/removed — version skew?)"))
            continue
        # arity shape-check — only when the entry's params are captured AND non-variadic.
        # Flag the certain case: host passes MORE args than the entry accepts. (Under-
        # flags 0-param and missing-required cases to stay precise — a false break would
        # hide a real one, same bias as gates.)
        params = getattr(entry, "params", None) or []
        if params and not any(p.startswith("...") for p in params):
            if len(h.accessible) > len(params):
                out.append(BrokenLink(
                    host_caller=h.enclosing, library=h.library, callee=callee,
                    reason="arity_mismatch", location=h.location,
                    detail=f"passes {len(h.accessible)} arg(s) to {h.library}.{callee}(), "
                           f"which accepts {len(params)} ({', '.join(params)}) — signature "
                           f"changed (version skew?)"))
    return out


def _namespace(net: Hypernetwork, module: str):
    """Return (vertices, edges, surfaces, exported_by_name) for a library graph with all
    ids prefixed `@module:` so they can't collide with the host or other libraries."""
    pre = f"@{module}:"

    def nid(vid: str) -> str:
        return pre + vid

    vertices = [replace(v, id=nid(v.id)) for v in net.vertices]
    edges = [replace(e, id=nid(e.id), members=[nid(m) for m in e.members])
             for e in net.hyperedges]
    surfaces = [replace(s, id=nid(s.id), vertex_id=nid(s.vertex_id)) for s in net.surfaces]
    exported = {v.name: nid(v.id) for v in net.vertices
                if v.exported and v.kind in ("function", "method")}
    return vertices, edges, surfaces, exported


def link(host: Hypernetwork, source_root, libraries: dict) -> Hypernetwork:
    """Compose `host` with the graphs of its dependencies. `libraries` maps a module name
    to its Hypernetwork. For each host handoff into a module that has a graph, emit a
    `links` join edge host-caller -> library-entrypoint, and merge the library's graph
    (namespaced) so reachability/taint continue through it. Modules with no graph stay an
    honest trace loss (no join)."""
    vertices = list(host.vertices)
    edges = list(host.hyperedges)
    surfaces = list(host.surfaces)
    diagnostics = list(host.diagnostics)

    merged: dict[str, dict] = {}     # module -> {exported_name: namespaced_entry_id}

    def ensure_merged(module: str) -> dict:
        if module not in merged:
            vs, es, ss, exported = _namespace(libraries[module], module)
            vertices.extend(vs)
            edges.extend(es)
            surfaces.extend(ss)
            diagnostics.extend(libraries[module].diagnostics)
            merged[module] = exported
        return merged[module]

    jid = 0
    seen_joins: set = set()
    for h in library_exposure(host, source_root):
        if h.library not in libraries:
            continue                                  # no graph -> stays a trace loss
        callee = h.callee.split(".")[-1]              # `ns.foo` -> `foo`
        entry_id = ensure_merged(h.library).get(callee)
        if entry_id is None:
            continue                                  # lib has a graph but not this export
        key = (h.enclosing, entry_id)
        if key in seen_joins:
            continue
        seen_joins.add(key)
        edges.append(Hyperedge(id=f"join{jid}", kind="links",
                               members=[h.enclosing, entry_id], directed=True, resolved=True))
        jid += 1

    return Hypernetwork(language=host.language, root=host.root,
                        vertices=vertices, hyperedges=edges, surfaces=surfaces,
                        diagnostics=diagnostics)
