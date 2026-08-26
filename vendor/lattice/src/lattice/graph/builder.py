# src/lattice/graph/builder.py
from __future__ import annotations
import hashlib
from lattice.ingest.types import RawIngest, RawSymbol
from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork

_LANG_PREFIX = {"typescript": "ts", "javascript": "js", "python": "py",
                "go": "go", "rust": "rs", "ruby": "rb"}

# Fan-out cap for the shared name-resolution pass: a callee name matching more than this
# many definitions is too ambiguous to be a useful lead (e.g. `to_dict` on every dataclass)
# — emitting N low-confidence dispatch edges there is noise, not recall, and balloons
# impact blast radius. Above the cap we stay silent (SILENCE != proof). A unique
# (single-candidate) name-match is always emitted; this only gates multi-candidate dispatch.
_MAX_NAME_DISPATCH = 4

# Dynamic dispatch (`obj[key]()`) genuinely reaches ALL of a container's members — a real
# dispatch table, not name-match ambiguity — so it gets a far more generous fan-out cap
# (only pathological mega-objects are skipped) and a flat confidence (all members are true
# targets; we just can't say which call hits which), not the 1/N ambiguity penalty.
_MAX_DYN_DISPATCH = 64
_DYN_DISPATCH_CONFIDENCE = 0.5

def _qualified(sym: RawSymbol) -> str:
    container = sym.container.replace("::", ".") if sym.container else ""
    return f"{container}.{sym.name}" if container else sym.name

# Symbol significance supplies deterministic ordering when distinct definitions collide.
# Every distinct definition is retained below; higher-rank symbols merely sort first.
_KIND_RANK = {"class": 4, "interface": 4, "function": 3, "method": 3,
              "type": 2, "variable": 1, "module": 0, "external": 0}

def _vid(prefix: str, file: str, qualified: str) -> str:
    return f"{prefix}-sym:{file}#{qualified}"


def _symbol_identity_key(s: RawSymbol) -> tuple:
    """Location-independent identity material for otherwise-colliding definitions."""
    return (
        s.kind,
        s.type or "",
        bool(s.exported),
        bool(s.is_stub),
        tuple(getattr(s, "params", []) or []),
        tuple(getattr(s, "extends", []) or []),
        tuple(getattr(s, "implements", []) or []),
    )


def _collision_token(s: RawSymbol) -> str:
    material = repr(_symbol_identity_key(s)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:12]

def build(raw: RawIngest) -> Hypernetwork:
    prefix = _LANG_PREFIX.get(raw.language, raw.language[:2])
    vertices: dict[str, Vertex] = {}
    symbol_vertex_ids: dict[int, str] = {}

    # --- Pass 1: create per-symbol vertices.  A lossy frontend can emit two real
    # definitions with the same file/name/container identity (overloads, or a nested
    # namespace it failed to preserve).  Collapsing those to one vertex manufactures
    # false uniqueness for Pass 3.  Keep every distinct emission, suffixing *all*
    # colliders deterministically; byte-for-byte-equivalent duplicate emissions still
    # dedupe to one vertex.
    grouped: dict[str, list[RawSymbol]] = {}
    for s in raw.symbols:
        grouped.setdefault(_vid(prefix, s.file, _qualified(s)), []).append(s)

    def _symbol_sort_key(s: RawSymbol) -> tuple:
        # Semantic material comes first so inserting comments cannot renumber overloads.
        # Location only breaks ties between definitions that are otherwise indistinguishable.
        return (_symbol_identity_key(s), s.start_line, s.end_line,
                -_KIND_RANK.get(s.kind, 0))

    for base_id, emitted in grouped.items():
        unique: list[RawSymbol] = []
        emission_index: dict[int, int] = {}
        for s in emitted:
            try:
                index = unique.index(s)
            except ValueError:
                unique.append(s)
                index = len(unique) - 1
            emission_index[id(s)] = index

        order = sorted(range(len(unique)), key=lambda i: _symbol_sort_key(unique[i]))
        token_counts: dict[str, int] = {}
        for s in unique:
            token = _collision_token(s)
            token_counts[token] = token_counts.get(token, 0) + 1
        token_seen: dict[str, int] = {}
        ids: dict[int, str] = {}
        for unique_i in order:
            s = unique[unique_i]
            if len(unique) == 1:
                vid = base_id
            else:
                token = _collision_token(s)
                token_seen[token] = token_seen.get(token, 0) + 1
                tie = (f"-{token_seen[token]}" if token_counts[token] > 1 else "")
                vid = f"{base_id}@S{token}{tie}"
            ids[unique_i] = vid
            vertices[vid] = Vertex(
                id=vid, kind=s.kind, name=s.name, file=s.file,
                start_line=s.start_line, end_line=s.end_line,
                type=s.type, exported=s.exported, stub=s.is_stub,
                params=getattr(s, "params", []) or [],
            )
        for s in emitted:
            symbol_vertex_ids[id(s)] = ids[emission_index[id(s)]]

    # --- Build position index from symbol vertices ONLY (before module vertices) ---
    by_file: dict[str, list[tuple[int, int, str]]] = {}
    for v in vertices.values():
        by_file.setdefault(v.file, []).append((v.start_line, v.end_line, v.id))
    for lst in by_file.values():
        lst.sort(key=lambda t: (t[1] - t[0]))

    # Predeclared so enclosing() closes over a name that already exists — Pass 2
    # fills it before Pass 3 makes the first enclosing() call.
    file_module: dict[str, str] = {}

    def enclosing(file: str | None, line: int | None,
                  *, module_fallback: bool = True) -> str | None:
        if file is None or line is None:
            return None
        matches = [(start, end, vid) for start, end, vid in by_file.get(file, [])
                   if start <= line <= end]
        if matches:
            width = min(end - start for start, end, _ in matches)
            narrowest = [vid for start, end, vid in matches if end - start == width]
            # Identical spans cannot prove which overload/collided symbol is meant.
            # Leave them unresolved so name matching remains calibrated ambiguity.
            if len(narrowest) == 1:
                return narrowest[0]
            return None
        # A call site inside no symbol is module-level code (e.g. `main()` at the
        # bottom of a CLI file) — attribute it to the module, so top-level-invoked
        # functions aren't seen as uncalled.
        return file_module.get(file) if module_fallback else None

    # --- Pass 2: synthesize ONE module vertex per distinct ingested file ---
    # file_module maps file -> module vertex id
    # Covers BOTH files-with-symbols AND all files listed in raw.files (I1 fix).
    files_with_symbols: dict[str, list[Vertex]] = {}
    for v in list(vertices.values()):
        files_with_symbols.setdefault(v.file, []).append(v)

    # All ingested file paths: union of files that have symbols + raw.files
    all_ingested_files: set[str] = set(files_with_symbols.keys()) | set(raw.files)

    for file in all_ingested_files:
        sym_verts = files_with_symbols.get(file)
        max_end = max(v.end_line for v in sym_verts) if sym_verts else 1
        mod_id = f"{prefix}-sym:{file}#<module>"
        file_module[file] = mod_id
        vertices[mod_id] = Vertex(
            id=mod_id,
            kind="module",
            name=file,
            file=file,
            start_line=1,
            end_line=max_end,
            exported=True,
            type=None,
            stub=False,
        )

    # --- Pass 3: build hyperedges ---
    hyperedges: list[Hyperedge] = []
    surfaces: list[Surface] = []
    ext_seen: set[str] = set()
    eid = 0

    # Name index for the shared, language-agnostic name-resolution pass: bare name ->
    # function/method vertex ids. Lets the calls/references branch recover edges a
    # frontend left unresolved (a known callee name with no located target) and augment
    # ambiguous same-name calls with dispatch edges to the siblings a first-match
    # resolver would drop. Modules/externals are excluded (externals don't exist yet).
    name_index: dict[str, list[str]] = {}
    for v in vertices.values():
        if v.kind in ("function", "method"):
            name_index.setdefault(v.name, []).append(v.id)

    for r in raw.references:
        eid += 1

        if r.kind == "dyn_dispatch":
            continue            # dynamic dispatch -> Pass 9 (needs the containment map)
        if r.kind == "imports":
            # Module-to-module import resolution
            src = file_module.get(r.from_file)
            if src is None:
                # importing file has no symbols -> no module vertex -> skip
                continue
            if r.to_file is None:
                # External package import (e.g. "import x from 'lodash'") -> external placeholder.
                # Gate ignores these: target is in external_ids, targets_external=True.
                key = r.name or "unknown"
                tgt = _vid(prefix, "<external>", key)
                if tgt not in ext_seen:
                    ext_seen.add(tgt)
                    vertices[tgt] = Vertex(id=tgt, kind="external", name=key,
                                           file="<external>", start_line=0, end_line=0)
                surfaces.append(Surface(id=f"surf-ext-{eid}", vertex_id=src,
                                        kind="external_call"))
                resolved = False
            else:
                tgt_mod = file_module.get(r.to_file)
                if tgt_mod is not None:
                    # Resolved relative import -> both files have symbols
                    tgt = tgt_mod
                    resolved = True
                else:
                    # Relative import to a file with no module vertex (un-ingested / missing).
                    # BROKEN internal import: target NOT added to vertices, NOT in external_ids.
                    # Gate sees a missing, non-external member -> flags unresolved_imports -> fail.
                    tgt = _vid(prefix, r.to_file, "<module>")
                    resolved = False
            hyperedges.append(Hyperedge(id=f"e{eid}", kind=r.kind,
                                        members=[src, tgt], directed=True, resolved=resolved))
        else:
            # calls / references: location-based resolution first, then the shared
            # name-resolution pass. PURELY ADDITIVE — a location-resolved edge is always
            # kept; name-match only ADDS edges (recovered or sibling-dispatch). Name-match
            # edges are honest leads: provenance="name-match", confidence < 1.0. Refs with
            # no callee name (every frontend until it opts in) take the identical old path.
            src = enclosing(r.from_file, r.from_line)
            if src is None:
                continue
            tgt = enclosing(r.to_file, r.to_line, module_fallback=False)

            # same-named function/method defs, minus self and the located target
            candidates = ([vid for vid in name_index.get(r.name, [])
                           if vid != src and vid != tgt]
                          if r.name and r.allow_name_match else [])
            # Multi-candidate DISPATCH is method-only: free functions sharing a name across
            # modules are namespacing coincidences, not polymorphism. (A unique match still
            # recovers regardless of kind.)
            method_cands = [c for c in candidates if vertices[c].kind == "method"]

            if tgt is not None:
                # frontend resolved by location -> keep the fact-grade edge as-is
                hyperedges.append(Hyperedge(id=f"e{eid}", kind=r.kind,
                                            members=[src, tgt], directed=True,
                                            resolved=r.resolved))
                # augment: ambiguous same-name method siblings a first-match resolver
                # dropped (skip ubiquitous names above the fan-out cap)
                if 0 < len(method_cands) <= _MAX_NAME_DISPATCH:
                    n = len(method_cands) + 1
                    for i, cid in enumerate(method_cands):
                        hyperedges.append(Hyperedge(
                            id=f"e{eid}-d{i}", kind="dispatch", members=[src, cid],
                            directed=True, resolved=True, confidence=1.0 / n,
                            provenance="name-match"))
            elif r.to_file is None and len(candidates) == 1:
                # unresolved by location, unambiguous callee name -> recover the edge
                hyperedges.append(Hyperedge(
                    id=f"e{eid}", kind="references", members=[src, candidates[0]],
                    directed=True, resolved=True, confidence=0.9, provenance="name-match"))
            elif r.to_file is None and 1 < len(method_cands) <= _MAX_NAME_DISPATCH:
                # unresolved + ambiguous methods within the cap -> dispatch to all
                n = len(method_cands)
                for i, cid in enumerate(method_cands):
                    hyperedges.append(Hyperedge(
                        id=f"e{eid}-d{i}", kind="dispatch", members=[src, cid],
                        directed=True, resolved=True, confidence=1.0 / n,
                        provenance="name-match"))
            else:
                # A frontend can retain an intended in-project file for an unresolved
                # internal call (for example ambiguous `super.foo()` in Solidity).
                # Keep it dangling/failing without falsely turning it into an outbound
                # dependency. Calls with no intended file remain external unknowns.
                if r.to_file is not None:
                    key = r.name or "unknown"
                    tgt = _vid(prefix, r.to_file, f"<unresolved:{key}>")
                else:
                    key = r.name or "unknown"
                    tgt = _vid(prefix, "<external>", key)
                    if tgt not in ext_seen:
                        ext_seen.add(tgt)
                        vertices[tgt] = Vertex(id=tgt, kind="external", name=key,
                                               file="<external>", start_line=0, end_line=0)
                    surfaces.append(Surface(id=f"surf-ext-{eid}", vertex_id=src,
                                            kind="external_call"))
                hyperedges.append(Hyperedge(id=f"e{eid}", kind=r.kind,
                                            members=[src, tgt], directed=True, resolved=False))

    # --- Pass 4: public_api surfaces — for exported function/method, NOT module.
    # A TS class method never individually carries `export`; only the enclosing class
    # does. A PUBLIC method of an exported class/interface is still public API (external
    # callers reach it), so it gets a surface too — but NOT `_`/`#`-prefixed members
    # (internal-by-convention / ES-hard-private), which stay eligible as dead-code leads. ---
    type_symbols = [s for s in raw.symbols if s.kind in ("class", "interface")]
    method_owner: dict[str, str] = {}
    for symbol in raw.symbols:
        if symbol.kind != "method" or not symbol.container:
            continue
        candidates = [owner for owner in type_symbols
                      if owner.file == symbol.file
                      and _qualified(owner) == symbol.container.replace("::", ".")]
        containing = [owner for owner in candidates
                      if owner.start_line <= symbol.start_line <= symbol.end_line <= owner.end_line]
        if containing:
            width = min(owner.end_line - owner.start_line for owner in containing)
            candidates = [owner for owner in containing
                          if owner.end_line - owner.start_line == width]
        if len(candidates) == 1:
            method_owner[symbol_vertex_ids[id(symbol)]] = symbol_vertex_ids[id(candidates[0])]

    def _public_method_of_exported_type(v: Vertex) -> bool:
        if v.kind != "method" or v.name[:1] in ("_", "#"):
            return False
        enclosing = vertices.get(method_owner.get(v.id, ""))
        return (enclosing is not None
                and enclosing.kind in ("class", "interface")
                and enclosing.exported)

    si = 0
    for v in vertices.values():
        if (v.kind in ("function", "method") and v.exported) \
                or _public_method_of_exported_type(v):
            surfaces.append(Surface(id=f"surf-api-{si}", vertex_id=v.id, kind="public_api"))
            si += 1

    # --- Pass 5: entrypoint surfaces — the module vertex of each program entry
    # (shebang script / package.json bin/main). These root reachability at the real
    # program start, so sinks reached from main() — not just from exported API — are
    # correctly proven reachable instead of mislabeled unverified. ---
    for ei, file in enumerate(sorted(raw.entry_files)):
        mod_id = file_module.get(file)
        if mod_id is not None:
            surfaces.append(Surface(id=f"surf-entry-{ei}", vertex_id=mod_id, kind="entrypoint"))
            # Native frontends flag the containing file/package as the entry surface.
            # Connect that root to an actual `main` symbol when present so reachability
            # does not stop at the otherwise-isolated module vertex.
            mains = sorted({
                symbol_vertex_ids[id(symbol)] for symbol in raw.symbols
                if symbol.file == file and symbol.kind == "function"
                and symbol.name == "main" and symbol.container is None
            })
            for mi, main_id in enumerate(mains):
                hyperedges.append(Hyperedge(
                    id=f"entry{ei}-{mi}", kind="calls",
                    members=[mod_id, main_id], directed=True, resolved=True,
                    provenance="entrypoint",
                ))

    # --- Pass 6: inheritance edges — `class C extends Base implements I` becomes
    # inherits/implements edges C->Base, C->I, resolved by type NAME to a class/interface
    # vertex. A whole relationship the graph was missing: a base type's blast radius now
    # reaches its subtypes, and dispatch fan-out has a foundation. Supertypes with no
    # local vertex (library base classes) are skipped — an honest non-edge. ---
    by_name: dict[str, list[str]] = {}
    by_qualified_name: dict[str, list[str]] = {}
    for v in vertices.values():
        if v.kind in ("class", "interface"):
            by_name.setdefault(v.name, []).append(v.id)
            qualified = v.id.split("#", 1)[-1].split("@S", 1)[0]
            by_qualified_name.setdefault(qualified, []).append(v.id)
    iei = 0
    for s in raw.symbols:
        if s.kind not in ("class", "interface"):
            continue
        src = symbol_vertex_ids[id(s)]
        for kind, names in (("inherits", getattr(s, "extends", []) or []),
                            ("implements", getattr(s, "implements", []) or [])):
            for tname in names:
                qualified = tname.replace("::", ".")
                candidates = by_qualified_name.get(qualified, []) or by_name.get(tname, [])
                tgt = candidates[0] if len(candidates) == 1 else None
                if tgt is not None and tgt != src:
                    hyperedges.append(Hyperedge(id=f"sup{iei}", kind=kind,
                                                members=[src, tgt], directed=True, resolved=True))
                    iei += 1

    # --- Pass 7: dispatch fan-out — a call landing on a supertype method should reach
    # EVERY subtype's override of it (one call, many endpoints). Built on Pass 6's
    # inherits/implements edges (the subtype is a fact) + the subtype having a same-named
    # method (a fact): edge supertype.m -> subtype.m. Reachability/taint/impact then fan
    # out through polymorphic calls instead of dead-ending at the interface signature. ---
    subtypes: dict[str, list[str]] = {}
    for e in hyperedges:
        if e.kind in ("inherits", "implements") and len(e.members) >= 2:
            subtypes.setdefault(e.members[-1], []).append(e.members[0])   # supertype -> [subtype]
    methods_by_owner: dict[str, dict[str, list[str]]] = {}
    for v in vertices.values():
        if v.kind != "method":
            continue
        owner = method_owner.get(v.id)
        if owner is None and "." in v.id.split("#")[-1]:
            owner = v.id.rsplit(".", 1)[0]
        if owner is not None:
            methods_by_owner.setdefault(owner, {}).setdefault(v.name, []).append(v.id)
    di = 0
    for sup_vid, subs in subtypes.items():
        for mname, sup_methods in methods_by_owner.get(sup_vid, {}).items():
            if len(sup_methods) != 1:
                continue
            sup_m = sup_methods[0]
            for sub_vid in subs:
                sub_methods = methods_by_owner.get(sub_vid, {}).get(mname, [])
                sub_m = sub_methods[0] if len(sub_methods) == 1 else None
                if sub_m is not None and sub_m != sup_m:
                    hyperedges.append(Hyperedge(id=f"disp{di}", kind="dispatch",
                                                members=[sup_m, sub_m], directed=True, resolved=True))
                    di += 1

    # --- Pass 8: containment by line-nesting -> `defines` edges. LSP flattens
    # object-literal members (`const formatters = { cmd(){}, ... }`) to container-less
    # module-level method symbols; line-nesting recovers the link to their container
    # (variable/class/interface). The cs-wide foundation for dynamic-dispatch recall —
    # and a relationship impact/diagnose were missing. Per-file to stay near-linear. ---
    _CONTAINER_KINDS = ("variable", "class", "interface")
    verts_by_file: dict[str, list[Vertex]] = {}
    for v in vertices.values():
        if v.kind != "module":
            verts_by_file.setdefault(v.file, []).append(v)
    members_of: dict[str, list[str]] = {}     # container vid -> member vids (for Pass 9)
    ci = 0
    for fverts in verts_by_file.values():
        containers = [c for c in fverts if c.kind in _CONTAINER_KINDS]
        for m in fverts:
            if m.kind not in ("function", "method"):
                continue
            best = None
            for c in containers:
                if c.id != m.id and c.start_line <= m.start_line and m.end_line <= c.end_line:
                    if best is None or (c.end_line - c.start_line) < (best.end_line - best.start_line):
                        best = c
            if best is not None:
                hyperedges.append(Hyperedge(id=f"e-def-{ci}", kind="defines",
                                            members=[best.id, m.id], directed=True, resolved=True))
                members_of.setdefault(best.id, []).append(m.id)
                ci += 1

    # --- Pass 9: dynamic-dispatch edges. A frontend-flagged `obj[<dynamic>](...)` site
    # (RawReference kind="dyn_dispatch", name=base object) reaches EVERY member of that
    # container — invisible to static resolution. Resolve the base name to a container
    # (same-file first), then emit capped dispatch edges site -> members. Honest leads:
    # provenance="dynamic-dispatch", confidence ~1/N; above the fan-out cap we stay silent. ---
    containers_by_name: dict[str, list[Vertex]] = {}
    for v in vertices.values():
        if v.kind in _CONTAINER_KINDS:
            containers_by_name.setdefault(v.name, []).append(v)
    ddi = 0
    for r in raw.references:
        if r.kind != "dyn_dispatch" or not r.name:
            continue
        src = enclosing(r.from_file, r.from_line)
        if src is None:
            continue
        cands = containers_by_name.get(r.name, [])
        same_file = [c for c in cands if c.file == r.from_file]
        pool = same_file or cands
        container = pool[0] if len(pool) == 1 else None
        if container is None:
            continue
        members = [mid for mid in members_of.get(container.id, []) if mid != src]
        if not (0 < len(members) <= _MAX_DYN_DISPATCH):
            continue
        for cid in members:
            hyperedges.append(Hyperedge(id=f"e-dd-{ddi}", kind="dispatch",
                                        members=[src, cid], directed=True, resolved=True,
                                        confidence=_DYN_DISPATCH_CONFIDENCE,
                                        provenance="dynamic-dispatch"))
            ddi += 1

    return Hypernetwork(language=raw.language, root=raw.root,
                        vertices=list(vertices.values()),
                        hyperedges=hyperedges, surfaces=surfaces,
                        diagnostics=list(raw.diagnostics))
