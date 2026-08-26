# src/lattice/ingest/cpp.py
"""C++/CUDA ingest backend — via libclang's AST, fact-grade.

Same pattern as the Solidity (solc) and Python (ast) frontends: parse each translation
unit, emit the universal RawIngest (functions, classes/structs with bases -> inheritance,
methods, call edges resolved by libclang's `referenced` cursor), and let the language-
agnostic builder + every analysis work unchanged.

CUDA: `.cu`/`.cuh` are parsed as C++ with the CUDA keywords macro'd to nothing, so a
`__global__` kernel reads as a plain function. There's no CUDA toolkit needed — missing
system headers produce a tolerable PARTIAL AST (libclang is error-recovering), which is
all we need for structure. Kernels are tagged by a source scan so the GPU host/device
boundary is recoverable downstream.
"""
from __future__ import annotations
import pathlib
import re

from lattice.ingest.types import RawIngest, RawSymbol, RawReference

_EXTS = ("*.c", "*.cpp", "*.cc", "*.cxx", "*.c++", "*.h", "*.hpp", "*.hh", "*.hxx", "*.cu", "*.cuh")
_PARSE_SUFFIXES = {pattern[1:] for pattern in _EXTS}
_SKIP = {"node_modules", "build", "dist", "out", ".git",
         "cmake-build-debug", "cmake-build-release", "third_party", "extern"}
_CUDA_DEFS = ["-D__global__=", "-D__device__=", "-D__host__=", "-D__shared__=",
              "-D__constant__=", "-D__restrict__=", "-D__forceinline__=",
              "-D__launch_bounds__(x)=", "-D__align__(x)="]
_KERNEL_RE = re.compile(r"__global__\s+[\w:<>,\s\*&]+?\b(\w+)\s*\(")
# CUDA kernel launch `kernel<<<grid, block>>>(args)` — `<<<` is unique to launches (not
# valid C++), so it can't parse in the AST; recover the host->kernel edge by source scan.
_LAUNCH_RE = re.compile(r"\b(\w+)\s*<<<")
_INCLUDE_RE = re.compile(r"^\s*#\s*include\s*([<\"])([^>\"]+)[>\"]")


def _clang_args(path: pathlib.Path, language: str = "cpp") -> list[str]:
    """Select the real translation-unit language instead of parsing C as C++.

    ``restrict`` and several declaration/type rules are valid C but not C++17; forcing
    every ``.c`` file through the C++ grammar can therefore mutate or drop symbols.
    Explicit ``language='c'`` also makes standalone headers use the C grammar.
    """
    suffix = path.suffix.lower()
    if suffix == ".c" or (language == "c" and suffix == ".h"):
        return ["-x", "c", "-std=c11"]
    return ["-x", "c++", "-std=c++17"] + _CUDA_DEFS


def _load_clang():
    """Load the optional Python binding only when C/C++ source is selected."""
    import clang.cindex as cx

    return cx


def _frontend_unavailable(root: pathlib.Path, files: list[pathlib.Path],
                          language: str, exc: BaseException) -> RawIngest:
    """Represent a missing optional clang runtime as gate-visible graph evidence."""
    filelist = [path.relative_to(root).as_posix() for path in files]
    detail = str(exc).strip()
    suffix = f" Underlying error: {detail}" if detail else ""
    return RawIngest(
        language=language, root=str(root), files=filelist,
        diagnostics=[{
            "kind": "frontend_unavailable", "language": language,
            "file": filelist[0] if filelist else "<project>",
            "line": 1, "severity": "error",
            "message": (
                "C/C++ frontend unavailable. Install the optional frontend with "
                "`pip install 'lattice[cpp]'`." + suffix
            ),
        }],
    )


def _is_libclang_load_error(cx, exc: BaseException) -> bool:
    """True only for expected optional-binding/shared-library load failures."""
    libclang_error = getattr(cx, "LibclangError", None)
    return (isinstance(exc, (ImportError, OSError))
            or (isinstance(libclang_error, type) and isinstance(exc, libclang_error)))


def cpp_ingest(root, language: str = "cpp") -> RawIngest:
    requested = pathlib.Path(root).resolve()
    unsupported_file = False
    if requested.is_file():
        root = requested.parent
        unsupported_file = requested.suffix.lower() not in _PARSE_SUFFIXES
        files = [] if unsupported_file else [requested]
    else:
        root = requested
        files = sorted({p for pat in _EXTS for p in root.rglob(pat)
                        if not (_SKIP & set(p.relative_to(root).parts))})

    if not files:
        detail = (f"unsupported C/C++ source suffix for {requested.name}"
                  if unsupported_file else
                  f"no C/C++ source files were found under {requested}")
        return RawIngest(
            language=language, root=str(root), files=[],
            diagnostics=[{
                "kind": "no_source_files", "language": language,
                "file": requested.name if unsupported_file else "<project>",
                "line": 1, "severity": "error", "message": detail,
            }],
        )

    try:
        cx = _load_clang()
    except (ImportError, OSError) as exc:
        return _frontend_unavailable(root, files, language, exc)
    try:
        idx = cx.Index.create()
    except Exception as exc:
        if not _is_libclang_load_error(cx, exc):
            raise
        return _frontend_unavailable(root, files, language, exc)
    file_set = set(files)

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    diagnostics: list[dict] = []
    filelist: list[str] = []
    func_pos: dict[str, list[tuple[str, int]]] = {}
    definition_pos: dict[str, list[tuple[str, int]]] = {}
    pending: list[tuple] = []

    for path in files:
        rel = path.relative_to(root).as_posix()
        args = _clang_args(path, language)
        # Read once; hand the same bytes to libclang via unsaved_files — halves the
        # disk I/O and removes the parse-vs-scan TOCTOU window.
        src = path.read_text(encoding="utf-8", errors="ignore")
        filelist.append(rel)
        for line_no, line in enumerate(src.splitlines(), 1):
            match = _INCLUDE_RE.match(line)
            if match is None:
                continue
            delimiter, target = match.groups()
            candidates = [path.parent / target, root / target]
            resolved_path = next((p.resolve() for p in candidates if p.is_file()), None)
            resolved_rel = None
            if resolved_path is not None:
                try:
                    resolved_rel = resolved_path.relative_to(root).as_posix()
                except ValueError:
                    resolved_rel = None
            if resolved_rel is not None:
                to_file, resolved = resolved_rel, True
                if resolved_path not in file_set and resolved_path.is_file():
                    # A direct-file ingest follows its local include closure instead of
                    # creating a resolved edge to a module it never parsed.
                    file_set.add(resolved_path)
                    if resolved_path.suffix.lower() in _PARSE_SUFFIXES:
                        files.append(resolved_path)
                    else:
                        filelist.append(resolved_rel)
            elif delimiter == '"':
                intended = (path.parent / target).resolve()
                try:
                    to_file = intended.relative_to(root).as_posix()
                except ValueError:
                    to_file = None
                resolved = False
            else:
                # System/SDK include: represented as an external placeholder, which is
                # visible to boundary analysis but excluded from in-project resolution.
                to_file, resolved = None, False
            references.append(RawReference(
                kind="imports", from_file=rel, from_line=line_no, name=target,
                to_file=to_file, to_line=1, resolved=resolved,
            ))
        try:
            tu = idx.parse(str(path), args=args,
                           unsaved_files=[(str(path), src)],
                           options=cx.TranslationUnit.PARSE_INCOMPLETE)
        except cx.TranslationUnitLoadError as exc:
            diagnostics.append({
                "kind": "parse_error", "language": language, "file": rel,
                "line": 1, "severity": "error",
                "message": f"libclang could not load translation unit: {exc}",
            })
            continue
        for diagnostic in tu.diagnostics:
            if diagnostic.severity < cx.Diagnostic.Error:
                continue
            location_file = diagnostic.location.file
            try:
                diagnostic_file = pathlib.Path(str(location_file)).resolve().relative_to(
                    root.resolve()).as_posix() if location_file is not None else rel
            except ValueError:
                diagnostic_file = str(location_file) if location_file is not None else rel
            diagnostics.append({
                "kind": "parse_error", "language": language,
                "file": diagnostic_file, "line": diagnostic.location.line or 1,
                "severity": "error",
                "message": diagnostic.spelling,
            })
        kernels = set(_KERNEL_RE.findall(src))
        _walk(tu.cursor, str(path), rel, kernels, symbols, pending, func_pos,
              definition_pos, cx)
        # kernel launches (the host->device boundary the C++ parser can't see)
        for i, line in enumerate(src.splitlines(), 1):
            for m in _LAUNCH_RE.finditer(line):
                pending.append((rel, i, m.group(1), None, None, None))

    modeled_sites = {(s.file, s.start_line) for s in symbols
                     if s.kind in ("function", "method")}
    for rel, from_line, callee, target_path, target_line, target_usr in pending:
        tgt = None
        definitions = list(dict.fromkeys(definition_pos.get(target_usr, []))) \
            if target_usr else []
        if len(definitions) == 1:
            # A call parsed from another translation unit often points at a header
            # declaration even though the unique definition was parsed separately.
            # Clang USRs are overload/linkage-aware, so prefer that definition rather
            # than dead-ending the graph at the declaration vertex.
            tgt = definitions[0]
        if target_path is not None and target_line is not None:
            try:
                target_rel = pathlib.Path(target_path).resolve().relative_to(root).as_posix()
                exact = (target_rel, target_line)
                if tgt is None and exact in modeled_sites:
                    tgt = exact
            except ValueError:
                pass
        candidates = list(dict.fromkeys(func_pos.get(callee, [])))
        if tgt is None and len(candidates) == 1:
            tgt = candidates[0]
        if tgt is not None:
            references.append(RawReference(kind="references", from_file=rel, from_line=from_line,
                                           to_file=tgt[0], to_line=tgt[1], resolved=True,
                                           name=callee))
        else:
            # Preserve the call as an unresolved named reference. The shared builder may
            # recover a unique candidate, but must never manufacture a fact-grade edge
            # to the first of several same-named functions.
            references.append(RawReference(kind="references", from_file=rel,
                                           from_line=from_line, name=callee,
                                           resolved=False))

    entry_files = {
        symbol.file for symbol in symbols
        if symbol.kind == "function" and symbol.name == "main" and symbol.container is None
    }
    return RawIngest(language=language, root=str(root), symbols=symbols,
                     references=references, diagnostics=diagnostics, files=filelist,
                     entry_files=entry_files)


def _semantic_container(cursor, cx) -> str | None:
    """Qualified namespace/class ownership from libclang's semantic parent chain."""
    K = cx.CursorKind
    owner_kinds = {K.NAMESPACE, K.CLASS_DECL, K.STRUCT_DECL, K.CLASS_TEMPLATE}
    parts: list[str] = []
    try:
        parent = cursor.semantic_parent
        while parent is not None and parent.kind != K.TRANSLATION_UNIT:
            if parent.kind in owner_kinds and parent.spelling:
                parts.append(parent.spelling)
            parent = parent.semantic_parent
    except Exception:
        return None
    return "::".join(reversed(parts)) or None


def _qualified_cursor(cursor, cx) -> str:
    owner = _semantic_container(cursor, cx)
    return f"{owner}::{cursor.spelling}" if owner else cursor.spelling


def _is_class_member(cursor, cx) -> bool:
    K = cx.CursorKind
    try:
        return cursor.semantic_parent.kind in {
            K.CLASS_DECL, K.STRUCT_DECL, K.CLASS_TEMPLATE,
        }
    except Exception:
        return False


def _walk(node, abspath, rel, kernels, symbols, pending, func_pos, definition_pos, cx,
          cls=None, func_line=None):
    K = cx.CursorKind
    for c in node.get_children():
        loc = c.location.file
        in_file = loc is not None and str(loc) == abspath
        kind = c.kind

        if kind in (K.CLASS_DECL, K.STRUCT_DECL, K.CLASS_TEMPLATE) and in_file and c.spelling:
            bases = [b.type.spelling.split("::")[-1].split("<")[0].strip()
                     for b in c.get_children() if b.kind == K.CXX_BASE_SPECIFIER]
            symbols.append(RawSymbol(
                name=c.spelling, kind="class", file=rel,
                start_line=c.extent.start.line, end_line=c.extent.end.line,
                container=_semantic_container(c, cx),
                exported=True, extends=[b for b in bases if b]))
            _walk(c, abspath, rel, kernels, symbols, pending, func_pos, definition_pos, cx,
                  cls=_qualified_cursor(c, cx), func_line=None)

        elif kind in (K.FUNCTION_DECL, K.CXX_METHOD, K.CONSTRUCTOR, K.DESTRUCTOR,
                      K.FUNCTION_TEMPLATE) and in_file and c.spelling:
            name = c.spelling
            is_member = _is_class_member(c, cx)
            container = _semantic_container(c, cx) or cls
            mkind = "method" if is_member else "function"
            # Public surface: externally linked free functions, public/protected
            # members, and CUDA kernels. File-local ``static`` functions and
            # anonymous-namespace functions have internal linkage; marking them as
            # API hides real dead code and makes private removals look breaking.
            linkage = getattr(getattr(c, "linkage", None), "name", "")
            exported = ((not is_member and linkage == "EXTERNAL")
                        or (is_member and c.access_specifier.name
                            in ("PUBLIC", "PROTECTED", "INVALID"))
                        or name in kernels)
            params = [a.spelling for a in c.get_arguments()]
            symbols.append(RawSymbol(
                name=name, kind=mkind, file=rel,
                start_line=c.extent.start.line, end_line=c.extent.end.line,
                container=container, exported=exported, params=params))
            func_pos.setdefault(name, []).append((rel, c.extent.start.line))
            usr = c.get_usr() or None
            if usr and c.is_definition():
                definition_pos.setdefault(usr, []).append((rel, c.extent.start.line))
            _walk(c, abspath, rel, kernels, symbols, pending, func_pos, definition_pos, cx,
                  cls=cls, func_line=c.extent.start.line)

        elif kind == K.CALL_EXPR and func_line is not None:
            callee = c.spelling or (c.referenced.spelling if c.referenced else "")
            if callee:
                target_path, target_line, target_usr = None, None, None
                try:
                    referenced = c.referenced
                    target_usr = referenced.get_usr() if referenced is not None else None
                    definition = referenced.get_definition() if referenced is not None else None
                    target = definition or referenced
                    if target is not None and target.location.file is not None:
                        target_path = str(target.location.file)
                        target_line = target.location.line
                except Exception:
                    pass
                pending.append((rel, func_line, callee, target_path, target_line, target_usr))
            _walk(c, abspath, rel, kernels, symbols, pending, func_pos, definition_pos,
                  cx, cls, func_line)

        else:
            _walk(c, abspath, rel, kernels, symbols, pending, func_pos, definition_pos,
                  cx, cls, func_line)
