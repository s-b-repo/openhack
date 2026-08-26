# src/lattice/ingest/rust_graph.py
"""Rust ingest backend via the packaged native syn bridge.

Same tier as the Python, Solidity, and Go frontends: symbols (functions, impl
methods with the self type as container, structs and enums as classes, traits as
interfaces with supertrait extends), trait impls recorded as implements on the
type, call edges resolved by NAME, exported = `pub` visibility, stub detection
(empty body or a lone todo!()/unimplemented!()), `mod`/`use crate::` imports
resolved to in-repo files, and main.rs / src/bin entrypoints. `target/` and
`vendor/` are skipped.

Known simplifications, consistent with the sibling frontends: name-level call
resolution (no type inference), `use self::`/`use super::` paths stay unresolved,
and trait-impl method visibility follows the written `pub`, not trait reachability.

The bridge is built lazily with `cargo build --release` when missing or stale.
"""
from __future__ import annotations
import json
import pathlib
import subprocess

from lattice.bridge_runtime import (
    BRIDGE_RUN_TIMEOUT_SECONDS,
    BridgeRuntimeError,
    ensure_rust_bridge,
)
from lattice.ingest.types import RawIngest, RawSymbol, RawReference

_SKIP_DIRS = {"target", "vendor", "node_modules", ".git"}


def ensure_bridge() -> pathlib.Path:
    return ensure_rust_bridge("rustgraph", binary="rustgraph")


def _is_entry(rel: str) -> bool:
    p = pathlib.PurePosixPath(rel)
    return p.name == "main.rs" or "bin" in p.parts


def _module_dir(rel: str) -> pathlib.PurePosixPath:
    """Filesystem directory containing child modules declared by ``rel``.

    Rust's non-``mod.rs`` rule is the important case: ``src/foo.rs`` declaring
    ``mod bar;`` loads ``src/foo/bar.rs``, not ``src/bar.rs``.
    """
    path = pathlib.PurePosixPath(rel)
    if path.name in {"lib.rs", "main.rs", "mod.rs"}:
        return path.parent
    return path.with_suffix("")


def _resolve_mod(rel: str, name: str, known: set[str]) -> tuple[str, bool]:
    base = _module_dir(rel)
    candidates = (base / f"{name}.rs", base / name / "mod.rs")
    for cand in candidates:
        if str(cand) in known:
            return str(cand), True
    return str(candidates[0]), False


def _resolve_use(rel: str, path: str, known: set[str]) -> tuple[str | None, bool]:
    """Resolve a local use path, retaining an intended target when it is broken."""
    parts = path.split("::")
    if len(parts) < 2 or parts[0] not in {"crate", "self", "super"}:
        return None, False              # external crate; represented by to_file=None
    if parts[0] == "crate":
        base = pathlib.PurePosixPath("src")
    elif parts[0] == "self":
        base = _module_dir(rel)
    else:
        base = _module_dir(rel).parent
    tail = parts[1:]
    joined = base.joinpath(*tail)
    parent_item = base.joinpath(*tail[:-1]) if len(tail) > 1 else None
    candidates = [
        str(joined) + ".rs",
        str(joined / "mod.rs"),
        str(parent_item) + ".rs" if parent_item is not None else rel,
        str(parent_item / "mod.rs") if parent_item is not None else rel,
    ]
    for cand in candidates:
        if cand and cand in known:
            return cand, True
    return candidates[2] if parent_item is not None else candidates[0], False


def _enclosing(symbols: list[RawSymbol], rel: str, line: int) -> RawSymbol | None:
    matches = [s for s in symbols if s.file == rel and s.kind in ("function", "method")
               and s.start_line <= line <= s.end_line]
    return min(matches, key=lambda s: s.end_line - s.start_line) if matches else None


def _qualified_symbol(symbol: RawSymbol) -> str:
    return f"{symbol.container}.{symbol.name}" if symbol.container else symbol.name


def _module_context(caller: RawSymbol | None) -> str:
    if caller is None or not caller.container:
        return ""
    if caller.kind == "method":
        return caller.container.rpartition(".")[0]
    return caller.container


def _crate_owner_target(owner_parts: list[str], known: set[str]) -> tuple[str, str | None] | None:
    """Resolve the file-backed prefix of ``crate::module::...``.

    The bridge correctly leaves a top-level item in ``src/b.rs`` container-less;
    its module identity lives in the filename. Match the longest file-backed prefix,
    then treat any remaining owner segments as inline-module/type containment.
    """
    if not owner_parts or owner_parts[0] != "crate":
        return None
    modules = owner_parts[1:]
    for cut in range(len(modules), 0, -1):
        prefix = pathlib.PurePosixPath("src").joinpath(*modules[:cut])
        candidates = (str(prefix) + ".rs", str(prefix / "mod.rs"))
        matches = [candidate for candidate in candidates if candidate in known]
        if len(matches) == 1:
            remainder = ".".join(modules[cut:]) or None
            return matches[0], remainder
    return None


def rust_ingest(root, language: str = "rust") -> RawIngest:
    root = pathlib.Path(root)
    direct_file = root if root.is_file() else None
    if direct_file is not None:
        rs_files = [direct_file] if direct_file.suffix == ".rs" else []
        root = root.parent
    else:
        rs_files = sorted(
            p for p in root.rglob("*.rs")
            if not (_SKIP_DIRS & set(p.relative_to(root).parts)))

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    diagnostics: list[dict] = []
    files = [path.relative_to(root).as_posix() for path in rs_files]
    entry_files: set[str] = set()
    pending: list[tuple] = []            # (rel, from_line, bare name, qualified path)
    imports_pending: list[tuple] = []    # (rel, line, spec, lexical scope, local binding)
    impls: list[tuple] = []              # (type_name, trait_name)

    if not rs_files:
        kind = "unsupported_source_file" if direct_file is not None else "no_source_files"
        diagnostics.append({
            "kind": kind, "severity": "error", "language": "rust",
            **({"file": direct_file.name} if direct_file is not None else {}),
            "message": (f"expected a .rs source file, got {direct_file.name}"
                        if direct_file is not None
                        else "no Rust source files found"),
        })
        return RawIngest(language="rust", root=str(root), diagnostics=diagnostics,
                         files=files)

    try:
        bridge = ensure_bridge()
    except (BridgeRuntimeError, OSError, subprocess.SubprocessError) as exc:
        diagnostics.append({
            "kind": "bridge_error", "severity": "error", "language": "rust",
            "message": str(exc),
        })
        return RawIngest(language="rust", root=str(root), diagnostics=diagnostics,
                         files=files)

    for path in rs_files:
        rel = path.relative_to(root).as_posix()
        try:
            res = subprocess.run([str(bridge), str(path)], capture_output=True, text=True,
                                 timeout=BRIDGE_RUN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            diagnostics.append({
                "kind": "bridge_error", "severity": "error", "language": "rust",
                "file": rel,
                "message": ("Rust graph bridge timed out after "
                            f"{BRIDGE_RUN_TIMEOUT_SECONDS:g}s"),
            })
            continue
        except OSError as exc:
            diagnostics.append({
                "kind": "bridge_error", "severity": "error", "language": "rust",
                "file": rel, "message": str(exc),
            })
            continue
        if res.returncode != 0:
            diagnostics.append({
                "kind": "parse_error" if res.returncode == 2 else "bridge_error",
                "severity": "error", "language": "rust", "file": rel,
                "message": res.stderr.strip() or f"rust bridge exited {res.returncode}",
            })
            continue
        try:
            data = json.loads(res.stdout)
            if not isinstance(data, dict):
                raise ValueError("expected a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            diagnostics.append({
                "kind": "bridge_output_error", "severity": "error", "language": "rust",
                "file": rel, "message": str(exc),
            })
            continue
        if data.get("has_main") and _is_entry(rel):
            entry_files.add(rel)
        for s in data.get("symbols") or []:
            symbols.append(RawSymbol(
                name=s["name"], kind=s["kind"], file=rel,
                start_line=s["start"], end_line=s["end"],
                container=s.get("container") or None,
                exported=bool(s.get("exported")), is_stub=bool(s.get("stub")),
                params=s.get("params") or [],
                extends=s.get("extends") or [], implements=s.get("implements") or []))
        for c in data.get("calls") or []:
            pending.append((rel, c["from_line"], c["name"], c.get("path") or c["name"]))
        for imp in data.get("imports") or []:
            imports_pending.append((rel, imp["line"], imp["path"],
                                    imp.get("scope") or "", imp.get("binding")))
        for im in data.get("impls") or []:
            impls.append((im["type_name"], im["trait_name"]))

    # Trait impls attach to the type symbol wherever it was declared.
    by_identity: dict[str, list[RawSymbol]] = {}
    for s in symbols:
        by_identity.setdefault(_qualified_symbol(s), []).append(s)
    for type_name, trait_name in impls:
        candidates = by_identity.get(type_name, [])
        target = candidates[0] if len(candidates) == 1 else None
        if target is not None and trait_name not in target.implements:
            target.implements.append(trait_name)

    callables: dict[str, list[RawSymbol]] = {}
    for s in symbols:
        if s.kind in ("function", "method", "class", "interface"):
            callables.setdefault(s.name, []).append(s)

    known = set(files)
    use_bindings: dict[
        tuple[str, str], dict[str, tuple[str, str | None, str]]
    ] = {}
    for rel, line, spec, scope, binding in imports_pending:
        kind, _, payload = spec.partition(":")
        if kind == "mod":
            target, resolved = _resolve_mod(rel, payload, known)
        else:
            target, resolved = _resolve_use(rel, payload, known)
        if target is None:
            references.append(RawReference(
                kind="imports", from_file=rel, from_line=line,
                resolved=False, name=payload))
        else:
            references.append(RawReference(
                kind="imports", from_file=rel, from_line=line,
                to_file=target, to_line=1 if resolved else None,
                resolved=resolved, name=payload))
            if kind == "use" and resolved and binding:
                parts = payload.split("::")
                local_parts = parts[1:] if parts and parts[0] in {"crate", "self", "super"} \
                    else parts
                # Separate-file modules do not appear in a symbol's lexical container;
                # inline modules do. Scope the binding itself either way so a `use` in
                # inline module A cannot leak into sibling module B.
                target_container = (".".join(local_parts[:-1]) or None) \
                    if target == rel else None
                use_bindings.setdefault((rel, scope), {})[binding] = (
                    target, target_container, parts[-1],
                )

    for rel, from_line, bare, path in pending:
        candidates: list[RawSymbol] = []
        exact_identity = False
        intended_file: str | None = None
        caller = _enclosing(symbols, rel, from_line)
        if "::" in path:
            parts = path.split("::")
            owner_parts = parts[:-1]
            if owner_parts == ["Self"] and caller and caller.container:
                candidates = [s for s in callables.get(bare, [])
                              if s.container == caller.container]
                exact_identity = True
            else:
                if owner_parts and owner_parts[0] == "crate":
                    intended_file, _ = _resolve_use(
                        rel, "::".join([*owner_parts, bare]), known)
                file_owner = _crate_owner_target(owner_parts, known)
                if file_owner is not None:
                    target_file, target_container = file_owner
                    intended_file = target_file
                    candidates = [
                        s for s in callables.get(bare, [])
                        if s.file == target_file and s.container == target_container
                    ]
                    exact_identity = True
                module = _module_context(caller)
                if file_owner is not None:
                    owner_options: set[str] = set()
                elif owner_parts and owner_parts[0] == "crate":
                    owner_options = {".".join(owner_parts[1:])}
                elif owner_parts and owner_parts[0] == "self":
                    tail = ".".join(owner_parts[1:])
                    owner_options = {".".join(part for part in (module, tail) if part)}
                elif owner_parts and owner_parts[0] == "super":
                    parent = module.rpartition(".")[0]
                    tail = ".".join(owner_parts[1:])
                    owner_options = {".".join(part for part in (parent, tail) if part)}
                else:
                    owner = ".".join(owner_parts)
                    owner_options = {owner}
                    if module:
                        owner_options.add(f"{module}.{owner}")
                owner_options.discard("")
                if owner_options:
                    candidates = [s for s in callables.get(bare, [])
                                  if s.container in owner_options]
                    exact_identity = True
        elif "." in path:
            receiver = path.rsplit(".", 1)[0]
            if receiver == "self" and caller and caller.container:
                candidates = [s for s in callables.get(bare, [])
                              if s.container == caller.container]
                exact_identity = True
            elif receiver[:1].isupper():
                module = _module_context(caller)
                owner_options = {receiver}
                if module:
                    owner_options.add(f"{module}.{receiver}")
                candidates = [s for s in callables.get(bare, [])
                              if s.container in owner_options]
                exact_identity = True
        else:
            module = _module_context(caller)
            bound = use_bindings.get((rel, module), {}).get(bare)
            if bound:
                bound_file, bound_container, target_name = bound
                candidates = [s for s in callables.get(target_name, [])
                              if s.file == bound_file
                              and (bound_container is None or s.container == bound_container)]
                exact_identity = True
            else:
                candidates = [s for s in callables.get(bare, [])
                              if s.file == rel and s.kind == "function"
                              and s.container == (module or None)]

        if len(candidates) == 1:
            tgt = candidates[0]
            references.append(RawReference(
                kind="references", from_file=rel, from_line=from_line,
                to_file=tgt.file, to_line=tgt.start_line, resolved=True,
                name=path if exact_identity else bare))
        else:
            references.append(RawReference(
                kind="references", from_file=rel, from_line=from_line,
                to_file=intended_file, resolved=False, name=bare))

    return RawIngest(language="rust", root=str(root), symbols=symbols,
                     references=references, diagnostics=diagnostics,
                     files=files, entry_files=entry_files)
