# src/lattice/ingest/ruby_graph.py
"""Ruby ingest backend via the packaged stdlib Ripper bridge.

Same tier as the Python, Solidity, Go, and Rust frontends: symbols (classes and
modules with superclass extends and include implements, defs as methods with the
enclosing class as container), visibility from bare private/protected/public
markers, stub detection (empty body or a lone `raise NotImplementedError`),
require_relative imports resolved to in-repo files, call edges resolved by NAME
(with `Const.new` counting as use of the class), and shebang / __FILE__ == $0
entrypoints. vendor/ and .bundle/ are skipped.

Known simplifications, consistent with the sibling frontends: name-level call
resolution, `private :sym` argument form not tracked (bare markers only), and
plain `require` of gems stays unresolved.
"""
from __future__ import annotations
import json
import pathlib
import posixpath
import subprocess

from lattice.bridge_runtime import BRIDGE_RUN_TIMEOUT_SECONDS, BridgeRuntimeError, ruby_bridge
from lattice.ingest.types import RawIngest, RawSymbol, RawReference

_SKIP_DIRS = {"vendor", ".bundle", "node_modules", ".git"}
_ENTRY_MARKERS = ("__FILE__ == $0", "$0 == __FILE__",
                  "__FILE__ == $PROGRAM_NAME", "$PROGRAM_NAME == __FILE__")


def ruby_ingest(root, language: str = "ruby") -> RawIngest:
    root = pathlib.Path(root)
    direct_file = root if root.is_file() else None
    if direct_file is not None:
        rb_files = [direct_file] if direct_file.suffix == ".rb" else []
        root = root.parent
    else:
        rb_files = sorted(
            p for p in root.rglob("*.rb")
            if not (_SKIP_DIRS & set(p.relative_to(root).parts)))

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    diagnostics: list[dict] = []
    files = [path.relative_to(root).as_posix() for path in rb_files]
    entry_files: set[str] = set()
    pending: list[tuple] = []            # (rel, from_line, callee, receiver)
    imports_pending: list[tuple] = []    # (rel, line, kind, path)

    if not rb_files:
        kind = "unsupported_source_file" if direct_file is not None else "no_source_files"
        diagnostics.append({
            "kind": kind, "severity": "error", "language": "ruby",
            **({"file": direct_file.name} if direct_file is not None else {}),
            "message": (f"expected a .rb source file, got {direct_file.name}"
                        if direct_file is not None
                        else "no Ruby source files found"),
        })
        return RawIngest(language="ruby", root=str(root), diagnostics=diagnostics,
                         files=files)

    try:
        bridge = ruby_bridge("ruby_graph.rb")
    except (BridgeRuntimeError, OSError) as exc:
        diagnostics.append({
            "kind": "bridge_error", "severity": "error", "language": "ruby",
            "message": str(exc),
        })
        return RawIngest(language="ruby", root=str(root), diagnostics=diagnostics,
                         files=files)

    for path in rb_files:
        rel = path.relative_to(root).as_posix()
        try:
            res = subprocess.run(["ruby", str(bridge), str(path)],
                                 capture_output=True, text=True,
                                 timeout=BRIDGE_RUN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            diagnostics.append({
                "kind": "bridge_error", "severity": "error", "language": "ruby",
                "file": rel,
                "message": ("Ruby graph bridge timed out after "
                            f"{BRIDGE_RUN_TIMEOUT_SECONDS:g}s"),
            })
            continue
        except OSError as exc:
            diagnostics.append({
                "kind": "bridge_error", "severity": "error", "language": "ruby",
                "file": rel, "message": str(exc),
            })
            continue
        if res.returncode != 0:
            diagnostics.append({
                "kind": "parse_error" if res.returncode == 2 else "bridge_error",
                "severity": "error", "language": "ruby", "file": rel,
                "message": res.stderr.strip() or f"ruby bridge exited {res.returncode}",
            })
            continue
        try:
            data = json.loads(res.stdout)
            if not isinstance(data, dict):
                raise ValueError("expected a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            diagnostics.append({
                "kind": "bridge_output_error", "severity": "error", "language": "ruby",
                "file": rel, "message": str(exc),
            })
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if text.startswith("#!") or any(m in text for m in _ENTRY_MARKERS):
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
            pending.append((rel, c["from_line"], c["name"], c.get("receiver")))
        for imp in data.get("imports") or []:
            imports_pending.append((rel, imp["line"], imp["kind"], imp["path"]))

    by_name: dict[str, list[RawSymbol]] = {}
    for s in symbols:
        if s.kind in ("function", "method", "class"):
            by_name.setdefault(s.name, []).append(s)
            if s.kind == "class" and "::" in s.name:
                by_name.setdefault(s.name.rsplit("::", 1)[-1], []).append(s)

    def enclosing(rel: str, line: int) -> RawSymbol | None:
        matches = [s for s in symbols if s.file == rel and s.kind in ("function", "method")
                   and s.start_line <= line <= s.end_line]
        return min(matches, key=lambda s: s.end_line - s.start_line) if matches else None

    for rel, from_line, callee, receiver in pending:
        caller = enclosing(rel, from_line)
        candidates: list[RawSymbol] = []
        exact_identity = False
        if receiver == "self" and caller and caller.container:
            candidates = [s for s in by_name.get(callee, [])
                          if s.container == caller.container]
            exact_identity = True
        elif receiver and receiver[:1].isupper():
            if callee == receiver:       # Const.new is emitted as the class name
                candidates = [s for s in by_name.get(callee, []) if s.kind == "class"]
            else:
                receiver_options = {receiver}
                if caller and caller.container and "::" in caller.container:
                    namespace = caller.container.rpartition("::")[0]
                    receiver_options.add(f"{namespace}::{receiver}")
                candidates = [s for s in by_name.get(callee, [])
                              if s.container in receiver_options]
            exact_identity = True
        elif receiver is None and caller and caller.container:
            candidates = [s for s in by_name.get(callee, [])
                          if s.container == caller.container]
            exact_identity = bool(candidates)
        elif receiver is None:
            candidates = [s for s in by_name.get(callee, [])
                          if s.file == rel and s.kind == "function"]

        if len(candidates) == 1:
            tgt = candidates[0]
            qualified_name = (f"{tgt.container}.{callee}"
                              if exact_identity and tgt.container
                              and len(by_name.get(callee, [])) > 1 else callee)
            references.append(RawReference(
                kind="references", from_file=rel, from_line=from_line,
                to_file=tgt.file, to_line=tgt.start_line, resolved=True,
                name=qualified_name))
        else:
            references.append(RawReference(
                kind="references", from_file=rel, from_line=from_line,
                resolved=False, name=callee))

    known = set(files)
    for rel, line, kind, spec in imports_pending:
        if kind != "require_relative":
            references.append(RawReference(
                kind="imports", from_file=rel, from_line=line,
                resolved=False, name=spec))
            continue
        base = pathlib.PurePosixPath(rel).parent
        candidate = str(base / spec) + ("" if spec.endswith(".rb") else ".rb")
        cand = posixpath.normpath(candidate)
        references.append(RawReference(
            kind="imports", from_file=rel, from_line=line,
            to_file=cand, to_line=1 if cand in known else None,
            resolved=cand in known, name=spec))

    return RawIngest(language="ruby", root=str(root), symbols=symbols,
                     references=references, diagnostics=diagnostics,
                     files=files, entry_files=entry_files)
