# src/lattice/ingest/go_graph.py
"""Go ingest backend via the packaged native go/parser bridge.

Same tier as the Python and Solidity frontends: symbols (functions, methods with the
receiver type as container, structs and interfaces with embedded types as inheritance),
call edges resolved by NAME, exported = capitalized identifier (the language rule),
stub detection (empty body or a lone panic with a TODO / not-implemented literal),
imports resolved through the go.mod module path to in-repo files, and package-main
entrypoints. Test files (*_test.go) and vendor/testdata are skipped: the graph models
product structure, and Go test functions are runner-invoked so they would all read as
dead code.

The bridge is built lazily from go_ast.go when missing or stale; that keeps the repo
source-only while staying hermetic for anyone with a Go toolchain.
"""
from __future__ import annotations
import json
import pathlib
import re
import subprocess

from lattice.bridge_runtime import (
    BRIDGE_RUN_TIMEOUT_SECONDS,
    BridgeRuntimeError,
    ensure_go_bridge,
)
from lattice.ingest.types import RawIngest, RawSymbol, RawReference

_SKIP_DIRS = {"vendor", "testdata", "node_modules", ".git"}


def ensure_bridge() -> pathlib.Path:
    return ensure_go_bridge()


def _module_path(root: pathlib.Path) -> str | None:
    gm = root / "go.mod"
    if not gm.exists():
        return None
    m = re.search(r"^module\s+(\S+)", gm.read_text(encoding="utf-8", errors="ignore"), re.M)
    return m.group(1) if m else None


def go_ingest(root, language: str = "go") -> RawIngest:
    root = pathlib.Path(root)
    direct_file = root if root.is_file() else None
    if direct_file is not None:
        go_files = ([direct_file]
                    if direct_file.suffix == ".go"
                    and not direct_file.name.endswith("_test.go") else [])
        root = root.parent
    else:
        go_files = sorted(
            p for p in root.rglob("*.go")
            if not p.name.endswith("_test.go")
            and not (_SKIP_DIRS & set(p.relative_to(root).parts)))
    module = _module_path(root)

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    diagnostics: list[dict] = []
    files = [path.relative_to(root).as_posix() for path in go_files]
    entry_files: set[str] = set()
    pending: list[tuple] = []            # (rel, from_line, bare name, qualified callee)
    imports_pending: list[tuple] = []    # (rel, line, import_path, explicit alias)
    package_by_file: dict[str, str] = {}

    if not go_files:
        kind = "unsupported_source_file" if direct_file is not None else "no_source_files"
        diagnostics.append({
            "kind": kind, "severity": "error", "language": "go",
            **({"file": direct_file.name} if direct_file is not None else {}),
            "message": (f"expected a non-test .go source file, got {direct_file.name}"
                        if direct_file is not None
                        else "no Go source files found"),
        })
        return RawIngest(language="go", root=str(root), diagnostics=diagnostics,
                         files=files)

    try:
        bridge = ensure_bridge()
    except (BridgeRuntimeError, OSError, subprocess.SubprocessError) as exc:
        diagnostics.append({
            "kind": "bridge_error", "severity": "error", "language": "go",
            "message": str(exc),
        })
        return RawIngest(language="go", root=str(root), diagnostics=diagnostics,
                         files=files)

    for path in go_files:
        rel = path.relative_to(root).as_posix()
        try:
            res = subprocess.run([str(bridge), "-mode", "graph", str(path)],
                                 capture_output=True, text=True,
                                 timeout=BRIDGE_RUN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            diagnostics.append({
                "kind": "bridge_error", "severity": "error", "language": "go",
                "file": rel,
                "message": ("Go graph bridge timed out after "
                            f"{BRIDGE_RUN_TIMEOUT_SECONDS:g}s"),
            })
            continue
        except OSError as exc:
            diagnostics.append({
                "kind": "bridge_error", "severity": "error", "language": "go",
                "file": rel, "message": str(exc),
            })
            continue
        if res.returncode != 0:
            diagnostics.append({
                "kind": "parse_error" if res.returncode == 2 else "bridge_error",
                "severity": "error", "language": "go", "file": rel,
                "message": res.stderr.strip() or f"go bridge exited {res.returncode}",
            })
            continue
        try:
            data = json.loads(res.stdout)
            if not isinstance(data, dict):
                raise ValueError("expected a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            diagnostics.append({
                "kind": "bridge_output_error", "severity": "error", "language": "go",
                "file": rel, "message": str(exc),
            })
            continue
        package_by_file[rel] = str(data.get("package") or "")
        if data.get("entry"):
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
            pending.append((rel, c["from_line"], c["name"], c.get("callee") or c["name"]))
        for imp in data.get("imports") or []:
            imports_pending.append((rel, imp["line"], imp["path"], imp.get("alias") or ""))

    callables: dict[str, list[RawSymbol]] = {}
    for s in symbols:
        if s.kind in ("function", "method", "class", "interface"):
            callables.setdefault(s.name, []).append(s)

    # go.mod-scoped import resolution: an import under the module path maps to the
    # in-repo package directory; its first source file stands in for the package.
    by_dir: dict[str, list[str]] = {}
    for f in files:
        by_dir.setdefault(str(pathlib.PurePosixPath(f).parent), []).append(f)
    import_dirs: dict[str, dict[str, str]] = {}
    for rel, line, imp, explicit_alias in imports_pending:
        if not module or not (imp == module or imp.startswith(module + "/")):
            references.append(RawReference(
                kind="imports", from_file=rel, from_line=line,
                resolved=False, name=imp))
            continue
        sub = imp[len(module):].lstrip("/") or "."
        targets = sorted(by_dir.get(sub, []))
        if targets:
            references.append(RawReference(
                kind="imports", from_file=rel, from_line=line,
                to_file=targets[0], to_line=1, resolved=True, name=imp))
            alias = explicit_alias or package_by_file.get(targets[0]) or pathlib.PurePosixPath(imp).name
            if alias not in ("_", "."):
                import_dirs.setdefault(rel, {})[alias] = sub
        else:
            intended = (f"{sub}/<missing-package>.go" if sub != "."
                        else "<missing-package>.go")
            references.append(RawReference(
                kind="imports", from_file=rel, from_line=line,
                to_file=intended, to_line=None, resolved=False, name=imp))

    for rel, from_line, bare, callee in pending:
        candidates: list[RawSymbol] = []
        qualified = "." in callee
        if qualified:
            qualifier = callee.split(".", 1)[0]
            imported_dir = import_dirs.get(rel, {}).get(qualifier)
            if imported_dir is not None:
                candidates = [s for s in callables.get(bare, [])
                              if str(pathlib.PurePosixPath(s.file).parent) == imported_dir
                              and s.kind == "function"]
        else:
            caller_dir = str(pathlib.PurePosixPath(rel).parent)
            candidates = [s for s in callables.get(bare, [])
                          if str(pathlib.PurePosixPath(s.file).parent) == caller_dir
                          and s.kind == "function"]

        if len(candidates) == 1:
            tgt = candidates[0]
            references.append(RawReference(
                kind="references", from_file=rel, from_line=from_line,
                to_file=tgt.file, to_line=tgt.start_line, resolved=True,
                name=callee if qualified else bare))
        else:
            # Preserve the call even when its receiver type is not statically known.
            # The shared builder may emit calibrated dispatch leads, but never a
            # confidence-1 edge to whichever duplicate happened to be seen first.
            references.append(RawReference(
                kind="references", from_file=rel, from_line=from_line,
                resolved=False, name=bare))

    return RawIngest(language="go", root=str(root), symbols=symbols,
                     references=references, diagnostics=diagnostics,
                     files=files, entry_files=entry_files)
