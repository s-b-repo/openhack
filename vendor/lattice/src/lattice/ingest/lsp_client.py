"""LSP-based ingestion of a TypeScript codebase into RawIngest.

Probed multilspy 0.0.15 return shape:
  request_document_symbols -> tuple (list[dict], None)
  Each dict: {name, kind (int), range: {start/end: {line(0-based), character}},
              selectionRange, detail}  -- flat list, no children key in TS output.
"""
from __future__ import annotations
import asyncio
import contextlib
import inspect
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import psutil

_IDENT = re.compile(r"^[A-Za-z_$][\w$]*$")
_FUNC_KEYWORD = re.compile(r"=\s*(?:async\s+)?function\b")
_CONTROL = re.compile(r"\s*(?:for|if|while|switch|catch)\b")


def _is_function_valued(lines: list[str], start_line: int) -> bool:
    """True if a const/var declaration holds a function: `= () =>`, `= x =>`,
    `= async () =>` (return-type annotations allowed), or `= function`. Looks only at
    the DECLARATION line and excludes control-flow lines, so object literals
    (`= {}`), loop variables (`for (const x of …)`), and counters (`for (let i = 0…)`)
    are correctly NOT treated as functions."""
    i = start_line - 1
    if not (0 <= i < len(lines)):
        return False
    line = lines[i]
    if _FUNC_KEYWORD.search(line):
        return True
    # an arrow on an assignment line that isn't a for/if/while header
    return "=>" in line and "=" in line.split("=>", 1)[0] and not _CONTROL.match(line)

# Seconds to let tsserver index the project before querying cross-file references.
# Override with LATTICE_LSP_SETTLE for larger codebases that need longer indexing.
_REFERENCE_SETTLE = float(os.environ.get("LATTICE_LSP_SETTLE", "2.5"))
# Python 3.13 + multilspy can resize the stdin buffer while a previous large JS
# didOpen payload is still exported. A short JS-only pause avoids that crash.
_JS_OPEN_SETTLE = float(os.environ.get("LATTICE_LSP_JS_OPEN_SETTLE", "0.05"))
# multilspy leaves server startup and shutdown futures unbounded. A missing/broken
# language server must fail with an actionable error instead of hanging an agent or CI
# job forever. The same budget is passed to request futures below.
_LSP_TIMEOUT = max(0.01, float(os.environ.get("LATTICE_LSP_TIMEOUT", "60")))
from lattice.ingest.types import RawSymbol, RawReference, RawIngest
from lattice.bridge_runtime import BridgeRuntimeError
from lattice.cache import SourceIngestError
from multilspy import SyncLanguageServer
from multilspy.multilspy_config import MultilspyConfig
from multilspy.multilspy_logger import MultilspyLogger

_LSP_BINARY = {
    "typescript": "typescript-language-server",
    "javascript": "typescript-language-server",
    "python": "pyright-langserver",
}


class LSPIngestError(SourceIngestError):
    """Expected LSP availability/lifecycle failure with an actionable message."""


def _quote_lsp_launch_command(lsp) -> None:
    """Quote multilspy's bundled executable path before its shell-based launch."""
    try:
        launch_info = lsp.language_server.server.process_launch_info
    except AttributeError:
        # Test doubles and future multilspy adapters may not expose launch metadata.
        return
    suffix = " --stdio"
    raw = str(launch_info.cmd).strip()
    if not raw.endswith(suffix):
        return
    executable = raw[:-len(suffix)].strip()
    if len(executable) >= 2 and executable[0] == executable[-1] \
            and executable[0] in ("'", '"'):
        executable = executable[1:-1]
    if not pathlib.Path(executable).is_file():
        # Do not reinterpret a generic shell pipeline whose argv boundary is unknown.
        return
    command = [executable, "--stdio"]
    rendered = subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command)
    launch_info.cmd = rendered


@contextlib.contextmanager
def _started_server(lsp, timeout: float | None = None):
    """Start/stop a multilspy server with finite waits for both lifecycle phases.

    multilspy's synchronous wrapper calls ``Future.result()`` without a timeout for
    startup and shutdown. Reproducing its short adapter here lets us bound those waits
    while retaining the same public LSP object and open-file/request behavior.
    """
    budget = _LSP_TIMEOUT if timeout is None else max(0.01, timeout)
    loop = asyncio.new_event_loop()
    loop_thread = threading.Thread(target=loop.run_forever, daemon=True,
                                   name="lattice-lsp-loop")
    lsp.loop = loop
    lsp.loop_thread = loop_thread
    loop_thread.start()
    ctx = lsp.language_server.start_server()
    entered = False
    startup_finished = threading.Event()

    async def enter_server():
        try:
            return await ctx.__aenter__()
        finally:
            # ``run_coroutine_threadsafe(...).cancel()`` marks its concurrent Future
            # cancelled before the asyncio task has necessarily run the async-generator
            # finalizer. This event records the stronger fact that __aenter__ itself is
            # actually done.
            startup_finished.set()

    def abort_underlying_server() -> None:
        """Best-effort bounded process cleanup for a failed/cancelled lifecycle.

        A multilspy frontend can launch its subprocess and then block waiting for the
        initialize response *before* its async context manager yields. Cancelling
        ``__aenter__`` alone therefore skips the frontend's post-yield shutdown block.
        Stop the protocol handler explicitly when it exists.
        """
        handler = getattr(getattr(lsp, "language_server", None), "server", None)
        stop = getattr(handler, "stop", None)
        process = getattr(handler, "process", None)
        if stop is not None:
            async def stop_server():
                result = stop()
                if inspect.isawaitable(result):
                    await result

            stopped = asyncio.run_coroutine_threadsafe(stop_server(), loop=loop)
            try:
                stopped.result(timeout=budget)
            except Exception:
                stopped.cancel()

        # If a buggy/blocked stop coroutine did not reap the process, force the same
        # process-tree termination hook multilspy itself uses, then await exit briefly.
        if process is not None and getattr(process, "returncode", None) is None:
            signal_tree = getattr(handler, "_signal_process_tree", None)
            try:
                if signal_tree is not None:
                    signal_tree(process, terminate=False)
                else:
                    process.kill()
            except Exception:
                pass
            wait = getattr(process, "wait", None)
            if wait is not None:
                async def wait_process():
                    result = wait()
                    if inspect.isawaitable(result):
                        await result

                waited = asyncio.run_coroutine_threadsafe(wait_process(), loop=loop)
                try:
                    waited.result(timeout=budget)
                except Exception:
                    waited.cancel()

    def cancel_and_finish(future, finished: threading.Event) -> None:
        future.cancel()
        # Await the coroutine's real finalizer, not only the already-cancelled wrapper
        # Future. If cancellation is stuck, explicit handler.stop below is the fallback.
        finished.wait(timeout=budget)

    def drain_loop_tasks() -> None:
        async def drain():
            current = asyncio.current_task()
            pending = [task for task in asyncio.all_tasks()
                       if task is not current and not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            await asyncio.sleep(0)

        drained = asyncio.run_coroutine_threadsafe(drain(), loop=loop)
        try:
            drained.result(timeout=budget)
        except Exception:
            drained.cancel()

    try:
        startup = asyncio.run_coroutine_threadsafe(enter_server(), loop=loop)
        try:
            startup.result(timeout=budget)
        except TimeoutError as exc:
            cancel_and_finish(startup, startup_finished)
            abort_underlying_server()
            raise LSPIngestError(
                f"Language server startup timed out after {budget:g}s. "
                "Set LATTICE_LSP_TIMEOUT to a larger finite value if this project "
                "needs more indexing time."
            ) from exc
        except BaseException:
            cancel_and_finish(startup, startup_finished)
            abort_underlying_server()
            raise
        entered = True
        yield lsp
    finally:
        active_exception = sys.exc_info()[0] is not None
        shutdown_error: BaseException | None = None
        if entered:
            shutdown_finished = threading.Event()

            async def exit_server():
                try:
                    return await ctx.__aexit__(None, None, None)
                finally:
                    shutdown_finished.set()

            shutdown = asyncio.run_coroutine_threadsafe(
                exit_server(), loop=loop)
            try:
                shutdown.result(timeout=budget)
            except TimeoutError as exc:
                cancel_and_finish(shutdown, shutdown_finished)
                abort_underlying_server()
                if not active_exception:
                    shutdown_error = LSPIngestError(
                        f"Language server shutdown timed out after {budget:g}s.")
                    shutdown_error.__cause__ = exc
            except BaseException as exc:
                abort_underlying_server()
                if not active_exception:
                    shutdown_error = exc
        drain_loop_tasks()
        loop.call_soon_threadsafe(loop.stop)
        loop_thread.join(timeout=budget)
        if not loop_thread.is_alive():
            loop.close()
        elif not active_exception:
            raise LSPIngestError(
                f"Language server event loop did not stop within {budget:g}s.")
        if shutdown_error is not None:
            raise shutdown_error

# LSP SymbolKind integers -> human-readable kind names
_KIND: dict[int, str] = {
    2: "module",
    5: "class",
    6: "method",
    8: "field",
    11: "interface",
    12: "function",
    13: "variable",
    26: "type",
}


def _symbol_kind_name(k: int) -> str:
    return _KIND.get(k, "variable")


def _read_lines(root: pathlib.Path, rel: str) -> list[str]:
    """Return file lines, empty list on error."""
    try:
        return (root / rel).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []


_BUILD_DIRS = {"dist", "build", "out", ".next", "coverage", ".cache"}
_TS_SOURCE_GLOBS = ("*.ts", "*.tsx")
_JS_SOURCE_GLOBS = ("*.js", "*.jsx", "*.mjs", "*.cjs")
_GENERATED_JS_SUFFIXES = (
    ".bundle.js", ".bundle.mjs", ".bundle.cjs",
    ".min.js", ".min.mjs", ".min.cjs",
)


def _select_source_files(root: pathlib.Path, language: str = "typescript") -> list[pathlib.Path]:
    """Source TS/JS files, excluding what ISN'T source: dependencies (node_modules),
    build output (dist/build/out — only NESTED, so ingesting a dep under node_modules
    still works), and GENERATED declarations (a `X.d.ts` whose `X.ts`/`X.tsx` sibling
    exists — the source IS the .ts; ingesting both triplicates findings and inflates
    dead-code). Standalone .d.ts (hand-written ambient / type-only packages) is kept."""
    out: list[pathlib.Path] = []
    globs = _JS_SOURCE_GLOBS if language == "javascript" else _TS_SOURCE_GLOBS
    for pat in globs:
        for p in root.rglob(pat):
            parts = set(p.relative_to(root).parts)
            if "node_modules" in parts or (_BUILD_DIRS & parts):
                continue
            if language == "javascript" and p.name.endswith(_GENERATED_JS_SUFFIXES):
                continue
            if p.name.endswith(".d.ts"):
                stem = p.name[:-5]
                if (p.parent / (stem + ".ts")).exists() or (p.parent / (stem + ".tsx")).exists():
                    continue
            out.append(p)
    return sorted(out)


_OUT_DIRS = ("dist/", "build/", "lib/", "out/")


def _entry_files_from_package_json(root: pathlib.Path, language: str = "typescript") -> set[str]:
    """Map package.json `main`/`bin` (which point at BUILT output like ./dist/index.js)
    back to the existing source file (src/index.ts). These are the authoritatively
    DECLARED program entrypoints — the most reliable reachability roots, and the ones
    shebang detection misses when the toolchain adds the shebang only at build time."""
    pkg = root / "package.json"
    if not pkg.exists():
        return set()
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    raw_paths: list[str] = []
    if isinstance(data.get("main"), str):
        raw_paths.append(data["main"])
    b = data.get("bin")
    if isinstance(b, str):
        raw_paths.append(b)
    elif isinstance(b, dict):
        raw_paths.extend(v for v in b.values() if isinstance(v, str))

    out: set[str] = set()
    source_exts = (".js", ".jsx", ".mjs", ".cjs") if language == "javascript" else (".ts", ".tsx")
    for p in raw_paths:
        base = re.sub(r"\.(js|jsx|cjs|mjs|ts|tsx)$", "", p.lstrip("./"))
        cands: list[str] = []
        for od in _OUT_DIRS:
            if base.startswith(od):
                stem = base[len(od):]
                cands += [f"src/{stem}{ext}" for ext in source_exts]
                cands += [f"{stem}{ext}" for ext in source_exts]
        cands += [f"{base}{ext}" for ext in source_exts]   # main may point straight at source
        for c in cands:
            if (root / c).exists():
                out.add(c)
                break
    return out


_STUB_MARKER = re.compile(r"todo|fixme|not[\s_]?implemented|unimplemented", re.I)


def _is_stub(lines: list[str], start_line: int, end_line: int) -> bool:
    """A function is a stub only if it is *explicitly marked unfinished* — a TODO/FIXME/
    not-implemented comment, or a body that is a single `throw`/`pass` placeholder.

    A *silently empty* function (`function noop() {}`) is NOT a stub: emptiness is
    ambiguous — it's just as likely a deliberate no-op, default callback, or empty
    constructor. Treating bare emptiness as 'unimplemented' produced critical false
    positives (e.g. `noop` flagged as a user-facing dead end). 'Unfinished' requires
    evidence of intent-to-implement, not mere absence of code."""
    text = "\n".join(lines[start_line - 1:end_line])
    if "{" not in text:
        return False                                   # no block body (e.g. type/expr)
    inner = text.split("{", 1)[-1].rsplit("}", 1)[0]
    has_marker = bool(_STUB_MARKER.search(inner))
    body = re.sub(r"/\*.*?\*/", "", inner, flags=re.S)
    body = re.sub(r"//.*", "", body)
    stmts = [s.strip() for s in body.replace(";", "\n").splitlines() if s.strip()]
    if not stmts:
        return has_marker                              # empty body: stub only if MARKED unfinished
    if len(stmts) == 1 and (stmts[0].lower().startswith("throw") or stmts[0].strip() == "pass"):
        return True                                    # single throw/pass placeholder
    return False                                       # has real code -> not a stub (TODO comments ignored)


def _exported(lines: list[str], start_line: int) -> bool:
    """Return True if the declaration line starts with 'export'."""
    try:
        return lines[start_line - 1].lstrip().startswith("export")
    except IndexError:
        return False


def _flatten(syms: list[dict], out: list, container: str | None = None) -> None:
    """Recursively flatten DocumentSymbol list into
    (name, kind, start, end, container, sel_line0, sel_char0) tuples.

    Handles both DocumentSymbol (with optional 'children') and SymbolInformation
    (with 'location.range').  Range lines are converted from 0-based LSP to 1-based;
    the selection position (the symbol name) is kept 0-based for LSP reference queries.
    """
    for s in syms:
        name = s.get("name", "?")
        kind = s.get("kind", 13)
        # DocumentSymbol uses 'range'; SymbolInformation uses 'location.range'
        rng = s.get("range") or s.get("location", {}).get("range", {})
        start = rng.get("start", {}).get("line", 0) + 1   # 0-based -> 1-based
        end = rng.get("end", {}).get("line", start - 1) + 1
        # selectionRange points at the name itself — the position to query references from.
        sel = s.get("selectionRange", {}).get("start") or rng.get("start", {})
        sel_line0 = sel.get("line", start - 1)
        sel_char0 = sel.get("character", 0)
        out.append((name, kind, start, end, container, sel_line0, sel_char0))
        # Recurse into children if present (some LSPs return nested symbols)
        for child in s.get("children", []) or []:
            _flatten([child], out, container=name)


def _location_site(loc: dict, root: pathlib.Path) -> tuple[str, int] | None:
    """Normalize one LSP reference location into (file_relative_to_root, line_1based).

    Returns None for locations outside the project root or lacking a parseable path.
    """
    rng = loc.get("range") or loc.get("location", {}).get("range", {})
    line0 = rng.get("start", {}).get("line")
    if line0 is None:
        return None
    rel = loc.get("relativePath")
    if rel is None:
        uri = loc.get("uri") or loc.get("absolutePath") or ""
        if uri.startswith("file://"):
            uri = uri[len("file://"):]
        if not uri:
            return None
        try:
            rel = pathlib.Path(uri).resolve().relative_to(root).as_posix()
        except ValueError:
            return None
    return (pathlib.Path(rel).as_posix(), line0 + 1)


def _ref_edges(sym_file: str, sym_start: int, sym_end: int,
               sites: list[tuple[str, int]]) -> list[RawReference]:
    """Turn a symbol's reference sites into 'references' edges pointing AT the symbol.

    Sites that fall inside the symbol's own declaration span are the declaration /
    self-references and are dropped — only true external users become edges. The
    builder's enclosing() logic then resolves each from_line to the calling symbol.
    """
    edges: list[RawReference] = []
    for f, ln in sites:
        if f == sym_file and sym_start <= ln <= sym_end:
            continue  # declaration or self-reference
        edges.append(RawReference(
            kind="references",
            from_file=f,
            from_line=ln,
            to_file=sym_file,
            to_line=sym_start,
            resolved=True,
        ))
    return edges


# Symbol kinds worth resolving references for — the entities refactor/taint care about.
_REFERENCEABLE = {"function", "method", "class", "interface"}


# Extensions a relative specifier may resolve to. TypeScript intentionally prefers
# source TS; JavaScript follows JS/Node order first. A main.js beside both dep.js and
# dep.ts must not silently point at the TypeScript file.
_TS_IMPORT_EXTS = (".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs",
                   ".json", ".vue", ".svelte")
_JS_IMPORT_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".json", ".ts", ".tsx",
                   ".d.ts", ".vue", ".svelte")
_JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs"}


def _import_language(from_file: str, language: str | None = None) -> str:
    if language in ("typescript", "javascript"):
        return language
    return "javascript" if pathlib.Path(from_file).suffix.lower() in _JS_SUFFIXES else "typescript"


def _js_tokens(lines: list[str]) -> list[tuple[str, str, int]]:
    """Small comment-aware JS/TS lexer for module declarations.

    Only identifiers, quoted strings, and punctuation are retained. That is enough to
    recognize static ESM/CommonJS dependencies while avoiding false imports inside
    comments, ordinary strings, and template literals. The integer is the 1-based line.
    """
    source = "\n".join(lines)
    tokens: list[tuple[str, str, int]] = []
    i, line, n = 0, 1, len(source)
    while i < n:
        ch = source[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch.isspace():
            i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            i += 2
            while i < n and source[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            i += 2
            while i < n:
                if source[i] == "\n":
                    line += 1
                if source[i:i + 2] == "*/":
                    i += 2
                    break
                i += 1
            continue
        if ch == "/":
            # Skip regex literals so `/require('not-a-module')/` cannot manufacture a
            # dependency. A slash can begin a regex only in expression-start contexts;
            # after an identifier/string/closing delimiter it is division instead.
            prev_kind, prev_value = (tokens[-1][:2] if tokens else (None, None))
            regex_context = (
                prev_value is None
                or (prev_kind == "punct" and prev_value in "([{,:;=!?&|+-*%~<>")
                or (prev_kind == "ident" and prev_value in {"return", "case", "throw", "yield"})
            )
            if regex_context:
                i += 1
                in_class = False
                while i < n:
                    cur = source[i]
                    if cur == "\\" and i + 1 < n:
                        i += 2
                        continue
                    if cur == "[":
                        in_class = True
                    elif cur == "]":
                        in_class = False
                    elif cur == "/" and not in_class:
                        i += 1
                        while i < n and source[i].isalpha():
                            i += 1
                        break
                    elif cur == "\n":
                        line += 1
                        break
                    i += 1
                continue
        if ch in ("'", '"', "`"):
            quote, start_line = ch, line
            i += 1
            value: list[str] = []
            while i < n:
                cur = source[i]
                if cur == "\\" and i + 1 < n:
                    # Preserve the escaped character. Module paths almost never need
                    # decoding beyond this, and this correctly handles escaped quotes.
                    value.append(source[i + 1])
                    if source[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if cur == quote:
                    i += 1
                    break
                if cur == "\n":
                    line += 1
                value.append(cur)
                i += 1
            # Template literals can contain arbitrary code/interpolation and cannot be
            # static module specifiers, so omit them entirely.
            if quote != "`":
                tokens.append(("string", "".join(value), start_line))
            continue
        if ch.isalpha() or ch in ("_", "$"):
            start = i
            i += 1
            while i < n and (source[i].isalnum() or source[i] in ("_", "$")):
                i += 1
            tokens.append(("ident", source[start:i], line))
            continue
        tokens.append(("punct", ch, line))
        i += 1
    return tokens


def _module_specifiers(lines: list[str]) -> list[tuple[int, str]]:
    """Return static module dependencies as ``(line, specifier)``.

    Handles multiline ESM imports/re-exports, side-effect imports, dynamic imports with
    a string literal, and bare CommonJS ``require('x')`` calls. Dynamic expressions are
    intentionally excluded because they do not identify one dependency edge.
    """
    tokens = _js_tokens(lines)
    found: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()

    def add(line: int, target: str) -> None:
        item = (line, target)
        if target and item not in seen:
            seen.add(item)
            found.append(item)

    for i, (kind, value, line) in enumerate(tokens):
        if kind != "ident":
            continue
        prev = tokens[i - 1][1] if i else None
        if value == "require" and prev != ".":
            if (i + 3 < len(tokens) and tokens[i + 1][1] == "("
                    and tokens[i + 2][0] == "string" and tokens[i + 3][1] == ")"):
                add(line, tokens[i + 2][1])
            continue
        if value == "import" and prev != ".":
            # import 'side-effect'; or import('dynamic-but-static-name')
            if i + 1 < len(tokens) and tokens[i + 1][0] == "string":
                add(line, tokens[i + 1][1])
                continue
            if (i + 3 < len(tokens) and tokens[i + 1][1] == "("
                    and tokens[i + 2][0] == "string"
                    and tokens[i + 3][1] in (")", ",")):
                add(line, tokens[i + 2][1])
                continue
        if value not in ("import", "export") or prev == ".":
            continue
        # import/export declarations can span lines. Stop at their semicolon; ``from``
        # is the only token whose following string is a dependency specifier.
        for j in range(i + 1, len(tokens) - 1):
            if tokens[j][1] == ";":
                break
            if tokens[j][0] == "ident" and tokens[j][1] == "from" \
                    and tokens[j + 1][0] == "string":
                add(line, tokens[j + 1][1])
                break
    return found


def _append_dynamic_dispatch_refs(source_files: list[str], root: pathlib.Path,
                                  language: str, references: list[RawReference],
                                  diagnostics: list[dict]) -> None:
    """Run the required Babel enrichment without turning bridge failure into silence."""
    try:
        from lattice.ingest.js_arbitrary_call import dynamic_dispatch_refs
        references.extend(dynamic_dispatch_refs(source_files, root, diagnostics, language))
    except BridgeRuntimeError as exc:
        diagnostics.append({
            "kind": "bridge_error", "language": language, "file": "<project>",
            "line": 1, "severity": "error", "message": str(exc),
        })
    except Exception as exc:
        diagnostics.append({
            "kind": "bridge_error", "language": language, "file": "<project>",
            "line": 1, "severity": "error",
            "message": f"JavaScript dynamic-dispatch enrichment failed: {exc}",
        })


def _request_reference_locations(lsp, rel: str, line0: int, char0: int,
                                 symbol_line: int, language: str,
                                 diagnostics: list[dict]) -> list[dict]:
    """Request LSP references, preserving timeout and non-timeout failure semantics."""
    try:
        return lsp.request_references(rel, line0, char0) or []
    except TimeoutError:
        raise
    except Exception as exc:
        diagnostics.append({
            "kind": "reference_error", "language": language, "file": rel,
            "line": symbol_line, "severity": "error",
            "message": f"LSP reference request failed: {exc}",
        })
        return []


def _resolve_import(target: str, from_file: str, root: pathlib.Path,
                    language: str | None = None) -> str | None:
    """Resolve a RELATIVE import specifier to the real file it points at, mirroring TS
    module resolution: try the path with each language-appropriate extension, then
    `<path>/index.<ext>` (barrels). TypeScript also rewrites explicit `.js`/`.mjs`
    specifiers to TS source when no exact JS file exists. Returns the path
    relative to root if a file actually EXISTS, else None — so genuinely-missing imports
    stay broken while resolvable ones (incl. `.json`, `.tsx`, index files) resolve.

    Bare specifiers (npm packages, path aliases) return None -> treated as external.
    """
    if not target.startswith("."):
        return None
    base = (root / pathlib.Path(from_file).parent / target).resolve()
    import_language = _import_language(from_file, language)
    extensions = _JS_IMPORT_EXTS if import_language == "javascript" else _TS_IMPORT_EXTS

    candidates: list[pathlib.Path] = []
    if base.suffix:                                  # explicit extension
        candidates.append(base)
        if import_language == "typescript" and base.suffix in _JS_SUFFIXES:
            # In authored TS, ./x.js commonly names the emitted extension for x.ts.
            stem = str(base)[: -len(base.suffix)]
            candidates += [pathlib.Path(stem + e) for e in (".ts", ".tsx", ".d.ts")]
    else:                                            # extensionless: file, then index barrel
        candidates += [pathlib.Path(str(base) + e) for e in extensions]
        candidates += [base / ("index" + e) for e in extensions]

    for c in candidates:
        if c.is_file():
            try:
                return c.relative_to(root).as_posix()
            except ValueError:
                return None                          # outside the project root
    return None


def _params(lines: list[str], start: int) -> list[str]:
    """Ordered parameter names from a function/method declaration, preserving the rest
    marker (`...args`). Captured at ingest so a library graph carries its signature — the
    join contract (arity) can be checked by reference, without the library's source."""
    decl = " ".join(lines[start - 1: start + 1])
    m = re.search(r"\(([^)]*)\)", decl)
    if not m:
        return []
    out: list[str] = []
    for tok in m.group(1).split(","):
        tok = tok.strip()
        if not tok:
            continue
        rest = tok.startswith("...")
        name = re.split(r"[=\s]", tok.lstrip(".").split(":")[0].strip().strip("{}").strip())[0]
        if name.isidentifier():
            out.append(("..." + name) if rest else name)
    return out


def _typelist(s: str) -> list[str]:
    """Split a comma list of type refs into base identifier names: strip generics and
    namespaces (`ns.Base<T>` -> `Base`)."""
    out: list[str] = []
    for t in s.split(","):
        t = re.sub(r"<.*?>", "", t).strip().split(".")[-1].strip()
        if t.isidentifier():
            out.append(t)
    return out


def _supertypes(lines: list[str], start: int):
    """(extends_names, implements_names) from a class/interface declaration. Facts read
    straight from `class C extends Base implements I, J`."""
    decl = " ".join(lines[start - 1: start + 2]).split("{", 1)[0]
    ext, impl = [], []
    m = re.search(r"\bextends\s+(.+?)(?:\bimplements\b|$)", decl)
    if m:
        ext = _typelist(m.group(1))
    m = re.search(r"\bimplements\s+(.+?)$", decl)
    if m:
        impl = _typelist(m.group(1))
    return ext, impl


def _symbols_from_flat(flat: list, rel: str, lines: list[str]):
    """Turn a file's flat LSP symbol list into (RawSymbols, reference-query targets).
    SINGLE SOURCE OF TRUTH for both full and incremental ingest — container recovery,
    the identifier filter, stub/param capture, and the referenceable decision all live
    here, so the two paths can't drift (they had: incremental was missing container
    recovery). ref targets are (rel, start, end, sel_line0, sel_char0)."""
    # TS returns a FLAT symbol list (no nesting), so methods arrive with no container.
    # Recover class/interface containment by range: smallest enclosing class that isn't self.
    containers = sorted(
        ((s[2], s[3], s[0]) for s in flat
         if _symbol_kind_name(s[1]) in ("class", "interface")),
        key=lambda c: c[1] - c[0])

    def container_of(start, end, name):
        for cs, ce, cname in containers:
            if cname != name and cs <= start and end <= ce:
                return cname
        return None

    symbols: list[RawSymbol] = []
    ref_targets: list[tuple] = []
    for name, kind, start, end, container, sel_line0, sel_char0 in flat:
        # Skip LSP synthetic symbols — anonymous callbacks, computed members: their names
        # aren't identifiers and they have no callable identity, only noise.
        if not _IDENT.match(name):
            continue
        container = container or container_of(start, end, name)
        kind_name = _symbol_kind_name(kind)
        # is_stub/params are only meaningful for things with a function body — functions,
        # methods, and function-valued consts.
        func_like = (kind_name in ("function", "method")
                     or (kind_name in ("variable", "constant")
                         and _is_function_valued(lines, start)))
        ext, impl = _supertypes(lines, start) if kind_name in ("class", "interface") else ([], [])
        symbols.append(RawSymbol(
            name=name, kind=kind_name, file=rel, start_line=start, end_line=end,
            container=container, exported=_exported(lines, start),
            is_stub=_is_stub(lines, start, end) if func_like else False,
            params=_params(lines, start) if func_like else [],
            extends=ext, implements=impl))
        # functions, methods, classes, interfaces — and function-valued consts/vars
        # (`export const f = () => {}`), real callable symbols worth reference edges.
        if kind_name in _REFERENCEABLE or (kind_name in ("variable", "constant")
                                           and _is_function_valued(lines, start)):
            ref_targets.append((rel, start, end, sel_line0, sel_char0))
    return symbols, ref_targets


def _intended_rel(target: str, from_file: str, root: pathlib.Path,
                  language: str | None = None) -> str:
    """The path a BROKEN relative import meant to point at (best-effort, no existence
    check). Used so a missing `./ghost` keeps a real-looking target the builder flags as
    unresolved — instead of collapsing to None and being mistaken for an external pkg."""
    base = (root / pathlib.Path(from_file).parent / target).resolve()
    try:
        rel = base.relative_to(root).as_posix()
    except ValueError:
        return target
    if base.suffix:
        return rel
    default_ext = ".js" if _import_language(from_file, language) == "javascript" else ".ts"
    return rel + default_ext


def ingest(root: str | pathlib.Path, language: str) -> RawIngest:
    """Ingest a TypeScript codebase via LSP and return a RawIngest."""
    root = pathlib.Path(root).resolve()
    if not root.is_dir():
        kind = "source file" if root.is_file() else "missing path"
        raise LSPIngestError(
            f"{language} LSP ingestion requires a project directory; got {kind}: {root}. "
            "Pass the containing project directory so tsconfig/jsconfig/package.json "
            "and cross-file references are available."
        )

    # A valid project directory with no selected-language source is not evidence of a
    # complete empty program. Retain an explicit gate-visible diagnostic and avoid
    # starting an LSP process that has nothing to index.
    source_files = _select_source_files(root, language)
    if not source_files:
        return RawIngest(
            language=language, root=str(root), files=[],
            diagnostics=[{
                "kind": "no_source_files", "language": language,
                "file": "<project>", "line": 1, "severity": "error",
                "message": f"no {language} source files were found under {root}",
            }],
        )

    binary = _LSP_BINARY.get(language)
    if binary and shutil.which(binary) is None:
        raise LSPIngestError(
            f"Language server '{binary}' for {language} not found on PATH. "
            f"Install it (e.g. for typescript: `npm install -g typescript typescript-language-server`)."
        )

    config = MultilspyConfig.from_dict({"code_language": language})
    lsp = SyncLanguageServer.create(
        config, MultilspyLogger(), str(root), timeout=_LSP_TIMEOUT)
    # multilspy launches a string through the shell and does not quote its bundled
    # executable. A checkout/venv path containing spaces otherwise exits with rc=127
    # while the initialize Future misleadingly waits until our lifecycle timeout.
    _quote_lsp_launch_command(lsp)

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    diagnostics: list[dict] = []
    # Resolved import targets that aren't .ts source (e.g. .json, .tsx, barrels) — we
    # don't model their internals, but they're real files, so register them as module
    # vertices to keep their imports RESOLVED instead of falsely broken.
    extra_files: set[str] = set()
    # Referenceable symbols stashed in phase 1, resolved in phase 2: (file, start, end, sel_line0, sel_char0)
    ref_targets: list[tuple[str, int, int, int, int]] = []
    entry_files: set[str] = _entry_files_from_package_json(root, language)
    ingest_complete = False

    try:
        with _started_server(lsp), contextlib.ExitStack() as open_files:
            # Keep ALL project files open for the whole ingest: tsserver resolves
            # cross-file references to `export const` (and other lazily-indexed
            # symbols) only for OPEN buffers. Querying with just the callee file
            # open silently drops those references — a real edge-recall hole.
            for path in source_files:
                open_files.enter_context(lsp.open_file(str(path.relative_to(root))))
                if language == "javascript" and _JS_OPEN_SETTLE > 0:
                    time.sleep(_JS_OPEN_SETTLE)

            # --- Phase 1: symbols + import edges ---
            for path in source_files:
                rel = str(path.relative_to(root))
                lines = _read_lines(root, rel)

                # A #!/usr/bin/env shebang marks a file meant to be EXECUTED directly —
                # a program entrypoint. Rooting reachability here (not only at exported
                # API) is what makes sinks reached from main() provably reachable.
                if lines and lines[0].startswith("#!"):
                    entry_files.add(rel)

                raw_syms = lsp.request_document_symbols(rel)
                # Probed shape: tuple (list[dict], None) — take first element
                if isinstance(raw_syms, tuple):
                    syms_list = raw_syms[0]
                else:
                    syms_list = raw_syms
                if not isinstance(syms_list, list):
                    diagnostics.append({
                        "kind": "lsp_schema_error", "language": language, "file": rel,
                        "line": 1, "severity": "error",
                        "message": "document-symbol response was not a list",
                    })
                    syms_list = []

                flat: list[tuple] = []
                _flatten(syms_list, flat)

                file_syms, file_refs = _symbols_from_flat(flat, rel, lines)
                symbols.extend(file_syms)
                ref_targets.extend(file_refs)

                # Static ESM + CommonJS dependencies, including multiline and
                # side-effect forms. The shared scanner is reused by incremental ingest.
                for i, target in _module_specifiers(lines):
                    resolved_to = _resolve_import(target, rel, root, language)
                    if resolved_to is not None:
                        extra_files.add(resolved_to)
                        to_file, resolved = resolved_to, True
                    elif target.startswith("."):
                        # relative import that resolves to no file -> BROKEN (not
                        # external). Keep the intended path so it's flagged unresolved.
                        to_file = _intended_rel(target, rel, root, language)
                        resolved = False
                    else:
                        to_file, resolved = None, False   # bare specifier -> external pkg
                    references.append(RawReference(
                        kind="imports", from_file=rel, from_line=i, name=target,
                        to_file=to_file, to_line=1, resolved=resolved,
                    ))

            # --- Phase 2: reference edges (refactor / taint substrate) ---
            # tsserver needs the project indexed before request_references returns
            # cross-file uses; let it settle once after all files are loaded.
            time.sleep(_REFERENCE_SETTLE)
            for rel, start, end, sel_line0, sel_char0 in ref_targets:
                locs = _request_reference_locations(
                    lsp, rel, sel_line0, sel_char0, start, language, diagnostics)
                sites: list[tuple[str, int]] = []
                for loc in locs:
                    site = _location_site(loc, root)
                    if site is not None:
                        sites.append(site)
                references.extend(_ref_edges(rel, start, end, sites))
            ingest_complete = True
    except psutil.NoSuchProcess as exc:
        if not ingest_complete:
            diagnostics.append({
                "kind": "lsp_process_error", "language": language, "file": "<project>",
                "line": 1, "severity": "error",
                "message": f"language server exited before ingestion completed: {exc}",
            })
        # Once all requests completed this is multilspy's benign macOS shutdown race.
    except TimeoutError as exc:
        raise LSPIngestError(
            f"Language server request timed out after {_LSP_TIMEOUT:g}s while ingesting "
            f"{language} at {root}. Set LATTICE_LSP_TIMEOUT to a larger finite value "
            "for unusually large projects."
        ) from exc

    source_rel = {str(p.relative_to(root)) for p in source_files}
    all_files = sorted(source_rel | extra_files)   # include resolved non-source import targets
    # Dynamic-dispatch sites (obj[<dynamic>]()) the LSP cannot resolve are required
    # enrichment. Bridge/tool/schema failures become gate-visible diagnostics.
    _append_dynamic_dispatch_refs(
        sorted(source_rel), root, language, references, diagnostics)
    return RawIngest(
        language=language,
        root=str(root),
        symbols=symbols,
        references=references,
        diagnostics=diagnostics,
        files=all_files,
        entry_files=entry_files,
    )
