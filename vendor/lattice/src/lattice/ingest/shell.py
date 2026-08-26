# src/lattice/ingest/shell.py
"""Shell ingest backend — bash/sh build & deploy scripts as a call graph.

No AST tool ships for shell, so this is a focused source parse: function definitions
(`name() {` / `function name {`) become symbols, their bodies are bounded by brace
counting, and an invocation of a known function name (in command position) becomes a
call edge. Shell is the build/deploy boundary — its exec sinks (`eval`, `curl | sh`,
`rm -rf`) are exactly the outbound boundary an audit cares about; secaudit's source scan
sees them, and the call graph attributes them to the function they live in.
"""
from __future__ import annotations
import pathlib
import re
import shutil
import subprocess

from lattice.ingest.types import RawIngest, RawSymbol, RawReference

_EXTS = ("*.sh", "*.bash")
_SKIP = {"node_modules", ".git", "dist", "build", "vendor"}
_FUNC = re.compile(r"^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\s*\)\s*\{")
_FUNC_KW = re.compile(r"^\s*function\s+([A-Za-z_]\w*)\s*\{")
_WORD = re.compile(r"[A-Za-z_]\w*")
_SYNTAX_TIMEOUT_SECONDS = 10


def _strip(line: str) -> str:
    return line.split("#", 1)[0]            # drop trailing comment (good enough)


def _functions(lines: list[str]):
    """Yield (name, start_line, end_line) for each shell function, body via brace count."""
    for i, line in enumerate(lines):
        m = _FUNC.match(line) or _FUNC_KW.match(line)
        if not m:
            continue
        depth = 0
        end = i
        for j in range(i, len(lines)):
            code = _strip(lines[j])
            depth += code.count("{") - code.count("}")
            end = j
            if depth <= 0 and j > i:
                break
        yield m.group(1), i + 1, end + 1


def shell_ingest(root, language: str = "shell") -> RawIngest:
    requested = pathlib.Path(root)
    diagnostics: list[dict] = []
    if requested.is_file():
        root = requested.parent
        supported = requested.suffix.lower() in {".sh", ".bash"}
        files = [requested] if supported else []
        if not supported:
            diagnostics.append({
                "kind": "unsupported_file", "severity": "error", "language": "shell",
                "file": requested.name,
                "message": "shell ingestion requires a .sh or .bash source file",
            })
    else:
        root = requested
        files = sorted({p for pat in _EXTS for p in root.rglob(pat)
                        if not (_SKIP & set(p.relative_to(root).parts))})
    if not files and not diagnostics:
        diagnostics.append({
            "kind": "no_source_files", "severity": "error", "language": "shell",
            "file": "<project>",
            "message": "no .sh or .bash source files were found",
        })

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    filelist: list[str] = []
    func_pos: dict[str, list[tuple[str, int]]] = {}
    per_file: list[tuple] = []        # (rel, lines, [(name, start, end)])
    entry_files: set[str] = set()
    validator = shutil.which("bash") or shutil.which("sh")

    for path in files:
        rel = path.relative_to(root).as_posix()
        filelist.append(rel)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            diagnostics.append({
                "kind": "read_error", "severity": "error", "language": "shell",
                "file": rel, "message": str(exc),
            })
            continue
        lines = text.splitlines()
        if requested.is_file() or (lines and lines[0].startswith("#!")):
            entry_files.add(rel)
        if validator is None:
            diagnostics.append({
                "kind": "syntax_validation_unavailable", "severity": "warning",
                "language": "shell", "file": rel,
                "message": "neither bash nor sh is available for syntax validation",
            })
        else:
            try:
                checked = subprocess.run(
                    [validator, "-n", str(path)], capture_output=True, text=True,
                    timeout=_SYNTAX_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                diagnostics.append({
                    "kind": "syntax_validation_error", "severity": "error",
                    "language": "shell", "file": rel, "message": str(exc),
                })
            else:
                if checked.returncode != 0:
                    diagnostics.append({
                        "kind": "parse_error", "severity": "error", "language": "shell",
                        "file": rel,
                        "message": (checked.stderr or checked.stdout
                                    or f"{path.name} failed shell syntax validation").strip(),
                    })
        funcs = list(_functions(lines))
        for name, start, end in funcs:
            symbols.append(RawSymbol(name=name, kind="function", file=rel,
                                     start_line=start, end_line=end, exported=True))
            func_pos.setdefault(name, []).append((rel, start))
        per_file.append((rel, lines, funcs))

    # calls: an invocation of a known function name, attributed to its line (the builder
    # resolves the enclosing function by range).
    for rel, lines, funcs in per_file:
        def_lines = {start for _, start, _ in funcs}
        for i, line in enumerate(lines, 1):
            if i in def_lines:
                # A compact definition can contain executable body text on the same
                # line (`call() { run; }`). Skip only the declaration prefix, not the
                # body call itself.
                stripped = _strip(line)
                code = stripped.split("{", 1)[1] if "{" in stripped else ""
            else:
                code = _strip(line)
            for w in _WORD.findall(code):
                candidates = func_pos.get(w, [])
                same_file = [target for target in candidates if target[0] == rel]
                pool = same_file if len(same_file) == 1 else candidates
                if len(pool) == 1:
                    tgt = pool[0]
                    references.append(RawReference(kind="references", from_file=rel,
                                                   from_line=i, to_file=tgt[0],
                                                   to_line=tgt[1], resolved=True, name=w))
                    break
                if candidates:
                    references.append(RawReference(
                        kind="references", from_file=rel, from_line=i,
                        to_file=rel, resolved=False, name=w,
                    ))
                    break          # first known callee per line is enough

    return RawIngest(language="shell", root=str(root), symbols=symbols,
                     references=references, diagnostics=diagnostics, files=filelist,
                     entry_files=entry_files)
