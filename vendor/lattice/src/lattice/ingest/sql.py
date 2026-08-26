# src/lattice/ingest/sql.py
"""SQL ingest backend — schema + stored logic as a graph.

SQL isn't a call graph the way code is, but the pieces that matter map cleanly: CREATE
TABLE/VIEW are data structures (class-like), CREATE FUNCTION/PROCEDURE are functions, and
a CALL between procedures is an edge. Dynamic SQL (EXECUTE/sp_executesql) is the injection
sink secaudit's source scan already sees. Regex-based — SQL has no single AST tool across
dialects, and the structural facts (names, ranges, CALLs) are recoverable directly.
"""
from __future__ import annotations
import pathlib
import re

from lattice.ingest.types import RawIngest, RawSymbol, RawReference

_SKIP = {"node_modules", ".git", "dist", "build", "migrations_backup"}
_TABLE = re.compile(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|VIEW|MATERIALIZED\s+VIEW)\s+"
                    r"(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?(\w+)", re.I)
_ROUTINE = re.compile(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+[`\"\[]?(\w+)", re.I)
_CALL = re.compile(r"\bCALL\s+(\w+)|\bPERFORM\s+(\w+)|\bSELECT\s+(\w+)\s*\(", re.I)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _lexical_error(text: str) -> str | None:
    """Detect only dialect-independent lexical failures; this is not a SQL parser."""
    i = 0
    depth = 0
    quote: str | None = None
    dollar: str | None = None
    block_comment = False
    bracket_identifier = False
    while i < len(text):
        if block_comment:
            if text[i:i + 2] == "*/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if bracket_identifier:
            if text[i:i + 2] == "]]":
                i += 2
                continue
            if text[i] == "]":
                bracket_identifier = False
            i += 1
            continue
        if dollar is not None:
            if text.startswith(dollar, i):
                i += len(dollar)
                dollar = None
            else:
                i += 1
            continue
        if quote is not None:
            if text[i] == quote:
                if i + 1 < len(text) and text[i + 1] == quote:
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if text[i:i + 2] == "--":
            newline = text.find("\n", i + 2)
            i = len(text) if newline < 0 else newline + 1
            continue
        if text[i] == "#":
            newline = text.find("\n", i + 1)
            i = len(text) if newline < 0 else newline + 1
            continue
        if text[i:i + 2] == "/*":
            block_comment = True
            i += 2
            continue
        if text[i] in ("'", '"', "`"):
            quote = text[i]
            i += 1
            continue
        if text[i] == "[":
            bracket_identifier = True
            i += 1
            continue
        if text[i] == "$":
            match = re.match(r"\$[A-Za-z_]*\$", text[i:])
            if match:
                dollar = match.group(0)
                i += len(dollar)
                continue
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth < 0:
                return "unmatched closing parenthesis"
        i += 1
    if block_comment:
        return "unterminated block comment"
    if dollar is not None:
        return f"unterminated dollar-quoted string {dollar}"
    if quote is not None:
        return "unterminated quoted string or identifier"
    if bracket_identifier:
        return "unterminated bracketed identifier"
    if depth:
        return f"unbalanced parentheses (depth {depth})"
    return None


def sql_ingest(root, language: str = "sql") -> RawIngest:
    requested = pathlib.Path(root)
    diagnostics: list[dict] = []
    if requested.is_file():
        root = requested.parent
        supported = requested.suffix.lower() == ".sql"
        files = [requested] if supported else []
        if not supported:
            diagnostics.append({
                "kind": "unsupported_file", "severity": "error", "language": "sql",
                "file": requested.name,
                "message": "SQL ingestion requires a .sql source file",
            })
    else:
        root = requested
        files = sorted(p for p in root.rglob("*.sql")
                       if not (_SKIP & set(p.relative_to(root).parts)))
    if not files and not diagnostics:
        diagnostics.append({
            "kind": "no_source_files", "severity": "error", "language": "sql",
            "file": "<project>",
            "message": "no .sql source files were found",
        })

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    filelist: list[str] = []
    pos: dict[str, list[tuple[str, int]]] = {}
    pending: list[tuple] = []

    for path in files:
        rel = path.relative_to(root).as_posix()
        filelist.append(rel)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            diagnostics.append({
                "kind": "read_error", "severity": "error", "language": "sql",
                "file": rel, "message": str(exc),
            })
            continue
        if error := _lexical_error(text):
            diagnostics.append({
                "kind": "parse_error", "severity": "error", "language": "sql",
                "file": rel, "message": error,
            })
        for rx, kind in ((_TABLE, "class"), (_ROUTINE, "function")):
            for m in rx.finditer(text):
                name = m.group(1)
                line = _line_of(text, m.start())
                symbols.append(RawSymbol(name=name, kind=kind, file=rel,
                                         start_line=line, end_line=line, exported=True))
                pos.setdefault(name, []).append((rel, line))
        for m in _CALL.finditer(text):
            callee = m.group(1) or m.group(2) or m.group(3)
            line = _line_of(text, m.start())
            pending.append((rel, line, callee))
    # routines need an end line so the builder can attribute a CALL to its enclosing
    # routine; approximate each routine's range as up to the next routine in the file.
    routine_starts: dict[str, list[int]] = {}
    for s in symbols:
        if s.kind == "function":
            routine_starts.setdefault(s.file, []).append(s.start_line)
    for s in symbols:
        if s.kind == "function":
            later = [ln for ln in routine_starts[s.file] if ln > s.start_line]
            s.end_line = (min(later) - 1) if later else s.start_line + 200

    for rel, line, callee in pending:
        candidates = [target for target in pos.get(callee, []) if target[1] != line]
        same_file = [target for target in candidates if target[0] == rel]
        pool = same_file if len(same_file) == 1 else candidates
        if len(pool) == 1:
            tgt = pool[0]
            references.append(RawReference(kind="references", from_file=rel, from_line=line,
                                           to_file=tgt[0], to_line=tgt[1], resolved=True,
                                           name=callee))
        elif candidates:
            references.append(RawReference(kind="references", from_file=rel, from_line=line,
                                           to_file=rel, resolved=False, name=callee))

    return RawIngest(language="sql", root=str(root), symbols=symbols,
                     references=references, diagnostics=diagnostics, files=filelist)
