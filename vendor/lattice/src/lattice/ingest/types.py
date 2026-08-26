# src/lattice/ingest/types.py
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class RawSymbol:
    name: str
    kind: str                 # LSP-derived symbol kind, lowercased
    file: str                 # path relative to root
    start_line: int
    end_line: int
    container: str | None = None   # enclosing symbol name, if any
    type: str | None = None        # declared type / signature, if LSP exposes it
    exported: bool = False
    is_stub: bool = False          # empty body / TODO / "not implemented"
    params: list = field(default_factory=list)   # param names (rest kept as "...name")
    extends: list = field(default_factory=list)      # base type names (extends ...)
    implements: list = field(default_factory=list)   # interface names (implements ...)


@dataclass
class RawReference:
    kind: str                 # "imports" | "calls" | "references"
    from_file: str
    from_line: int
    to_file: str | None = None
    to_line: int | None = None
    resolved: bool = False
    name: str | None = None   # callee name, for the builder's shared name-resolution pass
                              # (recovers call/dispatch edges a frontend left unresolved)
    allow_name_match: bool = True  # False when syntax already bounds identity/scope and
                                   # a bare-name fallback could cross-wire another symbol


@dataclass
class RawIngest:
    language: str
    root: str
    symbols: list[RawSymbol] = field(default_factory=list)
    references: list[RawReference] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    entry_files: set[str] = field(default_factory=set)   # program entrypoints (shebang/bin)
