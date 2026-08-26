# src/lattice/exposure.py
"""Outbound boundary analysis — what's accessible to each external library.

A path that terminates in a third-party library isn't terminated, it's handed off:
the library's own paths (and flaws) become reachable from your code. You can't see
inside it, but you CAN read your own side of the boundary — the data and handles that
cross into it at the call site. That set is the bound: whatever flaw the library has,
its blast radius is capped by what's accessible to it from here. So a library trace
loss isn't an absence in the report; it's a bounded worst-case statement of reach,
readable with zero visibility into the library, actionable via least-privilege.

This is the dual of the inbound entrypoint check (what's asked for + is it bounded):
here it's what's reachable to the callee + is that access bounded at the handoff.
"""
from __future__ import annotations
import pathlib
import re
from dataclasses import dataclass, field

from lattice.graph.models import Hypernetwork
from lattice.security import (
    _capture_args, _split_args, _has_taint, _interprocedural_taint, _SANITIZERS,
)

_IMPORT = re.compile(r"^\s*import\s+(.+?)\s+from\s+['\"]([^'\"]+)['\"]", re.M)
_IDENT = re.compile(r"^[A-Za-z_$][\w$]*$")


@dataclass
class LibraryExposure:
    library: str                 # the external module a path hands off to
    callee: str                  # the imported name being called (e.g. spawn, path.join)
    location: str                # file:line of the handoff
    enclosing: str               # the function that makes the call
    accessible: list = field(default_factory=list)   # identifiers/data that cross over
    tainted: list = field(default_factory=list)       # accessible items carrying untrusted input

    def to_dict(self) -> dict:
        return {"library": self.library, "callee": self.callee, "location": self.location,
                "enclosing": self.enclosing, "accessible": self.accessible, "tainted": self.tainted}


def _imported_externals(text: str) -> dict[str, str]:
    """{local_name: module} for BARE-specifier imports only — relative imports are
    internal code the tool traces through, not a library boundary."""
    out: dict[str, str] = {}
    for m in _IMPORT.finditer(text):
        clause, mod = m.group(1).strip(), m.group(2)
        if mod.startswith(".") or mod.startswith("/"):
            continue                                  # relative -> internal
        names: list[str] = []
        brace = re.search(r"\{([^}]*)\}", clause)
        if brace:                                     # { a, b as c }
            for part in brace.group(1).split(","):
                local = part.strip().split(" as ")[-1].strip()
                if _IDENT.match(local):
                    names.append(local)
            clause = clause[:brace.start()] + clause[brace.end():]
        for part in clause.split(","):                # default name and/or `* as ns`
            part = part.strip()
            if part.startswith("*"):
                ns = part.split(" as ")[-1].strip()
                if _IDENT.match(ns):
                    names.append(ns)
            elif _IDENT.match(part):
                names.append(part)
        for n in names:
            out[n] = mod
    return out


def library_exposure(net: Hypernetwork, source_root) -> list[LibraryExposure]:
    """For every call into an external library, report what's accessible to it from
    that point (the crossing args/handles), flagging any that carry untrusted input."""
    root = pathlib.Path(source_root)
    tset, tainted_returns = _interprocedural_taint(net, source_root)

    file_text: dict[str, str] = {}

    def ftext(f: str) -> str:
        if f not in file_text:
            try:
                file_text[f] = (root / f).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                file_text[f] = ""
        return file_text[f]

    # imported external names per file (the library handoffs available in that file)
    externals: dict[str, dict[str, str]] = {}

    out: list[LibraryExposure] = []
    funcs = [v for v in net.vertices if v.kind in ("function", "method")]
    for v in funcs:
        text = ftext(v.file)
        if v.file not in externals:
            externals[v.file] = _imported_externals(text)
        names = externals[v.file]
        if not names:
            continue
        body = "\n".join(text.splitlines()[v.start_line - 1: v.end_line])
        tainted_here = tset.get(v.id, set())
        for name, mod in names.items():
            # a direct call `name(` or a namespace member call `name.method(`
            rx = re.compile(r"\b" + re.escape(name) + r"(?:\.\w+)?\s*\(")
            for m in rx.finditer(body):
                callee = body[m.start():m.end() - 1].strip()
                args = _capture_args(body, m.end() - 1)
                accessible = [a.strip() for a in _split_args(args) if a.strip()]
                if not accessible:
                    continue
                tainted = [a for a in accessible
                           if _has_taint(a, tainted_here, _SANITIZERS, tainted_returns)]
                line = v.start_line + body[:m.start()].count("\n")
                out.append(LibraryExposure(
                    library=mod, callee=callee, location=f"{v.file}:{line}",
                    enclosing=v.id, accessible=accessible, tainted=tainted))
    return out
