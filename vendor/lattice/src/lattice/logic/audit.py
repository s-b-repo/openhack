# src/lattice/logic/audit.py
"""Paradox audit over a single condition string.

A condition is a paradox if it is:
  - a CONTRADICTION  -> unsatisfiable -> the branch can never execute (dead code), or
  - a TAUTOLOGY      -> always true   -> the guard is redundant (the check is pointless).

Returns a finding dict, or None when the condition is contingent (normal). Because
the parser degrades to opaque atoms when unsure, this only fires on structurally
certain paradoxes — no false positives.
"""
from __future__ import annotations

from lattice.logic.parse import parse
from lattice.logic.engine import analyze


def audit_condition(condition: str, file: str | None = None, line: int | None = None):
    expr = parse(condition)
    a = analyze(expr)
    kind = None
    detail = None
    if a["contradiction"]:
        kind, detail = "contradiction", "branch can never be true (dead code)"
    elif a["tautology"]:
        kind, detail = "tautology", "guard is always true (redundant check)"
    if kind is None:
        return None
    return {
        "kind": kind,
        "condition": condition.strip(),
        "file": file,
        "line": line,
        "atoms": a["atoms"],
        "detail": detail,
    }
