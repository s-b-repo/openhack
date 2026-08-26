# src/lattice/logic/extract.py
"""Best-effort extraction of boolean conditions from source text.

Finds `if (...)` / `else if (...)` / `while (...)` guards via balanced-paren capture
(so nested function calls and grouping parens inside the condition are preserved).
Tier-1: does not handle ternaries, `&&`/`||` outside guards, or multi-line conditions
beyond what the paren scan spans. Returns (1-based line, condition string) pairs.
"""
from __future__ import annotations
import re

_GUARD = re.compile(r"\b(?:if|while)\s*\(")


def extract_conditions(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for m in _GUARD.finditer(text):
        open_paren = m.end() - 1
        depth = 0
        i = open_paren
        while i < len(text):
            c = text[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    cond = text[open_paren + 1:i].strip()
                    line = text.count("\n", 0, m.start()) + 1
                    if cond:
                        out.append((line, cond))
                    break
            i += 1
    return out
