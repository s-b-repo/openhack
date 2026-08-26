# src/lattice/logic/parse.py
"""Tier-1 condition parser: a boolean condition string -> proposition tree.

Strategy: split at top-level `||` (lowest precedence), then `&&`, respecting paren
depth so operators inside `foo(a && b)` or `(a || b)` aren't split. A leading `!`
(not `!=`) is NOT. Everything else is an opaque atom — comparisons like `x > 5` and
function calls like `isReady(u)` are treated as single boolean variables.

This is propositional only: it sees `a && !a` as a contradiction, but treats
`x > 5` and `x < 3` as independent atoms (relational reasoning is a tier-2 concern).
When structure is ambiguous it degrades to a single atom, so it never invents a
paradox — uncertainty produces silence, not a false positive.
"""
from __future__ import annotations
import re

_WS = re.compile(r"\s+")


def _norm(s: str) -> str:
    return _WS.sub(" ", s.strip())


def _fully_wrapped(s: str) -> bool:
    if not (s.startswith("(") and s.endswith(")")):
        return False
    depth = 0
    for i, ch in enumerate(s):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i == len(s) - 1   # the opening paren closes only at the very end
    return False


def _split_top(s: str, op: str) -> list[str]:
    parts, depth, i, last = [], 0, 0, 0
    while i < len(s):
        ch = s[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and s[i:i + len(op)] == op:
            parts.append(s[last:i])
            i += len(op)
            last = i
            continue
        i += 1
    parts.append(s[last:])
    return [p for p in parts]


# Boolean literals recognized as constants (rather than opaque atoms). Extending this
# to the language's literal tokens closes the recall gap where `if (false)` was parsed
# as `("atom", "false")` and the analyzer couldn't tell it from a variable named
# `false` — so `if (false)` and `while (0)` produced neither a contradiction nor a
# tautology finding. `null`/`undefined`/`None` are ALSO boolean-false in JS/Python
# `if` guards (falsy), so a bare `if (null)` is a contradiction the same way.
_TRUE_LITERALS = {"true", "True", "TRUE", "1", "-1"}
_FALSE_LITERALS = {"false", "False", "FALSE", "0", "null", "undefined", "None"}


def parse(s: str):
    s = s.strip()
    while _fully_wrapped(s):
        s = s[1:-1].strip()

    for op, node in (("||", "or"), ("&&", "and")):
        parts = _split_top(s, op)
        if len(parts) > 1:
            tree = parse(parts[0])
            for p in parts[1:]:
                tree = (node, tree, parse(p))
            return tree

    if s.startswith("!") and not s.startswith("!="):
        # `!true` / `!1` collapses to a const; keeps the const propagation intact.
        inner = parse(s[1:])
        if inner and inner[0] == "const":
            return ("const", not inner[1])
        return ("not", inner)

    normed = _norm(s)
    if normed in _TRUE_LITERALS:
        return ("const", True)
    if normed in _FALSE_LITERALS:
        return ("const", False)
    return ("atom", normed)
