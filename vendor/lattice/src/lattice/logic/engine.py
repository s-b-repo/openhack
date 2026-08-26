# src/lattice/logic/engine.py
"""Exact propositional logic engine.

A proposition is a tree of tuples:
    ("atom", str) | ("not", expr) | ("and", e1, e2) | ("or", e1, e2)

Everything here is exact and finite: a truth table is an enumeration over the 2^n
assignments of the n atoms, and satisfiability/tautology/contradiction fall straight
out of it. No heuristics, no solver dependency.
"""
from __future__ import annotations
from itertools import product


def atoms(expr) -> set[str]:
    kind = expr[0]
    if kind == "atom":
        return {expr[1]}
    if kind == "const":                      # boolean literal has no free variable
        return set()
    if kind == "not":
        return atoms(expr[1])
    return atoms(expr[1]) | atoms(expr[2])


def evaluate(expr, env: dict[str, bool]) -> bool:
    kind = expr[0]
    if kind == "atom":
        return bool(env[expr[1]])
    if kind == "const":                      # literal true/false/0/1/null (parse.py)
        return bool(expr[1])
    if kind == "not":
        return not evaluate(expr[1], env)
    if kind == "and":
        return evaluate(expr[1], env) and evaluate(expr[2], env)
    if kind == "or":
        return evaluate(expr[1], env) or evaluate(expr[2], env)
    raise ValueError(f"unknown node: {expr!r}")


def truth_table(expr) -> list[tuple[dict, bool]]:
    names = sorted(atoms(expr))
    rows = []
    for combo in product([False, True], repeat=len(names)):
        env = dict(zip(names, combo))
        rows.append((env, evaluate(expr, env)))
    return rows


def analyze(expr) -> dict:
    results = [r for _, r in truth_table(expr)]
    satisfiable = any(results)
    return {
        "satisfiable": satisfiable,
        "tautology": all(results),
        "contradiction": not satisfiable,
        "atoms": sorted(atoms(expr)),
    }
