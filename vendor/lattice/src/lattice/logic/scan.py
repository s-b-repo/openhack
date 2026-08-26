# src/lattice/logic/scan.py
"""Scan a source tree for paradoxical conditions (dead branches / redundant guards)."""
from __future__ import annotations
import pathlib

from lattice.logic.extract import extract_conditions
from lattice.logic.audit import audit_condition

_EXTS = {".ts", ".tsx", ".js", ".jsx"}


def scan_paradoxes(root) -> list[dict]:
    root = pathlib.Path(root).resolve()
    findings: list[dict] = []
    for p in sorted(root.rglob("*")):
        if p.suffix not in _EXTS or "node_modules" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line, cond in extract_conditions(text):
            f = audit_condition(cond, file=rel, line=line)
            if f:
                findings.append(f)
    return findings
