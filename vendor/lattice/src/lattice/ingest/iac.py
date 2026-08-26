# src/lattice/ingest/iac.py
"""IaC ingest backend — the deployment boundary (Dockerfile to start).

The boundary model fits infrastructure unusually well: a base image (`FROM`) is an
OUTBOUND dependency (supply chain — code you didn't write running as you), a build stage
is a unit, `EXPOSE` is an INBOUND boundary (a port the world can reach), and `RUN` is a
command-exec sink. This frontend captures the structure — stages and their base-image
dependencies — so the same boundary/blindspots analyses see the deploy surface, not just
the source. (Compose / K8s / Terraform are the same shape and the natural next formats.)
"""
from __future__ import annotations
import pathlib
import re

from lattice.ingest.types import RawIngest, RawSymbol, RawReference

_SKIP = {"node_modules", ".git", "dist", "build"}
_FROM = re.compile(
    r"^\s*FROM(?:\s+--platform=\S+)?\s+(\S+)(?:\s+AS\s+([A-Za-z0-9_.-]+))?",
    re.I,
)
_FROM_PREFIX = re.compile(r"^\s*FROM\b", re.I)
_EXPOSE = re.compile(r"^\s*EXPOSE\s+(\d+)", re.I)


def _is_dockerfile(p: pathlib.Path) -> bool:
    n = p.name.lower()
    return n == "dockerfile" or n.startswith("dockerfile.") or n.endswith(".dockerfile")


def iac_ingest(root, language: str = "iac") -> RawIngest:
    requested = pathlib.Path(root)
    diagnostics: list[dict] = []
    if requested.is_file():
        root = requested.parent
        supported = _is_dockerfile(requested)
        files = [requested] if supported else []
        if not supported:
            diagnostics.append({
                "kind": "unsupported_file", "severity": "error", "language": "iac",
                "file": requested.name,
                "message": "IaC ingestion currently requires a Dockerfile filename",
            })
    else:
        root = requested
        files = sorted(p for p in root.rglob("*")
                       if p.is_file() and _is_dockerfile(p)
                       and not (_SKIP & set(p.relative_to(root).parts)))
    if not files and not diagnostics:
        diagnostics.append({
            "kind": "no_source_files", "severity": "error", "language": "iac",
            "file": "<project>",
            "message": "no Dockerfile source files were found",
        })

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    filelist: list[str] = []

    for path in files:
        rel = path.relative_to(root).as_posix()
        filelist.append(rel)
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            diagnostics.append({
                "kind": "read_error", "severity": "error", "language": "iac",
                "file": rel, "message": str(exc),
            })
            continue
        stages: dict[str, int] = {}        # stage name -> line (for internal FROM refs)
        valid_from = 0

        for i, line in enumerate(lines, 1):
            m = _FROM.match(line)
            if m is None and _FROM_PREFIX.match(line):
                diagnostics.append({
                    "kind": "parse_error", "severity": "error", "language": "iac",
                    "file": rel, "line": i, "message": "malformed FROM instruction",
                })
            if m:
                valid_from += 1
                base, alias = m.group(1), m.group(2)
                name = alias or base.split("/")[-1].split(":")[0]
                symbols.append(RawSymbol(name=name, kind="function", file=rel,
                                         start_line=i, end_line=i, exported=True))
                # the base: an internal prior stage, or an OUTBOUND external image (supply chain)
                prior_stage = stages.get(base.lower())
                if prior_stage is not None:
                    references.append(RawReference(kind="references", from_file=rel, from_line=i,
                                                   to_file=rel, to_line=prior_stage, resolved=True,
                                                   name=base))
                else:
                    references.append(RawReference(kind="references", from_file=rel, from_line=i,
                                                   to_file=None, resolved=False,
                                                   name=base))   # external image
                if alias:
                    stages[alias.lower()] = i
            em = _EXPOSE.match(line)
            if em:
                symbols.append(RawSymbol(name=f"EXPOSE:{em.group(1)}", kind="variable",
                                         file=rel, start_line=i, end_line=i, exported=True))
        if valid_from == 0:
            diagnostics.append({
                "kind": "parse_error", "severity": "error", "language": "iac",
                "file": rel, "line": 1,
                "message": "Dockerfile has no valid FROM instruction",
            })

    return RawIngest(language="iac", root=str(root), symbols=symbols,
                     references=references, diagnostics=diagnostics, files=filelist)
