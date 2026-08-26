# src/lattice/cache.py
"""Load a hypernetwork from a cached JSON artifact OR by ingesting a source tree.

Ingestion (the LSP pass) is the slow part — minutes on a real project. Every analysis
command (hunt, secaudit, impact, plan, diagnose, ...) only needs the *built graph*,
so an agent should ingest ONCE (`lattice ingest <dir> --out g.json`) and then run all
analyses against the cached `g.json` instantly. load_network() makes that transparent:
pass a `.json` cache and it loads in milliseconds; pass a directory and it ingests.

Source-dependent analyses (secaudit taint, paradox) recover the source root from the
cache (`net.root`), so they work from a cache too — no re-ingest required.
"""
from __future__ import annotations
import fnmatch
import json
import pathlib

from lattice.graph.models import Hypernetwork


class SourceIngestError(RuntimeError):
    """Base for expected, actionable source-frontend failures at public boundaries."""


class GraphIngestError(SourceIngestError):
    """A graph exists, but frontend errors make analysis unsafe to present as clean."""

    def __init__(self, path, report):
        self.path = pathlib.Path(path)
        self.report = report
        errors = [d for d in report.diagnostics
                  if str(d.get("severity", "error")).lower() == "error"]
        first = errors[0] if errors else {}
        where = first.get("file", "<project>")
        line = first.get("line", 1)
        detail = first.get("message", "frontend ingestion failed")
        extra = f" (+{len(errors) - 1} more error(s))" if len(errors) > 1 else ""
        super().__init__(
            f"graph ingestion failed for {self.path}: {where}:{line}: {detail}{extra}")


def _raise_on_ingest_errors(net: Hypernetwork, path) -> None:
    """Reject only gate-visible frontend errors; structural partial graphs remain usable."""
    from lattice.complete.gate import check

    report = check(net)
    if "ingest_diagnostics" in report.failing_checks:
        raise GraphIngestError(path, report)


# Short CLI/MCP codes -> canonical backend language names. The ingest backends and
# multilspy only know the canonical names, so every entry point normalizes first.
_LANG_ALIASES = {
    "ts": "typescript", "tsx": "typescript", "typescript": "typescript",
    "js": "javascript", "jsx": "javascript", "javascript": "javascript",
    "py": "python", "python": "python",
    "go": "go", "golang": "go",
    "rs": "rust", "rust": "rust",
    "rb": "ruby", "ruby": "ruby",
    "sol": "solidity", "solidity": "solidity",
    "cpp": "cpp", "cu": "cpp", "cuda": "cpp", "c": "c",
    "sh": "shell", "bash": "shell", "shell": "shell",
    "sql": "sql",
    "iac": "iac", "docker": "iac",
    "auto": "auto", "mixed": "auto", "multi": "auto",
}


def normalize_language(language: str) -> str:
    """Map a short code (`ts`, `py`, `sol`, ...) to the canonical backend name. Unknown
    values pass through unchanged so a new backend works before it's aliased here."""
    return _LANG_ALIASES.get(language, language)


def ingest_source(root, language: str = "typescript"):
    """Dispatch to the right ingest backend by language — all yield the same RawIngest, so
    the builder and every analysis are language-agnostic downstream. The whole point: to
    handle a new language you add ONE frontend here, nothing else changes."""
    language = normalize_language(language)
    if language in ("auto", "mixed"):
        raise SourceIngestError(
            "language='auto' is a graph-level operation, not one RawIngest frontend; "
            "use build_auto(), build_source(), or load_network()"
        )
    if language == "solidity":
        from lattice.ingest.solidity import solidity_ingest
        return solidity_ingest(root, language)
    if language == "python":
        from lattice.ingest.python_ast import python_ingest
        return python_ingest(root, language)
    if language == "go":
        from lattice.ingest.go_graph import go_ingest
        return go_ingest(root, language)
    if language == "rust":
        from lattice.ingest.rust_graph import rust_ingest
        return rust_ingest(root, language)
    if language == "ruby":
        from lattice.ingest.ruby_graph import ruby_ingest
        return ruby_ingest(root, language)
    if language in ("cpp", "c"):
        from lattice.ingest.cpp import cpp_ingest
        return cpp_ingest(root, language)
    if language == "shell":
        from lattice.ingest.shell import shell_ingest
        return shell_ingest(root, language)
    if language == "sql":
        from lattice.ingest.sql import sql_ingest
        return sql_ingest(root, language)
    if language == "iac":
        from lattice.ingest.iac import iac_ingest
        return iac_ingest(root, language)
    from lattice.ingest.lsp_client import ingest
    return ingest(root, language)


# extension globs -> backend language, with the dirs that are never source for it
_LANG_PROBES = (
    ("typescript", ("*.ts", "*.tsx"), {"node_modules", "dist", "build", "out"}),
    ("javascript", ("*.js", "*.jsx", "*.mjs", "*.cjs"), {"node_modules", "dist", "build", "out"}),
    ("solidity", ("*.sol",), {"node_modules", "out", "lib", "cache"}),
    ("python", ("*.py",), {".venv", "venv", "site-packages", "node_modules", "__pycache__"}),
    ("go", ("*.go",), {"vendor", "testdata", "node_modules"}),
    ("rust", ("*.rs",), {"target", "vendor", "node_modules"}),
    ("ruby", ("*.rb",), {"vendor", ".bundle", "node_modules"}),
    ("cpp", ("*.c", "*.cpp", "*.cc", "*.cxx", "*.cu", "*.cuh", "*.h", "*.hpp", "*.hh", "*.hxx"),
     {"node_modules", "build", "dist", "out", "third_party", "extern"}),
    ("shell", ("*.sh", "*.bash"), {"node_modules", ".git", "vendor"}),
    ("sql", ("*.sql",), {"node_modules", ".git"}),
    ("iac", ("Dockerfile*", "*.dockerfile"), {"node_modules", ".git"}),
)


def detect_languages(root) -> list[str]:
    """Which source languages a directory actually contains (excluding deps/build output).
    This is how the tool 'sees' what code is there instead of being told."""
    root = pathlib.Path(root)
    if root.is_file():
        return [lang for lang, patterns, _skip in _LANG_PROBES
                if any(fnmatch.fnmatch(root.name, pattern) for pattern in patterns)]
    found: list[str] = []
    for lang, pats, skip in _LANG_PROBES:
        if lang in ("typescript", "javascript"):
            from lattice.ingest.lsp_client import _select_source_files
            if _select_source_files(root, lang):
                found.append(lang)
            continue
        for pat in pats:
            if any(not (skip & set(p.relative_to(root).parts)) for p in root.rglob(pat)):
                found.append(lang)
                break
    return found


def _merge(nets: list[Hypernetwork]) -> Hypernetwork:
    """Union several language graphs into one. Vertex ids are language-prefixed so they
    can't collide; edge ids are namespaced per-graph on merge to stay unique."""
    from dataclasses import replace
    if len(nets) == 1:
        return nets[0]
    vs, es, ss, diagnostics = [], [], [], []
    for i, n in enumerate(nets):
        vs += n.vertices
        es += [replace(e, id=f"g{i}:{e.id}") for e in n.hyperedges]
        ss += [replace(s, id=f"g{i}:{s.id}") for s in n.surfaces]
        diagnostics += n.diagnostics
    return Hypernetwork(language="mixed", root=nets[0].root, vertices=vs,
                        hyperedges=es, surfaces=ss, diagnostics=diagnostics)


def build_auto(root) -> tuple[Hypernetwork, list[str]]:
    """Detect every source language present and ingest each into one unified graph —
    'handle any code it sees'. Returns (merged_network, languages_handled)."""
    from lattice.graph.builder import build
    root = pathlib.Path(root)
    langs = detect_languages(root)
    nets = [build(ingest_source(root, lang)) for lang in langs]
    if not nets:
        return Hypernetwork(language="mixed", root=str(root), vertices=[],
                            hyperedges=[], surfaces=[], diagnostics=[{
                                "kind": "no_source_files", "language": "auto",
                                "file": "<project>", "line": 1, "severity": "error",
                                "message": f"no supported source files were found under {root}",
                            }]), []
    return _merge(nets), langs


def build_source(root, language: str = "typescript") -> Hypernetwork:
    """Build one concrete frontend or the graph-level auto-detected union."""
    language = normalize_language(language)
    if language in ("auto", "mixed"):
        return build_auto(root)[0]
    from lattice.graph.builder import build
    return build(ingest_source(root, language))


def load_network(path, language: str = "typescript") -> tuple[Hypernetwork, pathlib.Path]:
    """Return (hypernetwork, source_root). A `.json` path loads the cache; a directory
    ingests + builds it fresh. language='auto' detects and handles every language present."""
    p = pathlib.Path(path)
    if p.is_file() and p.suffix == ".json":
        net = Hypernetwork.from_dict(json.loads(p.read_text()))
        _raise_on_ingest_errors(net, p)
        return net, pathlib.Path(net.root)

    root = p.resolve()
    net = build_source(root, language)
    _raise_on_ingest_errors(net, root)
    return net, pathlib.Path(net.root)
