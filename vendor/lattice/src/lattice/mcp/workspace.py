# src/lattice/mcp/workspace.py
"""Workspace — the stateful, transport-agnostic cache behind every MCP tool.

Ingestion is the slow part (minutes on a real repo); the built graph answers every
analysis in milliseconds. So a Workspace ingests ONCE, persists the built graph under
`<root>/.lattice/`, and serves it on reload. It tracks an mtime snapshot of the source
tree so it can tell — with stat() calls only, no parsing — when the cache has gone
stale, and rebuild on demand.

Refresh is incremental for TypeScript (the existing LSP splice in incremental.py) and a
full re-ingest for every other language. Staleness *detection* is universal; only the
refresh *cost* differs.
"""
from __future__ import annotations

import json
import pathlib

from lattice.cache import _LANG_PROBES, detect_languages, ingest_source, normalize_language
from lattice.graph.builder import build
from lattice.graph.models import Hypernetwork

_CACHE_DIRNAME = ".lattice"
_PROBE = {lang: (pats, skip) for lang, pats, skip in _LANG_PROBES}
_PROBE["c"] = _PROBE["cpp"]  # explicit --lang c; auto keeps one combined C/C++ graph


class Workspace:
    """One repo's cached graph + staleness tracking. Construct on a root, call
    `ensure()` to load-or-build, `staleness()` to check drift, `refresh()` to rebuild."""

    def __init__(self, root, cache_dir=None):
        self.root = pathlib.Path(root).resolve()
        self.cache_dir = pathlib.Path(cache_dir) if cache_dir else self.root / _CACHE_DIRNAME
        self.net: Hypernetwork | None = None
        self.language: str = "auto"
        # Distinguish the default auto state from a caller that explicitly selected
        # auto (or another language). A failed explicit switch remains sticky so later
        # analysis calls cannot silently reload an older-language disk cache.
        self._language_selected = False

    # ---- paths ----
    @property
    def _graph_path(self) -> pathlib.Path:
        return self.cache_dir / "graph.json"

    @property
    def _snapshot_path(self) -> pathlib.Path:
        return self.cache_dir / "snapshot.json"

    # ---- source discovery (same definition of "source file" as ingest) ----
    def _languages(self) -> list[str]:
        if self.language not in ("auto", "mixed"):
            return [self.language]
        return detect_languages(self.root)

    def _source_files(self) -> dict[str, int]:
        """Source plus graph-affecting metadata as ``{relpath: mtime_ns}``."""
        out: dict[str, int] = {}
        for lang in self._languages():
            if lang in ("typescript", "javascript"):
                from lattice.ingest.lsp_client import _select_source_files
                for p in _select_source_files(self.root, lang):
                    out[p.relative_to(self.root).as_posix()] = p.stat().st_mtime_ns
                continue
            pats, skip = _PROBE.get(lang, ((), set()))
            for pat in pats:
                for p in self.root.rglob(pat):
                    if skip & set(p.relative_to(self.root).parts):
                        continue
                    if not p.is_file():
                        continue
                    out[p.relative_to(self.root).as_posix()] = p.stat().st_mtime_ns
        # package.json changes entrypoint surfaces; ts/js configs and native manifests
        # can change discovery/resolution without touching source bytes. They belong to
        # freshness even though they are not graph vertices themselves.
        from lattice.changeset import graph_metadata_files
        for p in graph_metadata_files(self.root):
            out[p.relative_to(self.root).as_posix()] = p.stat().st_mtime_ns
        return out

    # ---- cache I/O ----
    def _write_cache(self, files: dict[str, int]) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._graph_path.write_text(json.dumps(self.net.to_dict()))
        self._snapshot_path.write_text(json.dumps({"language": self.language, "files": files}))

    def _load_cache(self, requested_language: str | None = None) -> bool:
        if not (self._graph_path.is_file() and self._snapshot_path.is_file()):
            return False
        snap = json.loads(self._snapshot_path.read_text())
        cached_language = normalize_language(snap.get("language", "auto"))
        if requested_language is not None and cached_language != requested_language:
            return False
        self.net = Hypernetwork.from_dict(json.loads(self._graph_path.read_text()))
        self.language = cached_language
        return True

    # ---- build ----
    def _ingest(self) -> Hypernetwork:
        if self.language in ("auto", "mixed"):
            from lattice.cache import build_auto
            net, _ = build_auto(self.root)
            return net
        return build(ingest_source(self.root, self.language))

    # ---- public API ----
    def ensure(self, language: str | None = None) -> Hypernetwork:
        """Load a matching cache, else ingest + build + persist.

        ``None`` means "keep/load the workspace's selected language" for analysis tools
        that call ``ensure()`` after mapping. Passing a language, including ``"auto"``,
        is an explicit cache-key request and cannot reuse a graph built by another
        frontend.
        """
        explicit = language is not None
        requested = (normalize_language(language) if explicit
                     else self.language if self._language_selected else None)
        if self.net is not None:
            if requested is None or requested == self.language:
                if explicit:
                    self._language_selected = True
                return self.net
            self.net = None
        if explicit:
            self._language_selected = True
            self.language = requested
        if self._load_cache(requested):
            return self.net
        self.language = requested or "auto"
        self.net = self._ingest()
        self._write_cache(self._source_files())
        return self.net

    def staleness(self) -> dict:
        """{changed, added, removed} relative to the snapshot — stat() only, no parsing."""
        empty = {"changed": [], "added": [], "removed": []}
        if not self._snapshot_path.is_file():
            return empty
        recorded = json.loads(self._snapshot_path.read_text()).get("files", {})
        current = self._source_files()
        changed = sorted(f for f, m in current.items() if f in recorded and recorded[f] != m)
        added = sorted(f for f in current if f not in recorded)
        removed = sorted(f for f in recorded if f not in current)
        return {"changed": changed, "added": added, "removed": removed}

    def refresh(self) -> dict:
        """Rebuild the graph from the current source tree and reset the snapshot.

        TS routes through the incremental LSP splice; everything else is a full
        re-ingest. Returns {rebuilt, mode, changed, added, removed, stats}.
        """
        drift = self.staleness()
        # Ensure language is known (a fresh Workspace that only called refresh()).
        if self.net is None:
            self.ensure()
        mode = "full"
        self.net = self._ingest()
        self._write_cache(self._source_files())
        return {
            "rebuilt": True, "mode": mode,
            "changed": drift["changed"], "added": drift["added"], "removed": drift["removed"],
            "stats": self.net.stats,
        }
