# src/lattice/registry.py
"""name@version@language graph registry — making library linking automatic.

A library's graph is computed once and stored addressed by `name@version@language`.
A host then links automatically: resolve each imported package to its INSTALLED version
(read from node_modules — the exact fact, not the package.json `^range`), look up that
exact language graph in the registry, and join it so reachability/taint follow through.
The dependency tree becomes a graph of graphs, joined by reference — "write once,
reference" at ecosystem scale. A package not in the registry stays an honest trace loss
(blindspots reports it).
"""
from __future__ import annotations
import json
import pathlib
from dataclasses import dataclass, field

from lattice.graph.models import Hypernetwork
from lattice.compose import link
from lattice.exposure import library_exposure


def gate_failure_reason(net: Hypernetwork) -> str | None:
    """Machine-readable refusal reason for a graph that fails completeness."""
    from lattice.complete.gate import check

    report = check(net)
    if report.verdict != "fail":
        return None
    payload = {
        "verdict": report.verdict,
        "failing_checks": list(report.failing_checks),
        # Do not filter warnings: when an error rejects a graph, adjacent frontend
        # warnings remain part of the evidence needed to repair the package.
        "diagnostics": list(report.diagnostics),
    }
    return f"graph gate failed: {json.dumps(payload, sort_keys=True)}"


class GraphRegistryGateError(ValueError):
    """Raised when a failed completeness graph is offered to the registry."""


class GraphRegistryIdentityError(ValueError):
    """Raised when the requested registry language contradicts the graph."""


_REGISTRY_META_KEY = "_registry"
_REGISTRY_SCHEMA = 1


def _canonical_language(language: str) -> str:
    """Registry identity uses the same canonical names as frontend dispatch."""
    from lattice.cache import normalize_language

    return normalize_language(language)


def _safe_component(value: str) -> str:
    """Keep a registry identity in one portable filename component."""
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


class GraphRegistry:
    """Precomputed library graphs addressed by name@version@canonical-language.

    ``language`` remains optional on the public methods for compatibility. A bare lookup
    succeeds only when exactly one language graph exists; it never selects arbitrarily
    once a package/version has graphs for multiple frontends. Legacy name@version JSON
    files remain readable when their graph language matches the requested language.
    """

    def __init__(self, root):
        self.root = pathlib.Path(root)

    def _path(self, name: str, version: str,
              language: str | None = None) -> pathlib.Path:
        # scoped names contain '/': @scope/pkg -> @scope__pkg so it's one flat file
        safe = name.replace("/", "__")
        identity = f"{safe}@{version}"
        if language is not None:
            identity += f"--{_safe_component(_canonical_language(language))}"
        return self.root / f"{identity}.json"

    def _candidate_paths(self, name: str, version: str) -> list[pathlib.Path]:
        """Qualified entries first, followed by the old unqualified cache path."""
        legacy = self._path(name, version)
        prefix = legacy.name[:-len(".json")] + "--"
        qualified = []
        if self.root.is_dir():
            qualified = sorted(
                path for path in self.root.iterdir()
                if path.is_file() and path.name.startswith(prefix)
                and path.name.endswith(".json")
            )
        return qualified + ([legacy] if legacy.is_file() else [])

    @staticmethod
    def _read_entry(path: pathlib.Path, name: str,
                    version: str) -> tuple[Hypernetwork, str] | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                return None
            net = Hypernetwork.from_dict(payload)
        except (OSError, TypeError, ValueError, KeyError):
            return None

        metadata = payload.get(_REGISTRY_META_KEY)
        if isinstance(metadata, dict):
            # A renamed/copied cache must not impersonate a different package identity.
            if metadata.get("name", name) != name or metadata.get("version", version) != version:
                return None
            stored_language = metadata.get("language")
        else:
            stored_language = None
        if not isinstance(stored_language, str) or not stored_language:
            stored_language = net.language
        stored_language = _canonical_language(stored_language)
        graph_language = _canonical_language(net.language)
        requested_language = metadata.get("requested_language") \
            if isinstance(metadata, dict) else None
        requested_language = (_canonical_language(requested_language)
                              if isinstance(requested_language, str) else None)
        # Reject mislabeled artifacts. The sole compatibility exception is the prior
        # auto-single format: an auto request could be stored under ``--auto`` even
        # though the graph itself records its one concrete frontend.
        if stored_language != graph_language and not (
                stored_language == "auto" and requested_language == "auto"):
            return None
        return net, stored_language

    def has(self, name: str, version: str, language: str | None = None) -> bool:
        if language is not None:
            return self.get(name, version, language) is not None
        # Preserve the old "does any graph exist?" meaning for callers that do not yet
        # provide a language, while still ignoring unreadable/misidentified artifacts.
        return any(self._read_entry(path, name, version) is not None
                   for path in self._candidate_paths(name, version))

    def put(self, name: str, version: str, net: Hypernetwork,
            language: str | None = None) -> None:
        failure = gate_failure_reason(net)
        if failure is not None:
            raise GraphRegistryGateError(failure)
        requested_language = _canonical_language(language or net.language)
        graph_language = _canonical_language(net.language)
        if requested_language != "auto" and requested_language != graph_language:
            raise GraphRegistryIdentityError(
                f"registry language {requested_language!r} does not match "
                f"graph language {graph_language!r}")
        # Auto over a single detected frontend returns that concrete graph unchanged.
        # Store it under the concrete identity so a matching host can link it; a truly
        # mixed auto graph remains isolated under ``auto``.
        identity_language = (graph_language
                             if requested_language == "auto" and graph_language != "auto"
                             else requested_language)
        self.root.mkdir(parents=True, exist_ok=True)
        payload = net.to_dict()
        payload[_REGISTRY_META_KEY] = {
            "schema": _REGISTRY_SCHEMA,
            "name": name,
            "version": version,
            "language": identity_language,
            "requested_language": requested_language,
            "graph_language": net.language,
        }
        self._path(name, version, identity_language).write_text(
            json.dumps(payload), encoding="utf-8")

    def get(self, name: str, version: str,
            language: str | None = None) -> Hypernetwork | None:
        requested = _canonical_language(language) if language is not None else None
        entries: list[tuple[Hypernetwork, str]] = []
        for path in self._candidate_paths(name, version):
            entry = self._read_entry(path, name, version)
            if entry is None:
                continue
            entries.append(entry)

        if requested is not None:
            # Exact requested identities always win (especially a truly mixed `auto`).
            exact: dict[str, Hypernetwork] = {}
            for net, stored_language in entries:
                if stored_language == requested:
                    exact.setdefault(stored_language, net)
            if requested in exact:
                return exact[requested]

            if requested == "auto":
                # With no mixed graph, auto and a sole concrete graph are equivalent.
                concrete: dict[str, Hypernetwork] = {}
                for net, _stored_language in entries:
                    graph_language = _canonical_language(net.language)
                    if graph_language != "auto":
                        concrete.setdefault(graph_language, net)
                return next(iter(concrete.values())) if len(concrete) == 1 else None

            # Backward compatibility: older versions stored auto-single graphs under
            # `--auto`; their graph language still proves the concrete identity.
            auto_single = [net for net, stored_language in entries
                           if stored_language == "auto"
                           and _canonical_language(net.language) == requested]
            return auto_single[0] if len(auto_single) == 1 else None

        # A language-free lookup remains safe when old auto-single and new concrete
        # entries coexist: group both by the effective graph language.
        matches: dict[str, Hypernetwork] = {}
        for net, stored_language in entries:
            graph_language = _canonical_language(net.language)
            effective = graph_language if graph_language != "auto" else stored_language
            matches.setdefault(effective, net)
        if len(matches) == 1:
            return next(iter(matches.values()))
        return None


_NODE_BUILTINS = {"fs", "path", "os", "crypto", "http", "https", "child_process", "util",
                  "stream", "events", "url", "querystring", "zlib", "net", "tls", "dns"}


def _package_of(specifier: str) -> str | None:
    """The installable package a bare import specifier belongs to. Node builtins (and
    `node:` imports) have no graph -> None. `@scope/pkg/sub` -> `@scope/pkg`; `lib/x` -> `lib`."""
    if specifier.startswith("node:") or specifier in _NODE_BUILTINS:
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else specifier
    return parts[0]


def installed_version(source_root, package: str) -> str | None:
    """The EXACT installed version from node_modules/<package>/package.json — the fact,
    not the package.json `^range`."""
    pj = pathlib.Path(source_root) / "node_modules" / package / "package.json"
    try:
        return json.loads(pj.read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError):
        return None


def _has_ts_source(pkg_dir: pathlib.Path) -> bool:
    """A package is ingestable if it ships any .ts/.tsx (incl. .d.ts declarations — enough
    for the inbound surface + contract verification), not just compiled .js."""
    return any(p for pat in ("*.ts", "*.tsx")
               for p in pkg_dir.rglob(pat)
               if "node_modules" not in p.relative_to(pkg_dir).parts)


def _has_ingestable_source(pkg_dir: pathlib.Path, language: str) -> bool:
    """Whether ``pkg_dir`` contains source for the selected canonical frontend."""
    from lattice.cache import _LANG_PROBES, detect_languages, normalize_language

    language = normalize_language(language)
    if language == "auto":
        return bool(detect_languages(pkg_dir))
    if language == "typescript":
        return _has_ts_source(pkg_dir)
    if language == "javascript":
        from lattice.ingest.lsp_client import _select_source_files
        return bool(_select_source_files(pkg_dir, language))
    probe_language = "cpp" if language == "c" else language
    for lang, patterns, skip in _LANG_PROBES:
        if lang != probe_language:
            continue
        return any(
            p.is_file() and not (skip & set(p.relative_to(pkg_dir).parts))
            for pattern in patterns for p in pkg_dir.rglob(pattern)
        )
    return False


def populate_from_project(project_root, registry: GraphRegistry,
                          language: str = "typescript", include_dev: bool = False) -> dict:
    """Index each installed dependency that ships ingestable source into the registry,
    addressed by name@version@language. Per-package isolation (one failure doesn't abort
    the run); dependencies without selected-language source are reported as skipped."""
    from lattice.cache import build_source, normalize_language

    root = pathlib.Path(project_root)
    language = normalize_language(language)
    try:
        pj = json.loads((root / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"added": [], "skipped_no_source": [], "failed": [("<project>", "no package.json")]}
    deps = dict(pj.get("dependencies", {}))
    if include_dev:
        deps.update(pj.get("devDependencies", {}))

    report = {"added": [], "skipped_no_source": [], "failed": []}
    for name in sorted(deps):
        pkg_dir = root / "node_modules" / name           # pathlib handles scoped '@a/b'
        if not pkg_dir.exists():
            report["failed"].append((name, "not installed"))
            continue
        version = installed_version(root, name)
        if version is None:
            report["failed"].append((name, "no version in package.json"))
            continue
        if registry.has(name, version, language):
            report["added"].append((name, version, "cached"))
            continue
        if not _has_ingestable_source(pkg_dir, language):
            report["skipped_no_source"].append(name)
            continue
        try:
            net = build_source(pkg_dir, language)
            failure = gate_failure_reason(net)
            if failure is not None:
                report["failed"].append((name, failure))
                continue
            registry.put(name, version, net, language)
            report["added"].append((name, version, len(net.vertices)))
        except Exception as e:                            # isolate: one bad dep != abort
            report["failed"].append((name, str(e)[:80]))
    return report


@dataclass
class LinkReport:
    linked: list = field(default_factory=list)        # (package, version) joined from registry
    missing: list = field(default_factory=list)       # (package, version) installed, not in registry
    unresolved: list = field(default_factory=list)    # imported, no installed version found

    def to_dict(self) -> dict:
        return {"linked": self.linked, "missing": self.missing, "unresolved": self.unresolved}


def link_auto(host: Hypernetwork, source_root, registry: GraphRegistry):
    """Resolve every library the host calls to its installed version, link the graphs the
    registry has, and report the rest. Returns (composed_network, LinkReport)."""
    libs: dict = {}
    report = LinkReport()
    seen: set = set()
    for specifier in sorted({e.library for e in library_exposure(host, source_root)}):
        pkg = _package_of(specifier)
        if pkg is None:
            continue                                  # builtin -> no graph expected
        if specifier in seen:
            continue
        seen.add(specifier)
        version = installed_version(source_root, pkg)
        if version is None:
            report.unresolved.append(specifier)
            continue
        g = registry.get(pkg, version, host.language)
        if g is None:
            if (pkg, version) not in report.missing:
                report.missing.append((pkg, version))
            continue
        libs[specifier] = g
        if (pkg, version) not in report.linked:
            report.linked.append((pkg, version))
    composed = link(host, source_root, libs)
    return composed, report
