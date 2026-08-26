import json, pathlib
import pytest
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.graph.query import GraphView
from lattice.registry import GraphRegistry, GraphRegistryIdentityError, link_auto


def _lib():
    return Hypernetwork(language="ts", root="/libx", vertices=[
        Vertex(id="lx:i#danger", kind="function", name="danger", exported=True,
               file="i.ts", start_line=1, end_line=2),
        Vertex(id="lx:i#runShell", kind="function", name="runShell",
               file="i.ts", start_line=3, end_line=4),
    ], hyperedges=[Hyperedge(id="e", kind="references",
                             members=["lx:i#danger", "lx:i#runShell"],
                             directed=True, resolved=True)], surfaces=[])


def test_registry_stores_and_retrieves_by_name_version(tmp_path):
    """A library graph is written once, addressed by name@version, retrieved by reference
    — incl. scoped packages whose names contain a slash."""
    reg = GraphRegistry(tmp_path / "reg")
    reg.put("@scope/libx", "1.2.3", _lib())
    assert reg.has("@scope/libx", "1.2.3")
    got = reg.get("@scope/libx", "1.2.3")
    assert got is not None and any(v.name == "danger" for v in got.vertices)
    assert reg.get("@scope/libx", "9.9.9") is None       # wrong version -> miss


def test_registry_reads_legacy_unqualified_cache_only_for_matching_language(tmp_path):
    """Pre-language registry artifacts stay readable without cross-language reuse."""
    root = tmp_path / "reg"
    root.mkdir()
    root.joinpath("libx@1.0.0.json").write_text(json.dumps(_lib().to_dict()))
    reg = GraphRegistry(root)

    assert reg.has("libx", "1.0.0")
    assert reg.get("libx", "1.0.0") is not None
    assert reg.get("libx", "1.0.0", language="ts") is not None
    assert reg.get("libx", "1.0.0", language="python") is None


def test_registry_rejects_requested_language_that_contradicts_graph(tmp_path):
    reg = GraphRegistry(tmp_path / "reg")

    with pytest.raises(GraphRegistryIdentityError, match="does not match"):
        reg.put("libx", "1.0.0", _lib(), language="go")

    assert not reg.has("libx", "1.0.0")


def test_link_auto_resolves_installed_version_and_links(tmp_path):
    """Auto-link: read the host's INSTALLED version from node_modules, look up that exact
    graph in the registry, and join it so reachability crosses. Report what linked."""
    host_dir = tmp_path / "host"
    (host_dir / "node_modules" / "libx").mkdir(parents=True)
    (host_dir / "node_modules" / "libx" / "package.json").write_text(
        json.dumps({"name": "libx", "version": "1.0.0"}))
    (host_dir / "app.ts").write_text(
        "import { danger } from 'libx'\n"
        "export function run(x: string) {\n  danger(x)\n}\n")
    host = Hypernetwork(language="ts", root=str(host_dir), vertices=[
        Vertex(id="ts:app.ts#run", kind="function", name="run", exported=True,
               file="app.ts", start_line=2, end_line=4),
        Vertex(id="ts:app.ts", kind="module", name="app.ts", file="app.ts",
               start_line=1, end_line=4),
    ], hyperedges=[], surfaces=[])

    reg = GraphRegistry(tmp_path / "reg")
    reg.put("libx", "1.0.0", _lib())

    composed, report = link_auto(host, str(host_dir), reg)
    assert ("libx", "1.0.0") in report.linked, report
    reach = GraphView(composed).reachable_from("ts:app.ts#run")
    assert any("runShell" in r for r in reach), f"auto-link did not cross: {reach}"


def test_link_auto_treats_graph_merge_multi_as_auto_identity(tmp_path):
    """Composed same-language hosts must retain concrete registry dependencies."""
    from lattice.graph.merge import merge

    host_dir = tmp_path / "host"
    (host_dir / "node_modules" / "libx").mkdir(parents=True)
    (host_dir / "node_modules" / "libx" / "package.json").write_text(
        json.dumps({"version": "1.0.0"}))
    (host_dir / "app.ts").write_text(
        "import { danger } from 'libx'\n"
        "export function run(x: string) { danger(x) }\n")
    ts_host = Hypernetwork(language="ts", root=str(host_dir), vertices=[
        Vertex(id="ts:app.ts#run", kind="function", name="run", exported=True,
               file="app.ts", start_line=2, end_line=2),
        Vertex(id="ts:app.ts", kind="module", name="app.ts", file="app.ts",
               start_line=1, end_line=2),
    ], hyperedges=[], surfaces=[])
    host = merge([ts_host], root=str(host_dir))
    assert host.language == "multi"

    reg = GraphRegistry(tmp_path / "reg")
    reg.put("libx", "1.0.0", _lib())
    _composed, report = link_auto(host, host_dir, reg)

    assert report.linked == [("libx", "1.0.0")]
    assert report.missing == []


def test_link_auto_reports_missing_library_as_trace_loss(tmp_path):
    """A library installed but NOT in the registry stays an honest trace loss."""
    host_dir = tmp_path / "host"
    (host_dir / "node_modules" / "libx").mkdir(parents=True)
    (host_dir / "node_modules" / "libx" / "package.json").write_text(
        json.dumps({"version": "2.0.0"}))
    (host_dir / "app.ts").write_text(
        "import { danger } from 'libx'\n"
        "export function run(x: string) {\n  danger(x)\n}\n")
    host = Hypernetwork(language="ts", root=str(host_dir), vertices=[
        Vertex(id="ts:app.ts#run", kind="function", name="run", exported=True,
               file="app.ts", start_line=2, end_line=4),
        Vertex(id="ts:app.ts", kind="module", name="app.ts", file="app.ts",
               start_line=1, end_line=4),
    ], hyperedges=[], surfaces=[])
    composed, report = link_auto(host, str(host_dir), GraphRegistry(tmp_path / "reg"))
    assert ("libx", "2.0.0") in report.missing and not report.linked


@pytest.mark.integration
def test_populate_from_project_indexes_ts_deps_and_skips_js_only(tmp_path):
    """Auto-populate: ingest each installed dependency that ships ingestable source, store
    by name@version. A JS-only dep (no .ts/.d.ts) is skipped and REPORTED, never silently."""
    from lattice.registry import populate_from_project
    proj = tmp_path / "proj"
    proj.mkdir()
    proj.joinpath("package.json").write_text(json.dumps(
        {"dependencies": {"tslibx": "1.0.0", "jsonly": "2.0.0"}}))
    tsx = proj / "node_modules" / "tslibx"
    tsx.mkdir(parents=True)
    tsx.joinpath("package.json").write_text(json.dumps({"version": "1.0.0"}))
    tsx.joinpath("index.ts").write_text("export function go(x: string): string { return x }\n")
    js = proj / "node_modules" / "jsonly"
    js.mkdir(parents=True)
    js.joinpath("package.json").write_text(json.dumps({"version": "2.0.0"}))
    js.joinpath("index.js").write_text("module.exports.f = () => 1\n")

    reg = GraphRegistry(tmp_path / "reg")
    report = populate_from_project(proj, reg)
    assert reg.has("tslibx", "1.0.0"), report
    assert "jsonly" in report["skipped_no_source"], report


def test_populate_native_dependency_uses_central_dispatcher(tmp_path, monkeypatch):
    from lattice import cache
    from lattice.ingest.types import RawIngest, RawSymbol
    from lattice.registry import populate_from_project

    proj = tmp_path / "proj"
    pkg = proj / "node_modules" / "golib"
    pkg.mkdir(parents=True)
    proj.joinpath("package.json").write_text(json.dumps({"dependencies": {"golib": "1.0.0"}}))
    pkg.joinpath("package.json").write_text(json.dumps({"version": "1.0.0"}))
    pkg.joinpath("lib.go").write_text("package golib\nfunc Run() {}\n")
    calls = []

    def fake_dispatch(root, language):
        calls.append((pathlib.Path(root).name, language))
        return RawIngest(
            language=language, root=str(root), files=["lib.go"],
            symbols=[RawSymbol("Run", "function", "lib.go", 2, 2, exported=True)],
        )

    monkeypatch.setattr(cache, "ingest_source", fake_dispatch)
    reg = GraphRegistry(tmp_path / "reg")
    report = populate_from_project(proj, reg, language="go")
    assert report["failed"] == [] and reg.has("golib", "1.0.0")
    assert calls == [("golib", "go")]


def test_cli_registry_add_native_uses_central_dispatcher(tmp_path, monkeypatch):
    from lattice import cache
    from lattice.cli import main as cli
    from lattice.ingest.types import RawIngest, RawSymbol

    pkg = tmp_path / "golib"
    pkg.mkdir()
    pkg.joinpath("lib.go").write_text("package golib\nfunc Run() {}\n")
    calls = []

    def fake_dispatch(root, language):
        calls.append(language)
        return RawIngest(
            language=language, root=str(root), files=["lib.go"],
            symbols=[RawSymbol("Run", "function", "lib.go", 2, 2, exported=True)],
        )

    monkeypatch.setattr(cache, "ingest_source", fake_dispatch)
    rc = cli.main([
        "registry-add", str(pkg), "--registry", str(tmp_path / "reg"),
        "--name", "golib", "--version", "1.0.0", "--lang", "go",
    ])
    assert rc == 0 and calls == ["go"]


def test_public_registry_put_refuses_failed_gate_and_preserves_diagnostics(tmp_path):
    from lattice.registry import GraphRegistryGateError

    net = _lib()
    net.diagnostics = [
        {"kind": "partial", "severity": "warning", "file": "i.ts", "line": 1,
         "message": "warning evidence"},
        {"kind": "parse_error", "severity": "error", "file": "i.ts", "line": 2,
         "message": "error evidence"},
    ]
    reg = GraphRegistry(tmp_path / "reg")
    with pytest.raises(GraphRegistryGateError) as exc:
        reg.put("broken", "1.0.0", net)
    assert "warning evidence" in str(exc.value) and "error evidence" in str(exc.value)
    assert not reg.has("broken", "1.0.0")


def test_populate_and_cli_refuse_diagnostic_failed_graph(tmp_path, monkeypatch, capsys):
    from lattice import cache
    from lattice.cli import main as cli
    from lattice.ingest.types import RawIngest
    from lattice.registry import populate_from_project

    proj = tmp_path / "proj"
    pkg = proj / "node_modules" / "golib"
    pkg.mkdir(parents=True)
    proj.joinpath("package.json").write_text(json.dumps(
        {"dependencies": {"golib": "1.0.0"}}))
    pkg.joinpath("package.json").write_text(json.dumps({"version": "1.0.0"}))
    pkg.joinpath("lib.go").write_text("package golib\n")
    diagnostics = [
        {"kind": "partial", "severity": "warning", "file": "lib.go", "line": 1,
         "message": "warning evidence"},
        {"kind": "parse_error", "severity": "error", "file": "lib.go", "line": 2,
         "message": "error evidence"},
    ]

    monkeypatch.setattr(
        cache, "ingest_source",
        lambda root, language: RawIngest(
            language=language, root=str(root), files=["lib.go"], diagnostics=diagnostics),
    )
    reg = GraphRegistry(tmp_path / "reg")
    report = populate_from_project(proj, reg, language="go")
    assert not reg.has("golib", "1.0.0")
    assert "warning evidence" in report["failed"][0][1]
    assert "error evidence" in report["failed"][0][1]

    rc = cli.main([
        "registry-add", str(pkg), "--registry", str(tmp_path / "reg"),
        "--name", "golib", "--version", "1.0.0", "--lang", "go",
    ])
    assert rc == 1 and not reg.has("golib", "1.0.0")
    err = capsys.readouterr().err
    assert "warning evidence" in err and "error evidence" in err


def test_cli_registry_add_all_returns_nonzero_on_failed_dependency(
        tmp_path, monkeypatch):
    from lattice.cli import main as cli
    from lattice import registry

    monkeypatch.setattr(
        registry, "populate_from_project",
        lambda *args, **kwargs: {
            "added": [], "skipped_no_source": [],
            "failed": [("broken", "graph gate failed")],
        },
    )
    assert cli.main([
        "registry-add-all", str(tmp_path), "--registry", str(tmp_path / "reg"),
    ]) == 1


def test_registry_auto_population_stores_graph_level_mixed_dependency(tmp_path):
    from lattice.registry import populate_from_project

    project = tmp_path / "project"
    package = project / "node_modules" / "mixed-lib"
    package.mkdir(parents=True)
    project.joinpath("package.json").write_text(json.dumps(
        {"dependencies": {"mixed-lib": "1.0.0"}}))
    package.joinpath("package.json").write_text(json.dumps(
        {"name": "mixed-lib", "version": "1.0.0"}))
    package.joinpath("run.sh").write_text("#!/bin/sh\nlaunch() { echo ready; }\n")
    package.joinpath("schema.sql").write_text("CREATE TABLE users (id integer);\n")

    registry = GraphRegistry(tmp_path / "registry")
    report = populate_from_project(project, registry, language="auto")
    graph = registry.get("mixed-lib", "1.0.0")

    assert report["failed"] == [] and graph is not None
    assert graph.language == "mixed"
    assert {"launch", "users"} <= {vertex.name for vertex in graph.vertices}
    assert registry.get("mixed-lib", "1.0.0", language="shell") is None


def test_registry_auto_single_graph_is_reusable_by_concrete_host_language(tmp_path):
    host_dir = tmp_path / "host"
    package = host_dir / "node_modules" / "libx"
    package.mkdir(parents=True)
    package.joinpath("package.json").write_text(json.dumps({"version": "1.0.0"}))
    host_dir.joinpath("app.ts").write_text(
        "import { danger } from 'libx'\n"
        "export function run(x: string) { danger(x) }\n")
    host = Hypernetwork(language="ts", root=str(host_dir), vertices=[
        Vertex(id="ts:app.ts#run", kind="function", name="run", exported=True,
               file="app.ts", start_line=2, end_line=2),
        Vertex(id="ts:app.ts#<module>", kind="module", name="app.ts",
               file="app.ts", start_line=1, end_line=2),
    ], hyperedges=[], surfaces=[])

    registry = GraphRegistry(tmp_path / "registry")
    registry.put("libx", "1.0.0", _lib(), language="auto")

    assert registry.has("libx", "1.0.0", language="auto")
    assert registry.get("libx", "1.0.0", language="typescript") is not None
    payload = json.loads(next((tmp_path / "registry").glob("*.json")).read_text())
    assert payload["_registry"]["language"] == "typescript"
    assert payload["_registry"]["requested_language"] == "auto"

    _composed, report = link_auto(host, host_dir, registry)
    assert report.linked == [("libx", "1.0.0")]
    assert report.missing == []


def test_registry_keeps_same_package_version_separate_by_language(tmp_path):
    """A package/version can have several frontend graphs without cache collisions."""
    from lattice.registry import populate_from_project

    project = tmp_path / "project"
    package = project / "node_modules" / "mixed-lib"
    package.mkdir(parents=True)
    project.joinpath("package.json").write_text(json.dumps(
        {"dependencies": {"mixed-lib": "1.0.0"}}))
    package.joinpath("package.json").write_text(json.dumps(
        {"name": "mixed-lib", "version": "1.0.0"}))
    package.joinpath("lib.py").write_text("def py_api():\n    return 1\n")
    package.joinpath("run.sh").write_text(
        "#!/bin/sh\nshell_api() {\n  echo ready\n}\n")

    registry = GraphRegistry(tmp_path / "registry")
    py_report = populate_from_project(project, registry, language="py")
    shell_report = populate_from_project(project, registry, language="sh")

    assert py_report["failed"] == []
    assert shell_report["failed"] == []
    assert shell_report["added"] != [("mixed-lib", "1.0.0", "cached")]
    assert registry.has("mixed-lib", "1.0.0", language="python")
    assert registry.has("mixed-lib", "1.0.0", language="shell")
    assert registry.get("mixed-lib", "1.0.0", language="py").language == "python"
    assert registry.get("mixed-lib", "1.0.0", language="sh").language == "shell"
    # A language-free lookup must not choose an arbitrary graph when several exist.
    assert registry.get("mixed-lib", "1.0.0") is None

    payloads = [json.loads(path.read_text())
                for path in (tmp_path / "registry").glob("*.json")]
    assert {payload["_registry"]["language"] for payload in payloads} == {
        "python", "shell",
    }
