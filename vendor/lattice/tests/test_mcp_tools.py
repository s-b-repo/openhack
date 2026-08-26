# tests/test_mcp_tools.py
"""The six MCP tool callables, tested directly (no transport) against a tmp Python repo.

Each tool returns a plain dict with a `freshness` block; analysis tools lazily map the
repo on first call.
"""
import builtins
import pytest

from lattice.graph.models import Vertex, Hyperedge, Surface, Hypernetwork
from lattice.mcp.workspace import Workspace
from lattice.mcp import tools


def _stub_net():
    """A graph with a stub reachable from a public entrypoint — the canonical
    public_path_to_stub. Python ingest can't synthesize stubs, so the bug-surfacing
    assertions use this hand-built net (testing the tool wrapper, not ingest depth)."""
    def fn(vid, name, stub=False):
        return Vertex(id=vid, kind="function", name=name, file="a.ts",
                      start_line=1, end_line=2, exported=True, stub=stub)
    return Hypernetwork(
        language="typescript", root="/x",
        vertices=[fn("E", "entry"), fn("G", "gap", stub=True)],
        hyperedges=[Hyperedge(id="e", kind="calls", members=["E", "G"], resolved=True)],
        surfaces=[Surface(id="s", vertex_id="E", kind="public_api")])


def _ws_with_net(tmp_path, net):
    ws = Workspace(tmp_path)
    ws.net = net                      # pre-loaded graph; tools' ensure() returns it as-is
    return ws


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _repo(tmp_path):
    # used() is reached from the public entrypoint main(); orphan() is dead;
    # gap() is an unimplemented stub reached from a public path.
    _write(tmp_path, "app.py",
           "def used():\n    return helper()\n\n"
           "def gap():\n    raise NotImplementedError\n\n"
           "def main():\n    used()\n    return gap()\n\n"
           "def orphan():\n    return 0\n")
    _write(tmp_path, "lib.py", "def helper():\n    return 2\n")
    return tmp_path


def _ws(tmp_path):
    ws = Workspace(_repo(tmp_path))
    ws.ensure(language="python")
    return ws


# ---- map ----

def test_map_reports_graph_stats_and_freshness(tmp_path):
    ws = Workspace(_repo(tmp_path))
    out = tools.tool_map(ws, language="python")
    assert out["vertices"] > 0
    assert "freshness" in out and out["freshness"]["stale"] is False


def test_map_auto_reports_missing_cpp_extra_and_keeps_other_languages(
        tmp_path, monkeypatch):
    _write(tmp_path, "app.py", "def python_api():\n    return 1\n")
    _write(tmp_path, "native.c", "int native_api(void) { return 2; }\n")
    original_import = builtins.__import__

    def import_without_clang(name, *args, **kwargs):
        if name == "clang" or name.startswith("clang."):
            raise ModuleNotFoundError("No module named 'clang'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_clang)
    ws = Workspace(tmp_path, cache_dir=tmp_path / ".test-lattice")
    out = tools.tool_map(ws, language="auto")

    assert "python_api" in {vertex.name for vertex in ws.net.vertices}
    assert out["graph_health"]["verdict"] == "fail"
    diagnostics = out["graph_health"]["diagnostics"]
    assert diagnostics[0]["kind"] == "frontend_unavailable"
    assert "lattice[cpp]" in diagnostics[0]["message"]
    assert "graph health failed" in out["freshness"]["hint"]


# ---- impact (the wedge) ----

def test_impact_by_symbol_returns_blast_radius(tmp_path):
    out = tools.tool_impact(_ws(tmp_path), "helper")
    assert out["targets"]
    # helper() is called by used(); used() by main() -> both are dependents
    assert any("used" in d for d in out["transitive_dependents"])
    assert out["blast_radius"] >= 1


def test_impact_by_file_unions_symbols(tmp_path):
    out = tools.tool_impact(_ws(tmp_path), "lib.py")
    assert out["targets"]                       # every symbol defined in lib.py
    assert out["by"] == "file"


def test_impact_unknown_symbol_suggests(tmp_path):
    out = tools.tool_impact(_ws(tmp_path), "helpr")    # typo
    assert "error" in out
    assert any("helper" in s for s in out["suggestions"])


# ---- hunt (the post-edit gate) ----

def test_hunt_finds_public_path_to_stub(tmp_path):
    out = tools.tool_hunt(_ws_with_net(tmp_path, _stub_net()))
    kinds = {b["kind"] for b in out["findings"]}
    assert "public_path_to_stub" in kinds       # stub reached from a public entrypoint


def test_hunt_severity_filter(tmp_path):
    ws = _ws_with_net(tmp_path, _stub_net())
    everything = tools.tool_hunt(ws, severity_min="low")
    crit_only = tools.tool_hunt(ws, severity_min="critical")
    assert crit_only["findings"]                                  # the stub is critical
    assert len(crit_only["findings"]) <= len(everything["findings"])
    assert all(b["severity"] == "critical" for b in crit_only["findings"])


def test_hunt_on_real_repo_returns_valid_shape(tmp_path):
    # end-to-end plumbing: real ingest -> hunt -> tool dict (findings may be empty;
    # Python ingest doesn't populate stub/broken-ref signals — that's an ingest-depth
    # property, not a server bug).
    out = tools.tool_hunt(_ws(tmp_path))
    assert isinstance(out["findings"], list)
    assert "counts" in out and "freshness" in out


# ---- secaudit ----

def test_secaudit_returns_honest_contract(tmp_path):
    out = tools.tool_secaudit(_ws(tmp_path))
    assert "verified" in out and "not_verified" in out
    assert "call_reachability" in out["verified"]


# ---- triage ----

def test_triage_ranks_by_priority(tmp_path):
    out = tools.tool_triage(_ws(tmp_path))
    prios = [item["priority"] for item in out["worklist"]]
    assert prios == sorted(prios, reverse=True)


# ---- refresh + freshness loop ----

def test_refresh_clears_staleness(tmp_path):
    ws = _ws(tmp_path)
    _write(ws.root, "extra.py", "def brand_new():\n    return 1\n")
    assert tools.tool_hunt(ws)["freshness"]["stale"] is True
    r = tools.tool_refresh(ws)
    assert r["rebuilt"] is True
    assert tools.tool_hunt(ws)["freshness"]["stale"] is False


def test_analysis_tools_lazy_map(tmp_path):
    # a fresh workspace that was never ensure()'d still answers (auto-map on first call)
    ws = Workspace(_repo(tmp_path))
    out = tools.tool_hunt(ws)
    assert "findings" in out


@pytest.mark.parametrize(
    "tool_name",
    ["map", "impact", "hunt", "secaudit", "triage", "refresh"],
)
def test_every_graph_tool_exposes_failed_health_without_false_fresh_hint(
        tmp_path, monkeypatch, tool_name):
    warning = {"kind": "partial", "severity": "warning", "file": "a.ts",
               "line": 1, "message": "warning evidence"}
    error = {"kind": "parse_error", "severity": "error", "file": "a.ts",
             "line": 2, "message": "error evidence"}
    net = _stub_net()
    net.diagnostics = [warning, error]
    ws = _ws_with_net(tmp_path, net)
    if tool_name == "refresh":
        monkeypatch.setattr(ws, "refresh", lambda: {"rebuilt": True, "mode": "test"})

    calls = {
        "map": lambda: tools.tool_map(ws),
        "impact": lambda: tools.tool_impact(ws, "entry"),
        "hunt": lambda: tools.tool_hunt(ws),
        "secaudit": lambda: tools.tool_secaudit(ws),
        "triage": lambda: tools.tool_triage(ws),
        "refresh": lambda: tools.tool_refresh(ws),
    }
    out = calls[tool_name]()
    health = out["graph_health"]
    assert health["verdict"] == "fail"
    assert health["failing_checks"] == ["ingest_diagnostics"]
    assert health["diagnostics"] == [warning, error]
    assert "matches source" not in out["freshness"]["hint"]
    assert "graph health failed" in out["freshness"]["hint"]
