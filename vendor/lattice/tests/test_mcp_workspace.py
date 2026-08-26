# tests/test_mcp_workspace.py
"""The stateful cache core behind the MCP server: ingest once, query fast, know when stale.

Fixtures are Python (python_ingest needs no LSP binary), so these run anywhere.
"""
import json
import time

import pytest

from lattice.mcp.workspace import Workspace


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def _repo(tmp_path):
    _write(tmp_path, "app.py", "def used():\n    return 1\n\ndef main():\n    return used()\n")
    _write(tmp_path, "lib.py", "def helper():\n    return 2\n")
    return tmp_path


# ---- ensure: build, cache, and reload ----

def test_ensure_builds_graph_and_writes_cache(tmp_path):
    ws = Workspace(_repo(tmp_path))
    net = ws.ensure(language="python")
    names = {v.name for v in net.vertices}
    assert {"used", "main", "helper"} <= names, names
    assert (tmp_path / ".lattice" / "graph.json").is_file()
    assert (tmp_path / ".lattice" / "snapshot.json").is_file()


def test_ensure_loads_from_cache_not_reingest(tmp_path):
    repo = _repo(tmp_path)
    Workspace(repo).ensure(language="python")          # build + cache
    (repo / "app.py").unlink()                          # a re-ingest would now lose used/main
    net = Workspace(repo).ensure(language="python")     # must come from cache
    assert {"used", "main"} <= {v.name for v in net.vertices}


# ---- staleness: cheap stat-only detection ----

def test_staleness_clean_right_after_build(tmp_path):
    ws = Workspace(_repo(tmp_path))
    ws.ensure(language="python")
    s = ws.staleness()
    assert s == {"changed": [], "added": [], "removed": []}


def test_staleness_detects_changed_file(tmp_path):
    repo = _repo(tmp_path)
    ws = Workspace(repo)
    ws.ensure(language="python")
    time.sleep(0.01)
    _write(repo, "app.py", "def used():\n    return 99\n")   # changed content + mtime
    assert "app.py" in ws.staleness()["changed"]


def test_staleness_detects_added_and_removed(tmp_path):
    repo = _repo(tmp_path)
    ws = Workspace(repo)
    ws.ensure(language="python")
    _write(repo, "new.py", "def fresh():\n    return 0\n")
    (repo / "lib.py").unlink()
    s = ws.staleness()
    assert "new.py" in s["added"]
    assert "lib.py" in s["removed"]


# ---- refresh: rebuild and clear staleness ----

def test_refresh_picks_up_new_symbol_and_clears_staleness(tmp_path):
    repo = _repo(tmp_path)
    ws = Workspace(repo)
    ws.ensure(language="python")
    time.sleep(0.01)
    _write(repo, "lib.py", "def helper():\n    return 2\n\ndef added_later():\n    return 3\n")
    out = ws.refresh()
    assert out["rebuilt"] is True
    assert "added_later" in {v.name for v in ws.net.vertices}
    assert ws.staleness() == {"changed": [], "added": [], "removed": []}


def test_refresh_python_uses_full_reingest(tmp_path):
    repo = _repo(tmp_path)
    ws = Workspace(repo)
    ws.ensure(language="python")
    out = ws.refresh()
    assert out["mode"] == "full"      # incremental splice is TS-only


def test_snapshot_records_language(tmp_path):
    repo = _repo(tmp_path)
    Workspace(repo).ensure(language="python")
    snap = json.loads((repo / ".lattice" / "snapshot.json").read_text())
    assert snap["language"] == "python"
    assert "app.py" in snap["files"]


def test_short_language_codes_are_normalized(tmp_path):
    # the MCP/CLI surface accepts short codes ("ts","py","sol"); ingest backends want
    # canonical names ("typescript","python"). The workspace must translate, or a real
    # TS repo dies in multilspy with "Language ts is not supported".
    repo = _repo(tmp_path)
    ws = Workspace(repo)
    ws.ensure(language="py")
    assert ws.language == "python"
    snap = json.loads((repo / ".lattice" / "snapshot.json").read_text())
    assert snap["language"] == "python"


def test_requested_language_invalidates_disk_and_memory_cache(tmp_path, monkeypatch):
    from lattice.graph.models import Hypernetwork

    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo, "run.sh", "echo shell\n")
    _write(repo, "query.sql", "select 1;\n")
    calls = []

    def fake_ingest(self):
        calls.append(self.language)
        return Hypernetwork(language=self.language, root=str(self.root),
                            vertices=[], hyperedges=[], surfaces=[])

    monkeypatch.setattr(Workspace, "_ingest", fake_ingest)
    first = Workspace(repo)
    assert first.ensure(language="sh").language == "shell"
    # Same object must not return its in-memory shell graph for an explicit SQL request.
    assert first.ensure(language="sql").language == "sql"
    # A new object must validate the requested canonical language against snapshot.json.
    assert Workspace(repo).ensure(language="shell").language == "shell"

    assert calls == ["shell", "sql", "shell"]
    snap = json.loads((repo / ".lattice" / "snapshot.json").read_text())
    assert snap["language"] == "shell"


def test_failed_language_switch_cannot_reload_previous_language_cache(tmp_path, monkeypatch):
    from lattice.graph.models import Hypernetwork

    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo, "run.sh", "echo shell\n")
    calls = []

    def fake_ingest(self):
        calls.append(self.language)
        if self.language == "typescript":
            raise RuntimeError("typescript unavailable")
        return Hypernetwork(language=self.language, root=str(self.root),
                            vertices=[], hyperedges=[], surfaces=[])

    monkeypatch.setattr(Workspace, "_ingest", fake_ingest)
    ws = Workspace(repo)
    assert ws.ensure(language="shell").language == "shell"

    with pytest.raises(RuntimeError, match="typescript unavailable"):
        ws.ensure(language="typescript")
    with pytest.raises(RuntimeError, match="typescript unavailable"):
        ws.ensure()

    assert ws.net is None
    assert ws.language == "typescript"
    assert calls == ["shell", "typescript", "typescript"]
    # A deliberate reselection may reuse the still-valid shell snapshot.
    assert ws.ensure(language="shell").language == "shell"


@pytest.mark.parametrize("metadata", [
    "package.json", "tsconfig.json", "jsconfig.json", "go.mod", "Cargo.toml",
])
def test_staleness_tracks_graph_affecting_metadata(tmp_path, metadata):
    repo = _repo(tmp_path)
    _write(repo, metadata, "{}\n")
    ws = Workspace(repo)
    ws.ensure(language="python")
    time.sleep(0.01)
    _write(repo, metadata, '{"changed":true}\n')
    assert metadata in ws.staleness()["changed"]
