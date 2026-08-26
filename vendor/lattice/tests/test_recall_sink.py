import json, subprocess, pathlib, pytest
from lattice.graph.models import Vertex, Hyperedge, Hypernetwork
from lattice.complete.report import HypernetworkReport
from lattice.memory.recall_sink import persist


def _count(db, key):
    """Read one persistence counter from `recall storage`.

    v0.12+ exposes `tables.cells`, `tables.hyperedges`, `tables.edges` under `storage`.
    Older builds returned the same numbers under `status.stats.{nodes,hyperedges}`.
    We accept both so a rollback doesn't silently break — with a stable name-map so a
    caller passes `"cells"`/`"hyperedges"` and doesn't have to know which shape is live.
    """
    stor = json.loads(subprocess.run(
        ["recall", "--db", db, "storage"], capture_output=True, text=True).stdout)
    tables = stor.get("tables") or {}
    if key in tables:
        return tables[key]
    # legacy fallback: pre-v0.12 status
    stat = json.loads(subprocess.run(
        ["recall", "--db", db, "status"], capture_output=True, text=True).stdout)
    stats = stat.get("stats", {})
    return stats.get(key, stats.get({"cells": "nodes"}.get(key, key), 0))


@pytest.mark.integration
def test_persist_writes_cells(tmp_path):
    db = str(tmp_path / "lattice_test.sqlite3")
    subprocess.run(["recall", "init", "--db", db], check=True, capture_output=True)
    v = Vertex(id="ts-sym:a.ts#foo", kind="function", name="foo", file="a.ts",
               start_line=1, end_line=3, exported=True)
    net = Hypernetwork(language="typescript", root="/x", vertices=[v], hyperedges=[])
    rep = HypernetworkReport(resolution=1.0, verdict="pass")
    persist(net, rep, db_path=db, project="lattice-test")
    assert _count(db, "cells") >= 1


@pytest.mark.integration
def test_persist_writes_hyperedges(tmp_path):
    db = str(tmp_path / "edges.sqlite3")
    subprocess.run(["recall", "init", "--db", db], check=True, capture_output=True)
    a = Vertex(id="ts-sym:a.ts#foo", kind="function", name="foo", file="a.ts",
               start_line=1, end_line=3, exported=True)
    b = Vertex(id="ts-sym:b.ts#bar", kind="function", name="bar", file="b.ts",
               start_line=1, end_line=3, exported=True)
    e = Hyperedge(id="e1", kind="calls", members=["ts-sym:a.ts#foo", "ts-sym:b.ts#bar"], resolved=True)
    net = Hypernetwork(language="typescript", root="/x", vertices=[a, b], hyperedges=[e])
    rep = HypernetworkReport(resolution=1.0, verdict="pass")
    persist(net, rep, db_path=db, project="lattice-test")
    assert _count(db, "cells") >= 2
    assert _count(db, "hyperedges") >= 1
