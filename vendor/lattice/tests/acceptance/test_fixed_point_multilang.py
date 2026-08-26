# FIXED POINT: definition of done for multi-language graph depth.
# Written from user intent ("make Lattice as deep for the other programming
# languages") BEFORE any of the go/rust/ruby/c frontends existed. Do not edit
# this file to make it pass; any change to it is a product decision requiring
# human approval. Pinned hash: .fixed-point-multilang.sha
# (verify: shasum -a 256 -c .fixed-point-multilang.sha)
#
# Given a Go / Rust / Ruby fixture whose exported entry function transitively
# calls an unimplemented stub through an internal helper,
# when the developer runs the real CLI (ingest, then hunt) on that fixture,
# then ingest exits 0 with a graph carrying an imports edge, an entrypoint
# surface, and correct exported flags, and hunt reports a critical
# public_path_to_stub naming that stub.
# For C, ingest exits 0 with the api.c function symbols and the serve call.

from __future__ import annotations
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures"


def _cli(tmp: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src")
    return subprocess.run(
        [sys.executable, "-m", "lattice.cli.main", *args],
        cwd=str(tmp), env=env, capture_output=True, text=True, timeout=600)


def _ingest_and_hunt(tmp_path: pathlib.Path, fixture: str, lang: str):
    graph = tmp_path / "hypernetwork.json"
    bugs = tmp_path / "bugs.json"
    ing = _cli(tmp_path, "ingest", str(FIXTURES / fixture), "--lang", lang,
               "--out", str(graph))
    assert ing.returncode == 0, f"ingest failed:\n{ing.stdout}\n{ing.stderr}"
    hunt = _cli(tmp_path, "hunt", str(graph), "--lang", lang, "--out", str(bugs))
    assert hunt.returncode == 0, f"hunt failed:\n{hunt.stdout}\n{hunt.stderr}"
    return (json.loads(graph.read_text()), json.loads(bugs.read_text()))


def _assert_deep(net: dict, bug_list: list, stub_name: str,
                 exported_name: str, internal_name: str) -> None:
    edge_kinds = {e["kind"] for e in net["hyperedges"]}
    assert "imports" in edge_kinds, f"no imports edge, kinds: {edge_kinds}"
    surface_kinds = {s["kind"] for s in net["surfaces"]}
    assert "entrypoint" in surface_kinds, f"no entrypoint surface: {surface_kinds}"
    by_name = {}
    for v in net["vertices"]:
        by_name.setdefault(v["name"], v)
    assert by_name[exported_name]["exported"] is True
    assert by_name[internal_name]["exported"] is False
    assert by_name[stub_name]["stub"] is True

    blob = json.dumps(bug_list)
    assert stub_name in blob, f"stub {stub_name} absent from hunt output"
    kinds = {(b["kind"], b["severity"]) for b in bug_list}
    assert ("public_path_to_stub", "critical") in kinds, (
        f"no critical public_path_to_stub, got: {sorted(kinds)}")


@pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain missing")
def test_go_reaches_ts_depth(tmp_path):
    net, bugs = _ingest_and_hunt(tmp_path, "go_deep", "go")
    _assert_deep(net, bugs, stub_name="notDone",
                 exported_name="Serve", internal_name="process")


@pytest.mark.skipif(shutil.which("cargo") is None, reason="rust toolchain missing")
def test_rust_reaches_ts_depth(tmp_path):
    net, bugs = _ingest_and_hunt(tmp_path, "rust_deep", "rs")
    _assert_deep(net, bugs, stub_name="not_done",
                 exported_name="serve", internal_name="process")


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby missing")
def test_ruby_reaches_ts_depth(tmp_path):
    net, bugs = _ingest_and_hunt(tmp_path, "ruby_deep", "rb")
    _assert_deep(net, bugs, stub_name="not_done",
                 exported_name="serve", internal_name="process")


def test_c_files_are_ingested(tmp_path):
    graph = tmp_path / "hypernetwork.json"
    res = _cli(tmp_path, "ingest", str(FIXTURES / "c_deep"), "--lang", "c",
               "--out", str(graph))
    if "libclang" in (res.stdout + res.stderr) and res.returncode != 0:
        pytest.skip("libclang unavailable")
    assert res.returncode == 0, f"ingest failed:\n{res.stdout}\n{res.stderr}"
    net = json.loads(graph.read_text())
    names = {v["name"] for v in net["vertices"]}
    assert {"serve", "process", "main"} <= names, f"missing C symbols: {names}"
    ref_edges = [e for e in net["hyperedges"] if e["kind"] in ("references", "calls")]
    assert ref_edges, "no call edges recovered from C sources"
