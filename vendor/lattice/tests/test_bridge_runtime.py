"""Packaging and clean-cache contracts for the shipped language bridges."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

import pytest

import lattice.bridge_runtime as runtime
import lattice.ingest.go_taint as go_taint
import lattice.ingest.js_arbitrary_call as js_arbitrary_call
import lattice.ingest.ruby_taint as ruby_taint
import lattice.ingest.rust_taint as rust_taint


_PACKAGED_ASSETS = {
    "goast": ("go_ast.go",),
    "jsast": ("parse.js", "package.json", "package-lock.json"),
    "rubyast": ("ruby_ast.rb", "ruby_graph.rb"),
    "rustast": ("Cargo.toml", "Cargo.lock", "src/main.rs"),
    "rustgraph": ("Cargo.toml", "Cargo.lock", "src/main.rs"),
}


@pytest.mark.parametrize(
    ("bridge", "asset"),
    [(bridge, asset) for bridge, assets in _PACKAGED_ASSETS.items() for asset in assets],
)
def test_bridge_source_assets_are_present(bridge, asset):
    assert runtime.bridge_source(bridge, *asset.split("/")).is_file()


def test_bridge_source_rejects_path_escape():
    with pytest.raises(runtime.BridgeRuntimeError, match="invalid .* asset path"):
        runtime.bridge_source("goast", "..", "rubyast", "ruby_ast.rb")
    with pytest.raises(runtime.BridgeRuntimeError, match="invalid packaged bridge name"):
        runtime.bridge_source("..", "bridge_runtime.py")


def test_go_bridge_clean_cache_and_source_freshness(tmp_path, monkeypatch):
    bridges = tmp_path / "assets"
    source = bridges / "goast" / "go_ast.go"
    source.parent.mkdir(parents=True)
    source.write_text("package main\nfunc main() {}\n")
    monkeypatch.setattr(runtime, "_BRIDGES_ROOT", bridges)
    monkeypatch.setenv("LATTICE_BRIDGE_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("GOOS", "plan9")
    monkeypatch.setenv("GOARCH", "amd64")
    monkeypatch.setenv("GOFLAGS", "-buildmode=plugin")
    monkeypatch.setattr(runtime, "_require_tool", lambda name: f"/tool/{name}")
    commands = []

    def fake_run(cmd, *, purpose, cwd=None, env=None):
        commands.append((cmd, purpose, cwd, env))
        output = pathlib.Path(cmd[cmd.index("-o") + 1])
        output.write_text("binary")
        output.chmod(0o755)

    monkeypatch.setattr(runtime, "_run_checked", fake_run)
    first = runtime.ensure_go_bridge()
    assert first.is_file()
    assert runtime.ensure_go_bridge() == first
    assert len(commands) == 1
    assert "-trimpath" in commands[0][0]
    assert commands[0][3]["GOENV"] == "off"
    assert commands[0][3]["CGO_ENABLED"] == "0"
    assert "GOOS" not in commands[0][3]
    assert "GOARCH" not in commands[0][3]
    assert "GOFLAGS" not in commands[0][3]

    source.write_text("package main\nfunc main() { println(1) }\n")
    second = runtime.ensure_go_bridge()
    assert second.is_file() and second != first
    assert len(commands) == 2


def test_same_fingerprint_build_is_serialized(tmp_path, monkeypatch):
    bridges = tmp_path / "assets"
    source = bridges / "goast" / "go_ast.go"
    source.parent.mkdir(parents=True)
    source.write_text("package main\nfunc main() {}\n")
    monkeypatch.setattr(runtime, "_BRIDGES_ROOT", bridges)
    monkeypatch.setenv("LATTICE_BRIDGE_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(runtime, "_require_tool", lambda name: f"/tool/{name}")
    commands = []

    def fake_run(cmd, *, purpose, cwd=None, env=None):
        commands.append(cmd)
        time.sleep(0.05)
        output = pathlib.Path(cmd[cmd.index("-o") + 1])
        output.write_text("binary")
        output.chmod(0o755)

    monkeypatch.setattr(runtime, "_run_checked", fake_run)
    with ThreadPoolExecutor(max_workers=2) as pool:
        artifacts = list(pool.map(lambda _: runtime.ensure_go_bridge(), range(2)))
    assert artifacts[0] == artifacts[1]
    assert len(commands) == 1


def test_rust_bridge_builds_clean_cache_locked_and_tracks_all_inputs(tmp_path, monkeypatch):
    bridges = tmp_path / "assets"
    crate = bridges / "rustast"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text('[package]\nname="rustast"\nversion="0.1.0"\n')
    lockfile = crate / "Cargo.lock"
    lockfile.write_text("version = 4\n")
    (crate / "src" / "main.rs").write_text("fn main() {}\n")
    monkeypatch.setattr(runtime, "_BRIDGES_ROOT", bridges)
    monkeypatch.setenv("LATTICE_BRIDGE_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("CARGO_BUILD_TARGET", "wasm32-unknown-unknown")
    monkeypatch.setenv("CARGO_TARGET_DIR", str(tmp_path / "wrong-target"))
    monkeypatch.setenv("RUSTFLAGS", "--cfg cross_target_probe")
    monkeypatch.setattr(runtime, "_require_tool", lambda name: f"/tool/{name}")
    monkeypatch.setattr(runtime, "_cargo_host_target", lambda cargo, env: "host-test-target")
    commands = []

    def fake_run(cmd, *, purpose, cwd=None, env=None):
        commands.append((cmd, purpose, cwd, env))
        target = pathlib.Path(cmd[cmd.index("--target-dir") + 1])
        host = cmd[cmd.index("--target") + 1]
        artifact = target / host / "release" / ("rust_ast.exe" if os.name == "nt" else "rust_ast")
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("binary")
        artifact.chmod(0o755)

    monkeypatch.setattr(runtime, "_run_checked", fake_run)
    first = runtime.ensure_rust_bridge("rustast", binary="rust_ast")
    assert first.is_file()

    def unexpected_tool_lookup(name):
        raise AssertionError(f"cached bridge must not need {name}")

    monkeypatch.setattr(runtime, "_require_tool", unexpected_tool_lookup)
    assert runtime.ensure_rust_bridge("rustast", binary="rust_ast") == first
    assert len(commands) == 1
    command = commands[0][0]
    assert "--locked" in command
    assert "--manifest-path" in command
    assert "--target-dir" in command
    assert command[command.index("--target") + 1] == "host-test-target"
    assert str(tmp_path / "cache") in str(first)
    assert "CARGO_BUILD_TARGET" not in commands[0][3]
    assert "CARGO_TARGET_DIR" not in commands[0][3]
    assert "RUSTFLAGS" not in commands[0][3]

    lockfile.write_text("version = 4\n# dependency update\n")
    monkeypatch.setattr(runtime, "_require_tool", lambda name: f"/tool/{name}")
    second = runtime.ensure_rust_bridge("rustast", binary="rust_ast")
    assert second.is_file() and second != first
    assert len(commands) == 2


def test_node_bridge_installs_locked_dependencies_in_cache(tmp_path, monkeypatch):
    bridges = tmp_path / "assets"
    source = bridges / "jsast"
    source.mkdir(parents=True)
    (source / "parse.js").write_text("process.stdout.write('{}')\n")
    (source / "package.json").write_text('{"dependencies":{"parser":"1.0.0"}}\n')
    (source / "package-lock.json").write_text('{"lockfileVersion":3}\n')
    monkeypatch.setattr(runtime, "_BRIDGES_ROOT", bridges)
    monkeypatch.setenv("LATTICE_BRIDGE_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(runtime, "_require_tool", lambda name: f"/tool/{name}")
    commands = []

    def fake_run(cmd, *, purpose, cwd=None, env=None):
        commands.append((cmd, purpose, cwd))
        (cwd / "node_modules").mkdir()

    monkeypatch.setattr(runtime, "_run_checked", fake_run)
    script = runtime.ensure_node_bridge()
    assert script.is_file()
    assert runtime.ensure_node_bridge() == script
    assert len(commands) == 1
    assert commands[0][0][1:3] == ["ci", "--ignore-scripts"]
    assert (script.parent / ".ready").is_file()


@pytest.mark.parametrize(
    ("frontend", "payload", "expected"),
    [
        (go_taint, {}, "expected a function list"),
        (rust_taint, {}, "expected a function list"),
        (ruby_taint, {}, "expected a function list"),
        (js_arbitrary_call, [], "expected a Babel Program"),
        (js_arbitrary_call, {"type": "File"}, "expected a Babel Program"),
    ],
)
def test_taint_frontends_reject_valid_json_with_wrong_top_level_shape(
    tmp_path, monkeypatch, frontend, payload, expected
):
    monkeypatch.setattr(frontend, "run_json_bridge_checked", lambda *args, **kwargs: payload)
    with pytest.raises(runtime.BridgeRuntimeError, match=expected):
        frontend._parse(tmp_path / "source", tmp_path / "bridge")


def test_wheel_clean_install_contains_every_bridge_asset(tmp_path):
    repo = pathlib.Path(__file__).resolve().parents[1]
    wheel_dir = tmp_path / "wheel"
    site_dir = tmp_path / "site"
    clean_cwd = tmp_path / "clean"
    wheel_dir.mkdir()
    clean_cwd.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            str(repo),
            "--no-deps",
            "--wheel-dir",
            str(wheel_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(wheel_dir.glob("lattice-*.whl"))
    expected = {
        f"lattice/_bridges/{bridge}/{asset}"
        for bridge, assets in _PACKAGED_ASSETS.items()
        for asset in assets
    }
    with zipfile.ZipFile(wheel) as archive:
        assert expected <= set(archive.namelist())

    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(site_dir), str(wheel)],
        check=True,
        capture_output=True,
        text=True,
    )
    probe = """
from lattice.bridge_runtime import bridge_source
assets = {
    'goast': ('go_ast.go',),
    'jsast': ('parse.js', 'package.json', 'package-lock.json'),
    'rubyast': ('ruby_ast.rb', 'ruby_graph.rb'),
    'rustast': ('Cargo.toml', 'Cargo.lock', 'src/main.rs'),
    'rustgraph': ('Cargo.toml', 'Cargo.lock', 'src/main.rs'),
}
for bridge, names in assets.items():
    for name in names:
        assert bridge_source(bridge, *name.split('/')).is_file(), (bridge, name)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(site_dir)
    subprocess.run(
        [sys.executable, "-c", probe],
        cwd=clean_cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
