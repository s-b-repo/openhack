"""Runtime support for Lattice's packaged language bridges.

Bridge *sources* ship inside the ``lattice`` wheel.  Compiled artifacts and
Node dependencies do not: they are created lazily in a writable, content-
addressed user cache.  This keeps installed packages read-only while making
freshness depend on every relevant source file and dependency lockfile.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager


class BridgeRuntimeError(RuntimeError):
    """A required bridge asset, toolchain, dependency install, or build failed."""


BRIDGE_RUN_TIMEOUT_SECONDS = 30
_BRIDGES_ROOT = pathlib.Path(__file__).resolve().parent / "_bridges"
_CACHE_ENV = "LATTICE_BRIDGE_CACHE"
_BUILD_TIMEOUT_SECONDS = 300
_LOCK_TIMEOUT_SECONDS = _BUILD_TIMEOUT_SECONDS + 30
_TOOL_HINTS = {
    "go": "Install Go and ensure the `go` executable is on PATH.",
    "cargo": "Install Rust with rustup and ensure `cargo` is on PATH.",
    "node": "Install Node.js and ensure the `node` executable is on PATH.",
    "npm": "Install npm (normally bundled with Node.js) and ensure it is on PATH.",
    "ruby": "Install Ruby and ensure the `ruby` executable is on PATH.",
}


def bridge_source(bridge: str, *parts: str) -> pathlib.Path:
    """Return a validated packaged bridge asset without assuming a checkout."""
    packaged_root = _BRIDGES_ROOT.resolve()
    bridge_root = (packaged_root / bridge).resolve()
    try:
        bridge_root.relative_to(packaged_root)
    except ValueError as exc:
        raise BridgeRuntimeError(f"invalid packaged bridge name: {bridge!r}") from exc
    path = bridge_root.joinpath(*parts).resolve()
    try:
        path.relative_to(bridge_root)
    except ValueError as exc:
        raise BridgeRuntimeError(f"invalid {bridge!r} bridge asset path: {parts!r}") from exc
    if not path.is_file():
        raise BridgeRuntimeError(
            f"packaged {bridge!r} bridge asset is missing: {path}. "
            "Reinstall Lattice from a complete wheel."
        )
    return path


def bridge_cache_root() -> pathlib.Path:
    """Writable root for content-addressed bridge artifacts."""
    override = os.environ.get(_CACHE_ENV)
    if override:
        return pathlib.Path(override).expanduser().resolve()
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return pathlib.Path(xdg).expanduser().resolve() / "lattice" / "bridges"
    if sys.platform == "darwin":
        return pathlib.Path.home() / "Library" / "Caches" / "lattice" / "bridges"
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        base = pathlib.Path(local) if local else pathlib.Path.home() / "AppData" / "Local"
        return base / "lattice" / "bridges"
    return pathlib.Path.home() / ".cache" / "lattice" / "bridges"


def _require_tool(name: str) -> str:
    executable = shutil.which(name)
    if executable:
        return executable
    hint = _TOOL_HINTS.get(name, f"Install {name!r} and ensure it is on PATH.")
    raise BridgeRuntimeError(f"the {name!r} executable is required for a Lattice bridge. {hint}")


def _fingerprint(root: pathlib.Path, paths: list[pathlib.Path], *, kind: str) -> str:
    """Hash immutable bridge inputs and the executable platform.

    Toolchain versions are deliberately not part of this key: once an artifact is built, it remains
    usable when the compiler/package manager is no longer installed.  Dependency versions *are* fixed
    by the hashed lockfiles; changing bridge source or a lockfile always selects a fresh cache entry.
    """
    digest = hashlib.sha256()
    digest.update(f"lattice-bridge-v1\0{kind}\0{sys.platform}\0{platform.machine()}\0".encode())
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:24]


@contextmanager
def _build_lock(directory: pathlib.Path):
    """Serialize a fingerprint build across processes; OS locks are released after crashes."""
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = directory / ".build.lock"
    handle = lock_path.open("a+b")
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    if os.name == "nt":
        import msvcrt

        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        while True:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    handle.close()
                    raise BridgeRuntimeError(f"timed out waiting for bridge build lock {lock_path}") from exc
                time.sleep(0.1)
        def unlock():
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    handle.close()
                    raise BridgeRuntimeError(f"timed out waiting for bridge build lock {lock_path}") from exc
                time.sleep(0.1)
        def unlock():
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    try:
        yield
    finally:
        unlock()
        handle.close()


def _run_checked(
    cmd: list[str],
    *,
    purpose: str,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> None:
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=_BUILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BridgeRuntimeError(f"{purpose} could not start: {exc}") from exc
    if result.returncode == 0:
        return
    detail = (result.stderr or result.stdout or "no diagnostic output").strip()
    if len(detail) > 2000:
        detail = detail[-2000:]
    raise BridgeRuntimeError(f"{purpose} failed with exit code {result.returncode}: {detail}")


def _host_build_env(kind: str) -> dict[str, str]:
    """Return a build environment that cannot redirect a cached bridge off-host."""
    env = os.environ.copy()
    if kind == "go":
        for name in (
            "GOOS",
            "GOARCH",
            "GOARM",
            "GOAMD64",
            "GO386",
            "GOMIPS",
            "GOMIPS64",
            "GOPPC64",
            "GORISCV64",
            "GOWASM",
            "GOFLAGS",
        ):
            env.pop(name, None)
        # Ignore persistent `go env -w` cross-target settings and avoid a host C toolchain dependency.
        env["GOENV"] = "off"
        env["CGO_ENABLED"] = "0"
    elif kind == "rust":
        for name in (
            "CARGO_BUILD_TARGET",
            "CARGO_TARGET_DIR",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTFLAGS",
            "RUSTDOCFLAGS",
        ):
            env.pop(name, None)
    else:
        raise ValueError(f"unsupported host build environment: {kind!r}")
    return env


def _cargo_host_target(cargo: str, env: dict[str, str]) -> str:
    """Return Cargo's active host triple so user config cannot redirect bridge output."""
    try:
        result = subprocess.run(
            [cargo, "-vV"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BridgeRuntimeError(f"querying the Cargo host target could not start: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic output").strip()
        raise BridgeRuntimeError(
            f"querying the Cargo host target failed with exit code {result.returncode}: {detail}"
        )
    for line in result.stdout.splitlines():
        if line.startswith("host: ") and line[6:].strip():
            return line[6:].strip()
    raise BridgeRuntimeError("Cargo did not report a host target in `cargo -vV` output")


def run_json_bridge_checked(cmd: list[str], *, purpose: str, timeout: int = 30):
    """Run a JSON bridge without converting operational or parse failures to empty results."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BridgeRuntimeError(f"{purpose} could not start: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic output").strip()
        raise BridgeRuntimeError(
            f"{purpose} failed with exit code {result.returncode}: {detail}"
        )
    if not result.stdout:
        raise BridgeRuntimeError(f"{purpose} produced no JSON output")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BridgeRuntimeError(
            f"{purpose} produced invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def _binary_name(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def _usable_binary(path: pathlib.Path) -> bool:
    return path.is_file() and path.stat().st_size > 0 and (os.name == "nt" or os.access(path, os.X_OK))


def ensure_go_bridge(
    bridge: str = "goast", *, source: str = "go_ast.go", binary: str = "go_ast"
) -> pathlib.Path:
    """Build a packaged Go bridge into the writable cache when absent or stale."""
    source_path = bridge_source(bridge, source)
    fingerprint = _fingerprint(source_path.parent, [source_path], kind=f"go:{bridge}:{binary}")
    artifact_dir = bridge_cache_root() / "go" / bridge / fingerprint
    artifact = artifact_dir / _binary_name(binary)
    if _usable_binary(artifact):
        return artifact

    with _build_lock(artifact_dir):
        if _usable_binary(artifact):
            return artifact
        if artifact.exists():
            artifact.unlink()
        go = _require_tool("go")
        temporary = artifact_dir / f".{artifact.name}.{os.getpid()}.tmp"
        try:
            _run_checked(
                [go, "build", "-trimpath", "-o", str(temporary), str(source_path)],
                purpose=f"building the {bridge!r} Go bridge",
                cwd=source_path.parent,
                env=_host_build_env("go"),
            )
            if not temporary.is_file():
                raise BridgeRuntimeError(
                    f"building the {bridge!r} Go bridge succeeded but produced no artifact at {temporary}"
                )
            temporary.chmod(temporary.stat().st_mode | 0o111)
            os.replace(temporary, artifact)
        finally:
            if temporary.exists():
                temporary.unlink()
    return artifact


def ensure_rust_bridge(bridge: str, *, binary: str) -> pathlib.Path:
    """Build a locked packaged Cargo bridge into a content-addressed target dir."""
    manifest = bridge_source(bridge, "Cargo.toml")
    lockfile = bridge_source(bridge, "Cargo.lock")
    source_dir = manifest.parent / "src"
    rust_sources = sorted(source_dir.rglob("*.rs")) if source_dir.is_dir() else []
    if not rust_sources:
        raise BridgeRuntimeError(
            f"packaged {bridge!r} Rust bridge has no source files under {source_dir}. Reinstall Lattice."
        )
    inputs = [manifest, lockfile, *rust_sources]
    fingerprint = _fingerprint(manifest.parent, inputs, kind=f"rust:{bridge}:{binary}")
    artifact_dir = bridge_cache_root() / "rust" / bridge / fingerprint
    target_dir = artifact_dir / "cargo-target"
    artifact = artifact_dir / "bin" / _binary_name(binary)
    if _usable_binary(artifact):
        return artifact

    with _build_lock(artifact_dir):
        if _usable_binary(artifact):
            return artifact
        if artifact.exists():
            artifact.unlink()
        cargo = _require_tool("cargo")
        build_env = _host_build_env("rust")
        host_target = _cargo_host_target(cargo, build_env)
        target_dir.mkdir(parents=True, exist_ok=True)
        _run_checked(
            [
                cargo,
                "build",
                "--release",
                "--locked",
                "--quiet",
                "--manifest-path",
                str(manifest),
                "--target-dir",
                str(target_dir),
                "--target",
                host_target,
            ],
            purpose=f"building the {bridge!r} Rust bridge",
            cwd=manifest.parent,
            env=build_env,
        )
        built = target_dir / host_target / "release" / _binary_name(binary)
        if not built.is_file():
            raise BridgeRuntimeError(
                f"building the {bridge!r} Rust bridge succeeded but produced no artifact at {built}"
            )
        artifact.parent.mkdir(parents=True, exist_ok=True)
        temporary = artifact.parent / f".{artifact.name}.{os.getpid()}.tmp"
        try:
            shutil.copy2(built, temporary)
            temporary.chmod(temporary.stat().st_mode | 0o111)
            os.replace(temporary, artifact)
        finally:
            if temporary.exists():
                temporary.unlink()
    return artifact


def ensure_node_bridge(bridge: str = "jsast", *, script: str = "parse.js") -> pathlib.Path:
    """Install locked Node dependencies beside a cached copy of a packaged script."""
    node = _require_tool("node")
    del node  # validation only; callers execute Node themselves
    source_script = bridge_source(bridge, script)
    package_json = bridge_source(bridge, "package.json")
    package_lock = bridge_source(bridge, "package-lock.json")
    inputs = [source_script, package_json, package_lock]
    fingerprint = _fingerprint(source_script.parent, inputs, kind=f"node:{bridge}:{script}")
    runtime_dir = bridge_cache_root() / "node" / bridge / fingerprint
    cached_script = runtime_dir / script
    ready = runtime_dir / ".ready"
    dependencies = runtime_dir / "node_modules"
    if ready.is_file() and cached_script.is_file() and dependencies.is_dir():
        return cached_script

    with _build_lock(runtime_dir):
        if ready.is_file() and cached_script.is_file() and dependencies.is_dir():
            return cached_script
        npm = _require_tool("npm")
        for source in inputs:
            shutil.copy2(source, runtime_dir / source.name)
        _run_checked(
            [npm, "ci", "--ignore-scripts", "--omit=dev", "--no-audit", "--no-fund"],
            purpose=f"installing locked dependencies for the {bridge!r} Node bridge",
            cwd=runtime_dir,
        )
        if not dependencies.is_dir():
            raise BridgeRuntimeError(
                f"installing the {bridge!r} Node bridge succeeded but produced no node_modules directory"
            )
        ready.write_text(f"{fingerprint}\n", encoding="utf-8")
    return cached_script


def ruby_bridge(script: str, *, bridge: str = "rubyast") -> pathlib.Path:
    """Return a packaged Ruby bridge after validating the Ruby runtime."""
    _require_tool("ruby")
    return bridge_source(bridge, script)
