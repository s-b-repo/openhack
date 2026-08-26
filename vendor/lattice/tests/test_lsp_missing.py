import os
import shlex
import subprocess

import pytest
from lattice.ingest import lsp_client


def test_missing_language_server_raises(monkeypatch, tmp_path):
    (tmp_path / "main.ts").write_text("export const main = 1\n")
    monkeypatch.setattr(lsp_client.shutil, "which", lambda _b: None)
    with pytest.raises(RuntimeError, match="typescript-language-server"):
        lsp_client.ingest(tmp_path, "typescript")


def test_multilspy_language_server_path_is_shell_quoted(tmp_path):
    executable = tmp_path / "server bundle" / "typescript-language-server"
    executable.parent.mkdir()
    executable.write_text('#!/bin/sh\n[ "$1" = "--stdio" ]\n')
    executable.chmod(0o755)

    class LaunchInfo:
        cmd = f"{executable} --stdio"

    class Handler:
        process_launch_info = LaunchInfo()

    class AsyncServer:
        server = Handler()

    class SyncServer:
        language_server = AsyncServer()

    server = SyncServer()
    lsp_client._quote_lsp_launch_command(server)

    command = server.language_server.server.process_launch_info.cmd
    assert "server bundle" in command and "--stdio" in command
    if os.name != "nt":
        assert shlex.split(command) == [str(executable), "--stdio"]
        assert subprocess.run(command, shell=True, check=False).returncode == 0

    # The shim is idempotent; a second pass must not quote the quote characters.
    lsp_client._quote_lsp_launch_command(server)
    assert server.language_server.server.process_launch_info.cmd == command
