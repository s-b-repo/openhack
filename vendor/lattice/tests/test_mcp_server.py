# tests/test_mcp_server.py
"""Server wiring: the six tools are registered, and a tool call routes through a
per-root workspace to a real result."""
import pytest

from lattice.mcp.server import build_server, tool_names

_EXPECTED = {"lattice_map", "lattice_impact", "lattice_hunt",
             "lattice_secaudit", "lattice_triage", "lattice_refresh"}


def test_server_exposes_the_six_tools():
    mcp = build_server()
    assert set(tool_names(mcp)) == _EXPECTED


def test_default_root_is_used_when_tool_omits_root(tmp_path):
    (tmp_path / "app.py").write_text("def used():\n    return 1\n\ndef main():\n    return used()\n")
    mcp = build_server(default_root=tmp_path)
    fn = mcp._tool_manager.get_tool("lattice_map").fn
    out = fn(language="python")
    assert out["vertices"] > 0
    assert out["root"] == str(tmp_path.resolve())


def test_missing_root_without_default_is_actionable(tmp_path):
    mcp = build_server()                 # no default root
    fn = mcp._tool_manager.get_tool("lattice_impact").fn
    with pytest.raises(ValueError, match="no root"):
        fn(query="x")
