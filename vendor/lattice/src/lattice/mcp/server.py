# src/lattice/mcp/server.py
"""FastMCP server exposing Lattice's agent-loop analyses over a cached graph.

Each tool is a thin wrapper over the transport-free callables in tools.py, bound to a
per-root Workspace registry so one server can serve several repos. The headline is
`lattice_impact` — blast radius before an edit — backed by a graph ingested once and
queried in milliseconds.
"""
from __future__ import annotations

import pathlib

from mcp.server.fastmcp import FastMCP

from lattice.mcp import tools
from lattice.mcp.workspace import Workspace


def build_server(default_root=None, cache_dir=None) -> FastMCP:
    """Construct the Lattice MCP server. `default_root` is the repo served when a tool
    call omits `root`; `cache_dir` overrides where each workspace caches its graph."""
    mcp = FastMCP("lattice")
    registry: dict[str, Workspace] = {}
    default = pathlib.Path(default_root).resolve() if default_root else None

    def ws_for(root) -> Workspace:
        r = pathlib.Path(root).resolve() if root else default
        if r is None:
            raise ValueError("no root given and the server has no default --root")
        key = str(r)
        if key not in registry:
            registry[key] = Workspace(r, cache_dir=cache_dir)
        return registry[key]

    @mcp.tool()
    def lattice_map(root: str | None = None, language: str = "auto") -> dict:
        """Ingest a repository into a structural graph (or load the cache) and report
        its size, languages, and attack-surface counts. Run this once per repo; every
        other tool reuses the cached graph. `language`: auto|ts|python|cpp|solidity|...
        """
        return tools.tool_map(ws_for(root), language=language)

    @mcp.tool()
    def lattice_impact(query: str, root: str | None = None) -> dict:
        """Blast radius of a change BEFORE you make it. `query` is a symbol name or a
        file path; for a file, the impact of every symbol it defines is unioned.
        Returns the dependents, affected files, and affected public API a change could
        reach. Run this before editing."""
        return tools.tool_impact(ws_for(root), query)

    @mcp.tool()
    def lattice_hunt(root: str | None = None, severity_min: str = "low") -> dict:
        """Ranked structural bug findings (public_path_to_stub, obstruction,
        called_stub, broken_reference, dead_code, ...). Run this AFTER an edit as a
        gate. `severity_min`: low|medium|high|critical filters the floor."""
        return tools.tool_hunt(ws_for(root), severity_min=severity_min)

    @mcp.tool()
    def lattice_secaudit(root: str | None = None) -> dict:
        """Security audit: attack surface plus which public entrypoints reach dangerous
        sinks, with an honest verified/not_verified contract and TAINTED-vs-reachable
        labels. Not proof of exploitability — it tells you where to look."""
        return tools.tool_secaudit(ws_for(root))

    @mcp.tool()
    def lattice_triage(root: str | None = None) -> dict:
        """Prioritized fix worklist: every bug ranked by severity x (1 + blast radius)
        — how bad times how far it reaches. The order to fix things in."""
        return tools.tool_triage(ws_for(root))

    @mcp.tool()
    def lattice_refresh(root: str | None = None) -> dict:
        """Rebuild the cached graph from the current source tree. Call this after edits
        when a tool's freshness block reports the graph is stale."""
        return tools.tool_refresh(ws_for(root))

    return mcp


def tool_names(mcp: FastMCP) -> list[str]:
    """The registered tool names — used by the smoke test and introspection."""
    return sorted(t.name for t in mcp._tool_manager.list_tools())
