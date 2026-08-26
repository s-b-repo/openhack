# src/lattice/mcp/__init__.py
"""Lattice MCP server — a stateful cache around the load_network -> analysis seam.

Ingest a repo once (the slow LSP/AST pass), then answer impact/hunt/secaudit/triage
queries against the cached graph in milliseconds. Gives a coding agent the structural
feedback loop it otherwise lacks: blast radius before an edit, a bug gate after.
"""
from lattice.mcp.workspace import Workspace

__all__ = ["Workspace"]
