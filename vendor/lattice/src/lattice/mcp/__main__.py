# src/lattice/mcp/__main__.py
"""Entry point: `python -m lattice.mcp --root <repo>` (console script `lattice-mcp`).

Serves the Lattice analyses over stdio MCP for a coding agent. Point `--root` at the
repository you want structural feedback on; the graph is ingested on first use and
cached under <root>/.lattice/.
"""
from __future__ import annotations

import argparse

from lattice.mcp.server import build_server


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="lattice-mcp",
        description="Lattice MCP server — structural analysis (impact/hunt/secaudit/triage) "
                    "over a cached code graph, for coding agents.")
    ap.add_argument("--root", default=None,
                    help="default repository root served when a tool omits `root`")
    ap.add_argument("--cache-dir", default=None,
                    help="override the graph cache directory (default: <root>/.lattice)")
    args = ap.parse_args(argv)

    server = build_server(default_root=args.root, cache_dir=args.cache_dir)
    server.run()          # stdio transport
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
