#!/usr/bin/env python3
"""OpenHack OSINT deep-research MCP — passive intelligence gathering.

Wraps the vendored gpt-researcher (``vendor/gpt-researcher``) as an MCP server
so the osint/recon specialist agents can run deep web research (CT logs,
passive DNS exposure, leaked credentials chatter, tech-stack reconnaissance)
through one bounded, evidence-producing tool.

Authorized use only: like every MCP tool, calls remain subject to the runtime's
safety/scope/ROE enforcement — this server only provides the transport.

Run inside the vendored venv (``vendor/gpt-researcher/.venv``):
    vendor/gpt-researcher/.venv/bin/python packages/openhack/mcp/osint_research.py

Environment: standard gpt-researcher config (OPENAI_API_KEY or the provider
keys its config resolves; TAVILY_API_KEY for retrieval). Bounded by
OPENHACK_RESEARCH_TIMEOUT_S (default 600).

Tools:
  research(query, report_type) -> structured report: markdown file path,
     sources, and cost. Writes the report under .openhack/osint/.
  research_status()            -> whether the vendored engine is importable.
"""
import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Self-heal a scrubbed spawn environment before importing gpt_researcher.
_path = os.environ.get("PATH", "").split(os.pathsep)
for _d in ("/usr/bin", "/bin", "/usr/local/bin"):
    if _d and _d not in _path:
        _path.append(_d)
os.environ["PATH"] = os.pathsep.join([p for p in _path if p])

mcp = FastMCP("osint-research")

TIMEOUT_S = int(os.environ.get("OPENHACK_RESEARCH_TIMEOUT_S", "600"))
REPORT_TYPES = ("research_report", "outline_report", "resource_report")


def _output_dir() -> Path:
    d = Path(os.environ.get("OPENHACK_OSINT_DIR", ".openhack/osint"))
    d.mkdir(parents=True, exist_ok=True)
    return d


@mcp.tool()
async def research_status() -> str:
    """Report whether the vendored gpt-researcher engine is importable."""
    try:
        import gpt_researcher  # noqa: F401

        return json.dumps({"ok": True, "engine": "gpt-researcher", "timeout_s": TIMEOUT_S})
    except Exception as exc:  # noqa: BLE001 — surfaced verbatim
        return json.dumps({
            "ok": False,
            "error": f"gpt-researcher not importable (bootstrap: vendor/gpt-researcher/bootstrap.sh): {exc}",
        })


@mcp.tool()
async def research(query: str, report_type: str = "research_report") -> str:
    """Run a bounded deep-research pass for an OSINT query.

    Args:
        query: the research question (passive intelligence only — no active probing).
        report_type: one of research_report | outline_report | resource_report.
    Returns:
        JSON: {ok, report_path, summary, sources, cost_usd, duration_s}.
    """
    if not query.strip():
        return json.dumps({"ok": False, "error": "query is required"})
    if report_type not in REPORT_TYPES:
        return json.dumps({"ok": False, "error": f"report_type must be one of {REPORT_TYPES}"})
    try:
        from gpt_researcher import GPTResearcher
    except Exception as exc:  # noqa: BLE001 — surfaced verbatim
        return json.dumps({
            "ok": False,
            "error": f"gpt-researcher not importable (bootstrap: vendor/gpt-researcher/bootstrap.sh): {exc}",
        })

    started = time.monotonic()
    try:
        researcher = GPTResearcher(query=query.strip(), report_type=report_type, verbose=False)
        await asyncio.wait_for(researcher.conduct_research(), timeout=TIMEOUT_S)
        report = await asyncio.wait_for(researcher.write_report(), timeout=TIMEOUT_S)
    except asyncio.TimeoutError:
        return json.dumps({
            "ok": False,
            "error": f"research timed out after {TIMEOUT_S}s (tune OPENHACK_RESEARCH_TIMEOUT_S)",
            "duration_s": round(time.monotonic() - started, 1),
        })
    except Exception as exc:  # noqa: BLE001 — surfaced verbatim to the agent
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    duration = round(time.monotonic() - started, 1)
    digest = hashlib.sha256(query.strip().encode()).hexdigest()[:12]
    path = _output_dir() / f"research-{digest}.md"
    header = (
        f"# OSINT research — {query.strip()}\n\n"
        f"- engine: gpt-researcher ({report_type})\n"
        f"- duration_s: {duration}\n"
        f"- cost_usd: {researcher.get_costs():.4f}\n"
        f"- generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n\n"
    )
    path.write_text(header + report)

    sources = researcher.get_research_sources() or []
    source_items = []
    for source in sources[:25]:
        if isinstance(source, dict):
            source_items.append({"url": source.get("url"), "title": source.get("title")})
        else:
            source_items.append({"url": str(source)})
    summary = report.strip().split("\n")[0][:280]
    return json.dumps({
        "ok": True,
        "report_path": str(path),
        "summary": summary,
        "sources": source_items,
        "cost_usd": round(researcher.get_costs(), 4),
        "duration_s": duration,
    })


if __name__ == "__main__":
    mcp.run()
