#!/usr/bin/env python3
"""
OpenHack Camoufox MCP — a stealth-browser MCP server for AUTHORIZED assessments.

Wraps Camoufox (an anti-detect Firefox fork) so an OpenHack agent can drive a real
browser that passes Cloudflare's managed challenge and carries the resulting
cf_clearance across requests — the exact capability needed to test targets whose
app layer sits behind a bot-mitigation WAF.

Authorized use only. Every call is still subject to the engagement's scope/ROE
enforcement in the OpenHack runtime; this server only provides the transport.

Runtime (validated combo): camoufox 0.4.11 + playwright 1.49.1 + mcp>=1.2, using
Camoufox virtual-display mode (headless="virtual", via Xvfb) which reliably clears
managed challenges. Override the mode with CAMOUFOX_HEADLESS (virtual|true|false).

Design: the SYNC Camoufox API passes managed challenges reliably (the async API
does not), so the browser is owned by a single dedicated worker thread (Playwright
sync objects are thread-affine) and async MCP tools marshal calls to it.

Tools:
  browser_status()                         -> whether a browser/session is live
  goto(url, wait_challenge, timeout_ms)    -> navigate; auto-wait for CF to clear
  fetch(url, method, headers, body)        -> API call carrying the warm session
  get_cookies(names)                       -> cookie presence (values masked)
  storage_state_save(path) / _load(path)   -> persist / restore a warm session
  screenshot(path)                         -> full-page PNG to disk (evidence)
  close()                                  -> tear down the browser
"""
import os
import json
import asyncio
import functools
from typing import Optional, Union
from concurrent.futures import ThreadPoolExecutor

from mcp.server.fastmcp import FastMCP

# Self-heal a scrubbed spawn environment BEFORE importing camoufox: virtual-display
# mode shells out to `Xvfb`, so PATH must include the system bin dirs, and HOME must
# point at the real user dir (that's where the fetched Camoufox binary + cache live).
# Some MCP hosts spawn servers with a minimal env; this keeps stealth mode working.
_path = os.environ.get("PATH", "").split(os.pathsep)
for _d in ("/usr/bin", "/bin", "/usr/local/bin", os.path.expanduser("~/.local/bin")):
    if _d and _d not in _path:
        _path.append(_d)
os.environ["PATH"] = os.pathsep.join([p for p in _path if p])
if not os.environ.get("HOME") or not os.path.isdir(os.environ["HOME"]):
    os.environ["HOME"] = os.path.expanduser("~") or "/home/kali"

from camoufox.sync_api import Camoufox

mcp = FastMCP("openhack-camoufox")

# Persistent profile: cf_clearance + login cookies + storage survive across runs, so
# the Cloudflare challenge and any login are solved ONCE and reused. Override with
# CAMOUFOX_PROFILE. Different engagements can point at different profile dirs.
PROFILE = os.environ.get("CAMOUFOX_PROFILE", os.path.expanduser("~/.cache/openhack-camoufox/profile"))

_CHALLENGE_MARKERS = ("Just a moment", "challenge-platform", "Performing security verification", "cf_chl", "cf-mitigated")

# Single worker thread owns the sync browser (Playwright sync is thread-affine).
_executor = ThreadPoolExecutor(max_workers=1)
_b: dict = {"cm": None, "browser": None, "page": None}


def _headless_mode():
    mode = os.environ.get("CAMOUFOX_HEADLESS", "virtual")
    return True if mode == "true" else False if mode == "false" else mode


async def _run(fn, *a, **kw):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, functools.partial(fn, *a, **kw))


def _is_challenge(html: str) -> bool:
    return any(m in html for m in _CHALLENGE_MARKERS)


# ── sync worker functions (run only on the executor thread) ──────────────────
def _sync_ensure():
    if _b["page"] is None:
        os.makedirs(PROFILE, exist_ok=True)
        # persistent_context=True → cookies (cf_clearance + login) + storage persist
        # in PROFILE across launches. Camoufox stealth is bound to this context.
        cm = Camoufox(headless=_headless_mode(), humanize=True, persistent_context=True, user_data_dir=PROFILE)
        ctx = cm.__enter__()  # BrowserContext when persistent
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        _b.update(cm=cm, browser=ctx, page=page)
    return _b["page"]


def _sync_solve_turnstile(page):
    """Humanized-click the Cloudflare 'verify you are a human' checkbox. The widget
    lives in a cross-origin iframe whose DOM CF blocks, so we click at the widget's
    on-screen position (checkbox is on the left, vertically centered)."""
    sels = [
        "iframe[src*='challenges.cloudflare.com']",
        "iframe[title*='Widget containing a Cloudflare security challenge']",
        "iframe[title*='challenge']",
        "div.cf-turnstile", "#cf-chl-widget", "#challenge-stage", "#turnstile-wrapper",
    ]
    for sel in sels:
        try:
            el = page.query_selector(sel)
        except Exception:
            el = None
        if not el:
            continue
        box = el.bounding_box()
        if not box or box.get("width", 0) < 10:
            continue
        x = box["x"] + min(30, box["width"] / 2)
        y = box["y"] + box["height"] / 2
        try:
            page.mouse.move(x - 60, y + 25)  # approach (humanize adds realism)
            page.wait_for_timeout(120)
            page.mouse.move(x, y)
            page.mouse.click(x, y, delay=70)
            return {"clicked": True, "selector": sel, "x": round(x), "y": round(y)}
        except Exception as e:
            return {"clicked": False, "selector": sel, "error": str(e)}
    return {"clicked": False}


def _sync_goto(url, wait_challenge, timeout_ms):
    page = _sync_ensure()
    resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
    status = resp.status if resp else None
    cleared = True
    if wait_challenge:
        cleared = False
        for i in range(14):  # ~42s
            page.wait_for_timeout(3000)
            # Page CONTENT is the authority — a persistent profile can hold a stale
            # cf_clearance cookie while CF still serves a fresh challenge, so cookie
            # presence alone must NOT be treated as cleared.
            try:
                challenging = _is_challenge(page.content())
            except Exception:
                challenging = True  # navigating (challenge refreshing) — keep waiting
            if not challenging:
                cleared = True
                break
            # interactive Turnstile checkbox may be waiting for a click — solve it
            if i in (1, 4, 8):
                try:
                    _sync_solve_turnstile(page)
                except Exception:
                    pass
    try:
        page.wait_for_load_state("domcontentloaded", timeout=8000)
    except Exception:
        pass
    try:
        text, title = page.inner_text("body")[:4000], page.title()
    except Exception:
        text, title = "", ""
    return {"status": status, "final_url": page.url, "challenge_cleared": cleared, "title": title, "text": text}


def _sync_fetch(url, method, headers, body):
    page = _sync_ensure()
    kwargs = {"method": method.upper(), "headers": headers or {}, "timeout": 45000}
    if body is not None:
        kwargs["data"] = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
    resp = page.context.request.fetch(url, **kwargs)
    return {"status": resp.status, "url": url, "body": resp.text()[:8000]}


def _sync_cookies(names):
    if _b["page"] is None:
        return {}
    out = {}
    for c in _b["page"].context.cookies():
        if names and c["name"] not in names:
            continue
        out[c["name"]] = (c["value"][:10] + "…") if c.get("value") else ""
    return out


def _sync_state_save(path):
    if _b["page"] is None:
        return {"ok": False, "error": "no session"}
    _b["page"].context.storage_state(path=path)
    return {"ok": True, "path": path}


def _sync_state_load(path):
    if not os.path.exists(path):
        return {"ok": False, "error": "path not found"}
    _sync_ensure()
    with open(path) as f:
        state = json.load(f)
    cookies = state.get("cookies", [])
    if cookies:
        _b["page"].context.add_cookies(cookies)
    return {"ok": True, "path": path, "cookies_loaded": len(cookies)}


def _sync_screenshot(path):
    if _b["page"] is None:
        return {"ok": False, "error": "no page"}
    _b["page"].screenshot(path=path, full_page=True)
    return {"ok": True, "path": path}


def _sync_fill(selector, value):
    page = _sync_ensure()
    page.fill(selector, value, timeout=20000)
    return {"ok": True, "selector": selector}


def _sync_click(selector, wait_nav):
    page = _sync_ensure()
    if wait_nav:
        with page.expect_navigation(wait_until="domcontentloaded", timeout=30000):
            page.click(selector, timeout=20000)
    else:
        page.click(selector, timeout=20000)
    return {"ok": True, "selector": selector, "final_url": page.url}


def _sync_evaluate(expression):
    page = _sync_ensure()
    result = page.evaluate(expression)
    try:
        return {"ok": True, "result": result if isinstance(result, (str, int, float, bool, type(None))) else json.loads(json.dumps(result))}
    except Exception:
        return {"ok": True, "result": str(result)}


def _sync_close():
    if _b["cm"] is not None:
        try:
            _b["cm"].__exit__(None, None, None)
        finally:
            _b.update(cm=None, browser=None, page=None)
    return {"ok": True}


# ── MCP tools (async; marshal to the worker thread) ──────────────────────────
@mcp.tool()
async def browser_status() -> str:
    """Report whether a stealth browser session is currently live."""
    return json.dumps({"live": _b["page"] is not None, "mode": os.environ.get("CAMOUFOX_HEADLESS", "virtual")})


@mcp.tool()
async def goto(url: str, wait_challenge: bool = True, timeout_ms: int = 60000) -> str:
    """Navigate the stealth browser to `url`. If `wait_challenge`, poll until the
    Cloudflare managed-challenge clears (cf_clearance issued, up to ~42s), then
    return HTTP status, final URL, whether it cleared, title, and truncated text.
    Use this first to warm cf_clearance before `fetch`."""
    return json.dumps(await _run(_sync_goto, url, wait_challenge, timeout_ms))


@mcp.tool()
async def fetch(url: str, method: str = "GET", headers: Optional[dict] = None, body: Optional[Union[str, dict]] = None) -> str:
    """Make an API request through the browser's context (carries cf_clearance +
    cookies from a prior `goto`). Ideal for wp-json / webhook / gateway endpoints
    once the session is warm. `body` may be a string or JSON object."""
    return json.dumps(await _run(_sync_fetch, url, method, headers, body))


@mcp.tool()
async def get_cookies(names: Optional[list] = None) -> str:
    """List cookies for the current session (values MASKED). Pass `names` to filter
    (e.g. ["cf_clearance","wordpress_logged_in"]). Confirms a warm session."""
    return json.dumps({"cookies": await _run(_sync_cookies, names)})


@mcp.tool()
async def storage_state_save(path: str) -> str:
    """Save the current session (cookies + storage) to a JSON file so a warmed
    Cloudflare/login session can be reloaded later without re-solving."""
    return json.dumps(await _run(_sync_state_save, path))


@mcp.tool()
async def storage_state_load(path: str) -> str:
    """Restore a previously-saved warm session; cookies (cf_clearance / login) are
    added to the stealthy default context so the fingerprint is preserved."""
    return json.dumps(await _run(_sync_state_load, path))


@mcp.tool()
async def screenshot(path: str) -> str:
    """Capture a full-page PNG screenshot to `path` (for evidence)."""
    return json.dumps(await _run(_sync_screenshot, path))


@mcp.tool()
async def fill(selector: str, value: str) -> str:
    """Type `value` into the element matching CSS `selector` (e.g. a login field)."""
    return json.dumps(await _run(_sync_fill, selector, value))


@mcp.tool()
async def click(selector: str, wait_nav: bool = False) -> str:
    """Click the element matching CSS `selector`. Set `wait_nav` to wait for the
    resulting navigation (e.g. a login submit)."""
    return json.dumps(await _run(_sync_click, selector, wait_nav))


@mcp.tool()
async def evaluate(expression: str) -> str:
    """Run a JS expression/function in the page and return its (JSON) result. Async
    functions are awaited — e.g. an in-page `fetch(...)` runs with the logged-in
    cookies and same-origin, ideal for authenticated REST probes with a wp_rest nonce."""
    return json.dumps(await _run(_sync_evaluate, expression))


@mcp.tool()
async def solve_turnstile() -> str:
    """Humanized-click the Cloudflare 'verify you are a human' checkbox if present.
    `goto` already calls this automatically while waiting; use it manually if a
    challenge appears mid-session."""
    if _b.get("page") is None:
        return json.dumps({"clicked": False, "error": "no page — call goto first"})
    return json.dumps(await _run(_sync_solve_turnstile, _b["page"]))


@mcp.tool()
async def close() -> str:
    """Tear down the stealth browser session (session persists on disk in the profile)."""
    return json.dumps(await _run(_sync_close))


if __name__ == "__main__":
    mcp.run()
