# OpenHack Camoufox MCP (stealth browser)

`camoufox_mcp.py` is a stdio MCP server that drives **Camoufox** (an anti-detect
Firefox fork) so an OpenHack agent can test targets whose app layer sits behind a
Cloudflare **managed challenge** / bot-mitigation WAF. It passes the challenge in
Camoufox virtual-display mode, then carries `cf_clearance` (and any login cookies)
across subsequent requests.

**Authorized use only.** Every call is still gated by the engagement's scope/ROE in
the OpenHack runtime; this server is only the browser transport.

## Install (one-time)

```bash
pipx install camoufox
camoufox fetch                                    # downloads the Camoufox browser (~700MB)
pipx inject camoufox "playwright==1.49.1" "mcp>=1.2"   # 1.49.1 is required — newer breaks Camoufox's Juggler
sudo apt-get install -y xvfb                      # virtual-display mode needs Xvfb
```

The server path is `packages/openhack/mcp/camoufox_mcp.py`; run it with the pipx
venv's Python: `~/.local/share/pipx/venvs/camoufox/bin/python`.

## Enable in a config

Flip `mcp.camoufox.enabled` to `true` in the engagement's `.openhack/openhack.jsonc`
(the repo catalog ships it `enabled:false`). The command is already templated with
`{env:HOME}`. OpenHack passes the full `process.env` to the server, so virtual mode
works. Override the mode with `CAMOUFOX_HEADLESS` = `virtual` (default) | `true` | `false`.

## Tools

| Tool | Purpose |
|---|---|
| `goto(url, wait_challenge, timeout_ms)` | Navigate; auto-wait until the CF challenge clears (cf_clearance issued), auto-clicking the Turnstile checkbox if one appears. Use first to warm the session. |
| `fetch(url, method, headers, body)` | API request through the warm context (carries cf_clearance) — for `wp-json` / webhook / gateway endpoints. |
| `fill(selector, value)` / `click(selector, wait_nav)` | Drive forms (e.g. a login). |
| `evaluate(expression)` | Run JS in the page (async awaited) — e.g. an in-page `fetch` with a `wp_rest` nonce for authenticated REST probes. |
| `solve_turnstile()` | Humanized-click the Cloudflare "verify you are a human" checkbox (also auto-called by `goto`). |
| `get_cookies(names)` | Cookie presence (values masked) — confirm a warm session. |
| `storage_state_save(path)` / `storage_state_load(path)` | Persist / restore a warmed Cloudflare/login session. |
| `screenshot(path)` | Full-page PNG (evidence). |
| `browser_status()` / `close()` | Session lifecycle. |

## Persistent session

The browser uses a **persistent profile** (`CAMOUFOX_PROFILE`, default
`~/.cache/openhack-camoufox/profile`), so `cf_clearance` **and** any WordPress login
survive across runs — you clear Cloudflare (auto-click or one manual click) and log
in **once**, and every later call reuses the session. Point `CAMOUFOX_PROFILE` at a
different dir per engagement. Note: Cloudflare rate-escalates a source IP under heavy
automated traffic; if the managed challenge stops clearing, slow down / let the IP
cool — the persistent session avoids re-solving once it's warm.

## Typical flow (authorized target behind Cloudflare)

1. `goto("https://target/")` → clears the managed challenge, sets `cf_clearance`.
2. `fetch("https://target/wp-json/...")` → authenticated/edge API calls now succeed.
3. For logged-in tests: `goto` the login page, drive it, then `storage_state_save`
   the session and reuse it with `storage_state_load`.

## Notes / gotchas (learned during bring-up)

- **Playwright must be 1.49.1** — newer versions send viewport fields Camoufox's
  patched Juggler rejects (`isMobile ... not described in this scheme`).
- **Use the default context** (`browser.new_page()`), not `new_context()` — Camoufox
  binds its stealth to the default context; a fresh context gets flagged.
- **The sync API passes managed challenges reliably; the async API does not** — the
  server runs the sync browser in one dedicated worker thread.
- **The server needs the real environment** (PATH→Xvfb, HOME→browser cache). OpenHack
  passes full env; the server also self-heals PATH/HOME defensively.
- Detect "cleared" via the **`cf_clearance` cookie**, not page HTML — the challenge
  page auto-navigates and racing `page.content()` throws.
