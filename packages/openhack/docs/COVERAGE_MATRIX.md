# Coverage Matrix — worked example

This is a **reference example** of a completed OpenHack coverage matrix: the exact
artifact the engine's `Coverage` + `Combinations` tracker is designed to converge
toward — a per-engagement grid asserting that *every type of test that can be done*
has actually been attempted on the target, with an explicit status and evidence for
each vector.

It maps every **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)**
category (67) plus the HTTP-method / request-smuggling vectors to what was actually
done against a self-hosted test target (Gole Service Desk, `localhost:5078`). Use it
as a template for how to document coverage and, when reviewing gaps, as a checklist
of vectors worth exercising.

Most rows correspond to a `Checklist.VulnClass` id in
[`../src/checklist.ts`](../src/checklist.ts) (e.g. row 51 SQLi → `sqli`, row 49 SSRF →
`ssrf`, row 36 Mass Assignment → `api-bola-bfla`). Categories present here but **not
yet** modelled as first-class `Checklist` classes — CSV injection, LaTeX injection,
tabnabbing, DOM clobbering, dependency confusion, DNS rebinding, type juggling, zip
slip, XSLT, XS-Leak — are candidates for future `CLASSES[]` entries (see
`../knowledge/README.md` → "Adding a class").

> Provenance: this matrix is a demonstration artifact against the author's own
> local test app. Real per-engagement matrices live under `.openhack/` and are
> git-ignored (never commit client findings, scope, or ROE); this committed copy
> exists only as a methodology reference.

---

**Legend:** ✅ live-tested (dynamic) · 📖 source-reviewed (white-box) · ⚪ N/A (not in stack) · ⛔ gap (not tested) · ⚠️ finding

| # | Vector (PayloadsAllTheThings) | Status | Result / Evidence |
|---|---|---|---|
| 1 | Account Takeover | 📖✅ | Reset flow non-enumerable; SMTP off; no takeover path. Password-hash verify used to disprove leaked creds. |
| 2 | API Key Leaks | ✅ | `ApiKeys` table empty; keys stored as `KeyHash`; none leaked in OpenAPI/responses. |
| 3 | Brute Force / Rate Limit | ✅ | **Strong.** Lockout 5/15min + `auth` 20/min (429 at 21st) + CAPTCHA per POST. |
| 4 | Business Logic Errors | ✅📖 | Partial: reg-approval gate, MustChangePassword, rate limits verified. Not exhaustive (billing/SLA edge cases ⛔). |
| 5 | Clickjacking | ✅ | Protected: `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'`. |
| 6 | Client-Side Path Traversal | ⚪📖 | Low applicability; not exercised. |
| 7 | Command Injection | 📖 | None — only fixed `sw_vers`/`/etc/os-release`, no user input reaches `Process.Start`. |
| 8 | CORS Misconfiguration | ✅ | No CORS configured; no `Access-Control-Allow-Origin`. Safe. |
| 9 | CRLF Injection | ✅ | Safe — `returnUrl` kept URL-encoded in body, never in response headers (raw-socket verified). |
| 10 | CSRF | 📖✅ | Antiforgery global; `X-CSRF-TOKEN`; SameSite cookies; POSTs validated. |
| 11 | CSS Injection | 📖 | CSP `style-src 'unsafe-inline'` would allow it *if* HTML injection existed — none found. |
| 12 | CSV Injection | ✅⚠️ | Not exploitable now: `Escape()` lacks formula-neutralization, but exports emit only server-controlled labels; `Status` not attacker-settable. **Latent — fix defensively.** |
| 13 | CVE Exploits | ✅ | `nuclei` full templates: no CVE matched (.NET 10, patched deps). |
| 14 | Denial of Service | ✅⚠️ | Rate limits present. Two unhandled-500s found (F-13 CI Index, F-02 PK collision). No resource-exhaustion DoS run. |
| 15 | Dependency Confusion | ⚪ | Not applicable to a runtime pentest. |
| 16 | Directory Traversal | ✅ | Safe — sensitive files 404; attachment DL by GUID id; tenant-logo path guarded. |
| 17 | DNS Rebinding | 📖 | `AllowedHosts:"*"` is relevant (F-09); no live rebinding test. |
| 18 | DOM Clobbering | ⚪📖 | nonce-CSP mitigates; not exercised. |
| 19 | Encoding Transformations | ✅ | Covered via XSS/injection encoding variants (entity/case/whitespace). |
| 20 | External Variable Modification | ✅ | = Mass assignment (see #36). |
| 21 | File Inclusion (LFI/RFI) | ✅ | Safe — no file/path params; static content 404. |
| 22 | Google Web Toolkit | ⚪ | Not in stack. |
| 23 | GraphQL Injection | ⚪ | No GraphQL. |
| 24 | Headless Browser | ⚪ | N/A. |
| 25 | Hidden Parameters | ✅ | Overposting probe (see #36). |
| 26 | HTTP Parameter Pollution | ✅ | Duplicate `page`/`searchTerm` params — no effect. Safe. |
| 27 | Insecure Deserialization | 📖 | System.Text.Json only; no BinaryFormatter/TypeNameHandling. |
| 28 | IDOR | 📖✅ | Ownership checks + tenant query filters in source; runtime **limited** (1 tenant / 2 users). Partial — ⛔ needs a 2nd low-priv account. |
| 29 | Insecure Management Interface | ✅ | `/metrics`, `/healthz/perf` token-gated (401); admin behind auth. |
| 30 | Insecure Randomness | 📖 | `RandomNumberGenerator` for nonces + GUID filenames. |
| 31 | Insecure Source Code Mgmt | ✅ | `/.git/config` → 404. |
| 32 | Java RMI | ⚪ | N/A. |
| 33 | JSON Web Token | ⚪ | No JWT — API-key handler instead. |
| 34 | LaTeX Injection | ⚪ | N/A. |
| 35 | LDAP Injection | 📖 | `DirectoryAuthenticator` exists but **no directory configured** → not exploitable now. Live filter-injection ⛔ (needs a connection). |
| 36 | Mass Assignment | ✅⚠️ | **F-02:** ticket `Create` binds client `Id` (arbitrary PK + 500 on collision). `CreatedById`/`TenantId`/`CreatedAt` correctly server-resolved. |
| 37 | NoSQL Injection | ⚪ | SQLite (relational). |
| 38 | OAuth Misconfiguration | 📖 | OIDC disabled by default (PKCE, SaveTokens=false when on). |
| 39 | Open Redirect | ✅ | Safe — login/logout/sessionlock `returnUrl` all rejected external (`Url.IsLocalUrl`). |
| 40 | ORM Leak | 📖 | EF projections; no obvious over-exposure; not deeply fuzzed. |
| 41 | Prompt Injection | ⚪ | AI provider = `none` (disabled). |
| 42 | Prototype Pollution | ⚪📖 | Client-side; not exercised. |
| 43 | Race Condition | ⛔ | **Gap** — needs a concurrency harness (e.g., last-SysAdmin guard, tenant-request approval). Not run. |
| 44 | Regular Expression (ReDoS) | 📖 | No user-input-compiled regex found; not fuzzed. |
| 45 | Request Smuggling | ✅ | TE.CL / TE-obfuscation → **400 rejected**. CL+TE & bare-LF accepted but **no fronting proxy → no desync** (informational). |
| 46 | Reverse Proxy Misconfig | ⚪ | Direct Kestrel (no proxy); `ForwardedHeaders` absent (noted). |
| 47 | SAML Injection | 📖 | SAML not configured (`/Saml/*` 404); ITfoxtec signature validation. |
| 48 | Server-Side Include | ⚪ | N/A. |
| 49 | SSRF | 📖 | `SsrfGuard` hardened handlers on ALL outbound clients + `ValidateUrlWithDnsAsync`; host-allowlist. Live test ⛔ (needs a stored integration/PBX/directory connection). |
| 50 | Server-Side Template Injection | ✅ | Safe — `${}/{{}}/#{}/<%%>/@()` with distinctive product `1787569` → no evaluation, not reflected. |
| 51 | SQL Injection | ✅ | Safe — `'` / `' OR '1'='1` / `--` / `UNION SELECT` on KB+Tickets search treated literally; parameterized EF, no 500s. |
| 52 | Tabnabbing | ⛔ | Not tested (`target=_blank` `rel=noopener` audit). Low priority. |
| 53 | Type Juggling | ⚪ | Strongly-typed .NET model binding. |
| 54 | Upload Insecure Files | ✅⚠️ | Attachments: allowlist (no exe/script), GUID name, outside webroot — safe. Tenant-logo SVG denylist weak (**F-03**) but CSP-mitigated. |
| 55 | Virtual Hosts | ✅⚠️ | **F-09:** `AllowedHosts:"*"` accepts any `Host` (200). |
| 56 | Web Cache Deception | 📖 | No cache layer (direct Kestrel); not exploitable. |
| 57 | Web Sockets | ⚪ | Only external Jitsi (`wss://meet.jit.si`); no app WS. |
| 58 | XPATH Injection | ⚪ | No XPath. |
| 59 | XS-Leak | ⚪📖 | Not exercised. |
| 60 | XSLT Injection | ⚪ | No XSLT. |
| 61 | XSS Injection | ✅ | Safe — ticket/KB/announcement rich-text encoded; `SafeMarkdown` neutralizes scheme links + raw HTML; nonce-CSP (even on static files). 0 executable nodes across all payloads. |
| 62 | XXE Injection | ✅ | Safe — XML POSTs → 401/not-parsed; no `/etc/passwd` leak (System.Text.Json app; SVG parsed as string, not XML entities). |
| 63 | Zip Slip | 📖 | No zip extraction (`.zip` stored as-is with GUID name) → no surface. |
| — | **All HTTP methods** (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS/TRACE/PROPFIND/arbitrary) | ✅ | No method-based authz bypass — every method → uniform `302→login` on protected paths. `X-HTTP-Method-Override` not honored. |
| — | Reverse-proxy `X-Forwarded-*` spoofing | ⚪ | No proxy; `ForwardedHeaders` not enabled (rate-limit partitions by real RemoteIp). |

## Gaps still open (would extend coverage)
1. **IDOR / privilege escalation (exhaustive)** — needs a 2nd low-privilege account (blocked by a 2nd CAPTCHA login).
2. **SSRF (live)** — create an integration/PBX/directory connection pointing at `169.254.169.254` / `127.0.0.1` and trigger its test-connection to confirm `SsrfGuard` blocks in practice.
3. **Race conditions** — concurrency harness against uniqueness/approval guards.
4. **Authenticated sqlmap / full DAST** — blocked because the session cookie is HttpOnly (can't hand it to external tools); replaced with manual in-session injection probes.
5. **Client-side** (tabnabbing, XS-Leak, prototype pollution) and **ReDoS** — low priority given the nonce-CSP and no user-compiled regex.
6. **Business-logic depth** (billing/SLA/workflow abuse) — spot-checked only.

## New findings this round
- **F-13 (Low/Availability):** `GET /ConfigurationItems/Index` → **HTTP 500** for everyone. Root cause: `Views/ConfigurationItems/Index.cshtml` line 1 `@model IEnumerable<...CallSession>` but the controller passes `List<ConfigurationItem>` (copy-paste error). Fix the `@model`.
- **F-14 (Info/Latent):** `AnalyticsController.Escape()` performs CSV quoting but no formula-injection neutralization. Not exploitable today (exports carry only server-controlled labels), but will become exploitable if any raw user field (title/name/description) is ever added to an export. Prefix cells starting with `= + - @ \t \r` with a `'`.
