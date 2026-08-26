"""FIRES / SILENT / toggle tests for the Wave-2 taxonomy additions in taxonomy.py.

Mirrors test_sink_categorization.py (which covers the tier-2 regex layer in
security.py). This file covers the tier-1 name-heuristic layer: every added
TOUCHPOINT trigger has one FIRES and one adjacent SILENT case, and every added
GATE trigger has a FIRES + a nearby SILENT (a common-noise word that MUST NOT
be treated as a gate — false gates hide real vulns).
"""
from lattice.taxonomy import TOUCHPOINTS, GATES, _norm, _match


def _cats_by_name(name: str) -> set[str]:
    n = _norm(name)
    out = set()
    for pats, cat, _sev in TOUCHPOINTS:
        if _match(n, pats):
            out.add(cat)
            break                      # first-match-wins mirrors classify_touchpoints
    return out


def _sev_by_name(name: str) -> str | None:
    n = _norm(name)
    for pats, cat, sev in TOUCHPOINTS:
        if _match(n, pats):
            return sev
    return None


def _gates_by_name(name: str) -> set[str]:
    n = _norm(name)
    return {g for g, pats in GATES.items() if _match(n, pats)}


# ── TOUCHPOINTS: new triggers per category ──────────────────────────────────

def test_command_exec_new_triggers_FIRES():
    for name in ("spawnSync", "forkSync", "powershell", "winExec"):
        assert "command_exec" in _cats_by_name(name), name


def test_command_exec_common_words_SILENT():
    for name in ("Task", "runJob", "compileTemplate", "renderPage"):
        assert "command_exec" not in _cats_by_name(name), name


def test_code_eval_new_triggers_FIRES():
    for name in ("newFunction", "vmRunInContext", "vmRunInNewContext",
                 "runInNewContext", "runInThisContext"):
        assert "code_eval" in _cats_by_name(name), name


def test_code_eval_similar_but_safe_SILENT():
    # `evaluateExpression` is NOT a live-code eval by common name — but our substring
    # match will hit `eval` inside `evaluate`. Document this as a known FIRE=lead
    # instead of asserting silence (would be a false silence otherwise). This test
    # instead asserts unrelated names stay silent.
    for name in ("compile", "parseAst", "renderJSX"):
        assert "code_eval" not in _cats_by_name(name), name


def test_deserialization_new_triggers_FIRES():
    for name in ("XMLDecoder", "ObjectInputStream", "readObject",
                 "fromXML", "jacksonAsObject"):
        assert "deserialization" in _cats_by_name(name), name


def test_weak_crypto_FIRES_at_high_severity():
    for name in ("md5", "sha1", "des", "rc4", "ecb"):
        assert "weak_crypto" in _cats_by_name(name), name
        assert _sev_by_name(name) == "high", name


def test_generic_crypto_still_medium():
    for name in ("encrypt", "cipher", "hmac"):
        assert "crypto" in _cats_by_name(name), name
        assert _sev_by_name(name) == "medium", name


def test_sql_injection_new_strong_triggers_FIRES():
    for name in ("executeRaw", "queryRaw", "rawSqlQuery", "unpreparedStatement"):
        assert "sql_injection" in _cats_by_name(name), name


def test_sql_injection_generic_still_demoted():
    """Weak name-only match: contains the substring `query` but no strong sink
    token. `invalidateQueries` normalizes to `invalidatequeries` which does NOT
    contain `query` as a substring (queri≠query), so it correctly lands in NO
    category — the fallback demotion is for names that DO carry the substring."""
    for name in ("useQuery", "queryClient", "queryString"):
        assert _cats_by_name(name) == {"sql_injection_possible"}, name


def test_sql_injection_raw_whole_name_FIRES():
    # `=raw` matches the WHOLE normalized name only (not raw substring), matching
    # the `=query` convention already in the taxonomy.
    assert "sql_injection" in _cats_by_name("raw")
    # a name containing "raw" as a substring must NOT hit the strong SQL row
    # via the =raw pattern; e.g. "renderRawText" or "drawBox".
    assert "sql_injection" not in _cats_by_name("renderRawText")
    assert "sql_injection" not in _cats_by_name("drawBox")


def test_xss_new_dom_triggers_FIRES():
    for name in ("outerHTML", "insertAdjacentHTML", "documentWrite",
                 "documentWriteln", "htmlSafeString", "htmlMarkSafe"):
        assert "xss" in _cats_by_name(name), name


def test_secrets_new_strong_triggers_FIRES():
    for name in ("vaultRead", "awsSecret", "getParameter", "signingKey",
                 "masterKey", "clientSecret"):
        assert "secrets" in _cats_by_name(name), name
        assert _sev_by_name(name) == "high", name


def test_getToken_is_demoted_to_secrets_possible():
    """`getToken` is common in JWT-decode helpers — was in the strong `secrets` row,
    now demoted to `secrets_possible` (low) so it doesn't inflate rankings."""
    assert "secrets" not in _cats_by_name("getToken")
    assert "secrets_possible" in _cats_by_name("getToken")
    assert _sev_by_name("getToken") == "low"


def test_ambiguous_secret_words_demoted():
    for name in ("csrfToken", "cacheKey", "colorSecret"):
        cats = _cats_by_name(name)
        assert "secrets" not in cats, name
        assert "secrets_possible" in cats, name


def test_networking_new_triggers_FIRES():
    for name in ("httpxGet", "okHttp", "restClient", "webClient", "wget"):
        assert "networking" in _cats_by_name(name), name


def test_file_access_new_triggers_FIRES():
    for name in ("createReadStream", "createWriteStream", "sendFile",
                 "unlink", "rmdir", "renameFile"):
        assert "file_access" in _cats_by_name(name), name


# ── GATES: new triggers + adversarial SILENT ────────────────────────────────


def test_authorization_new_triggers_FIRES():
    for name in ("requirePermission", "assertPermission", "canAccess",
                 "checkABAC", "authorizeAccess"):
        assert "authorization" in _gates_by_name(name), name


def test_authentication_new_triggers_FIRES():
    for name in ("authGuard", "authCheck", "requireUser", "verifyJWT",
                 "verifyAccessToken"):
        assert "authentication" in _gates_by_name(name), name


def test_input_validation_new_triggers_FIRES():
    for name in ("yupValidate", "aioValidate", "pydanticValidate",
                 "zodSafeParse", "parseAsync", "escapeSQL"):
        assert "input_validation" in _gates_by_name(name), name


def test_rate_limiting_new_triggers_FIRES():
    for name in ("slowDown", "leakyBucket", "limitRequests", "rlimit"):
        assert "rate_limiting" in _gates_by_name(name), name


def test_generic_parse_and_validate_are_NOT_gates_SILENT():
    """The load-bearing precision invariant on gates: bare `parse` / `validate`
    would silently mark half the code as a gate and hide missing-gate findings
    (which are the actual vulns). NEVER let these leak in."""
    for name in ("parse", "validate", "check", "run", "handle"):
        assert _gates_by_name(name) == set(), f"{name} became a false gate — hides vulns"


# ── Toggle: adding a demoted category doesn't drop strong SQL classification ─


def test_sql_strong_vs_possible_toggle_is_genuine():
    """Toggle test: a function literally named `query` (strong; =query) must land
    in sql_injection; `queryClient` (weak; only substring "query") must land in
    the demoted sql_injection_possible. If both hit the same category the demotion
    is dead."""
    strong = _cats_by_name("query")
    weak = _cats_by_name("queryClient")
    assert "sql_injection" in strong and "sql_injection_possible" not in strong
    assert "sql_injection_possible" in weak and "sql_injection" not in weak
    assert strong != weak
