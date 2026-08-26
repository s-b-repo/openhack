# src/lattice/taxonomy.py
"""The operation taxonomy — touchpoints and gates as data, classified by name.

Touchpoints = sensitive operations a path may reach (sinks). Gates = required
waypoints a path should cross before a sink. Both feed the single guarded_reachability
engine; adding a concern is a row here, not new code.

Precision bias differs by kind:
  - touchpoints lean RECALL (a false touchpoint = extra review, harmless)
  - gates lean PRECISION (a false gate would make a path look guarded and HIDE a real
    missing-gate finding — a false negative on a vuln). So gate patterns stay specific.
"""
from __future__ import annotations

# (name substrings) -> (category, severity). First match wins, top to bottom.
# A pattern starting with "=" matches the WHOLE normalized name, not a substring
# (e.g. "=query" hits a function literally named `query`, not getQueryParams).
TOUCHPOINTS = [
    (("spawn", "spawnsync", "forksync", "popen", "childprocess", "execcommand",
      "execsync", "ossystem", "shellexec", "execfile", "powershell", "winexec"),
     "command_exec", "critical"),
    (("eval", "functionconstructor", "newfunction",
      "vmrunincontext", "vmruninnewcontext", "runinnewcontext", "runinthiscontext"),
     "code_eval", "critical"),
    (("deserialize", "unserialize", "pickle", "unpickle", "marshal", "yamlload",
      "xmldecoder", "objectinputstream", "readobject", "fromxml", "jacksonasobject"),
     "deserialization", "high"),
    # Weak-crypto (broken primitives). Placed BEFORE the generic `crypto` row so
    # md5/sha1/des/rc4/ecb take the higher-severity category rather than the medium
    # generic one (first-match-wins).
    (("md5", "sha1", "des", "rc4", "ecb"), "weak_crypto", "high"),
    (("rawsql", "sqlquery", "rawquery", "sqlexec", "dbquery", "executequery",
      "runquery", "executeraw", "queryraw", "rawsqlquery", "unpreparedstatement",
      "=query", "=raw"), "sql_injection", "high"),
    (("innerhtml", "outerhtml", "insertadjacenthtml", "dangerouslyset", "renderhtml",
      "documentwrite", "documentwriteln", "htmlsafestring", "htmlmarksafe"),
     "xss", "high"),
    # Strong secret-access names (unambiguous). Ambiguous tokens fall through to
    # the `secrets_possible` fallback row (see below).
    (("getsecret", "vaultread", "awssecret", "getparameter", "apikey",
      "credential", "privatekey", "signingkey", "masterkey", "clientsecret"),
     "secrets", "high"),
    (("fetch", "urlopen", "httprequest", "urlget", "axios",
      "httpxget", "okhttp", "restclient", "webclient", "wget"),
     "networking", "medium"),
    (("encrypt", "decrypt", "cipher", "hmac"), "crypto", "medium"),
    (("writefile", "readfile", "openfile", "createreadstream", "createwritestream",
      "sendfile", "unlink", "rmdir", "renamefile"),
     "file_access", "medium"),
    # LAST rows: generic-word fallbacks (FIRE=lead). A name containing a weak token
    # with none of the strong tokens above (getQueryParams, getTokenBalance,
    # fetchUserAvatar…) is name-only evidence — still reported, but as its own
    # demoted category so URL/cache/JWT-helpers can't pollute high-severity rankings.
    (("query",), "sql_injection_possible", "low"),
    (("gettoken", "token", "secret", "key"), "secrets_possible", "low"),
]

# gate_name -> specific patterns that satisfy the gate (kept narrow on purpose)
GATES = {
    "authorization": ("authorize", "isauthorized", "hasrole", "haspermission",
                      "requirerole", "checkaccess", "checkpermission", "enforceacl",
                      "requirepermission", "assertpermission", "canaccess",
                      "checkabac", "authorizeaccess"),
    "authentication": ("authenticate", "isauthenticated", "requireauth",
                       "verifytoken", "verifysession", "requirelogin",
                       "authguard", "authcheck", "requireuser", "verifyjwt",
                       "verifyaccesstoken"),
    "input_validation": ("validateinput", "sanitize", "escapehtml",
                         "validateschema", "zodparse", "joivalidate",
                         "yupvalidate", "aiovalidate", "pydanticvalidate",
                         "zodsafeparse", "parseasync", "escapesql"),
    "rate_limiting": ("ratelimit", "throttle", "tokenbucket", "checkquota",
                      "slowdown", "leakybucket", "limitrequests", "rlimit"),
}


def _norm(name: str) -> str:
    return "".join(c for c in name.lower() if c.isalnum())


def _match(n: str, pats) -> bool:
    """Substring match, except "=name" patterns which require the whole name."""
    return any(n == p[1:] if p.startswith("=") else p in n for p in pats)


def _real(v) -> bool:
    return v.kind not in ("external", "module")


import re as _re
_TEST_PATH = _re.compile(r"(^|/)(tests?|__tests__|spec)/|\.(test|spec)\.[jt]sx?$|\.(test|spec)\.")


def is_test_file(path: str) -> bool:
    """Test files aren't shipped — they're not part of the attack surface. A spawn()
    in a *.test.ts is a fixture, not a vulnerability; including it floods the audit."""
    return bool(_TEST_PATH.search(path or ""))


def classify_touchpoints(net) -> dict:
    """{category: (set_of_vids, severity)} — sensitive-op sinks present in the graph."""
    out: dict = {}
    for v in net.vertices:
        if not _real(v) or is_test_file(v.file):
            continue
        n = _norm(v.name)
        for pats, cat, sev in TOUCHPOINTS:
            if _match(n, pats):
                out.setdefault(cat, (set(), sev))[0].add(v.id)
                break
    return out


def gate_vertices(net) -> dict:
    """{gate_name: set_of_vids} — functions that satisfy each gate."""
    out: dict = {g: set() for g in GATES}
    for v in net.vertices:
        if not _real(v):
            continue
        n = _norm(v.name)
        for gname, pats in GATES.items():
            if _match(n, pats):
                out[gname].add(v.id)
    return out
