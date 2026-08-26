"""Shared source / sink / sanitizer vocabulary — the one place a taint detector's
NAME-SETS live, so improving a term (a new SSRF sink, a new HTML sanitizer, a
Rails source) benefits every language at once instead of drifting.

DESIGN RULES (load-bearing):
  1. DATA ONLY. This module MUST NOT import any detector; the flow is one-way.
     Detectors import vocab; vocab imports nothing but stdlib. That keeps the
     dependency graph acyclic and makes vocab safe to import from tests too.
  2. UNIONS, NEVER OVERRIDES. Every detector call passes its truly-language-
     specific extras via the `extra=` argument; the returned set is the UNION of
     the shared vocab for the requested kinds and those extras. A per-language
     divergence (Ruby's `Shellwords`, Rust's `env::var`, C's `getenv`) stays in
     the detector; only the CROSS-LANGUAGE terms migrate here.
  3. THE OPERATOR IS SOUND. `lattice.taint.trust_obstructions` isn't touched by
     any of this — vocab.py is INGEST-side, exactly like every detector.

Kinds:
  SOURCES     — attacker-controllable input surfaces
     "http_request" — HTTP-shaped request handles (req/request/ctx/event, request fields)
     "cli"          — command-line argv, argv0
     "env"          — process environment (getenv, environ, os.environ)
     "network"      — raw sockets, recv, read, ReadFile

  SINKS       — trust-sensitive destinations
     "shell"        — OS command execution (system, popen, exec*, spawn)
     "sql"          — SQL execution (execute, executemany, query, raw, text)
     "code_exec"    — arbitrary code evaluation (eval, Function, vm.Script, require)
     "deserialize"  — object deserialization (pickle, yaml.load, XMLDecoder…)
     "ssrf"         — outbound HTTP (fetch, urlopen, requests.get, axios)
     "xss"          — DOM write (innerHTML, outerHTML, document.write, insertAdjacentHTML)
     "path"         — filesystem access (open, readFile, writeFile)
     "format"       — printf-family FORMAT arg (printf, snprintf, syslog)

  SANITIZERS  — detoxifying wrappers, keyed by SINK domain
     "shell"        — shlex.quote, pipes.quote, shlex.join, Shellwords.escape
     "sql"          — parametrized-query construction (recognized at sink-shape level)
     "html"         — escapeHtml, escape (context-tagged), Markup.escape
     "path"         — realpath, canonicalize, resolve after allowlist
"""
from __future__ import annotations
from typing import Iterable


# ── SOURCES ───────────────────────────────────────────────────────────────────
SOURCES: dict[str, set[str]] = {
    "http_request": {
        # request-shaped identifiers (Python / Flask / Django / Node / TS)
        "request", "req", "ctx", "event", "httpRequest",
        # common attribute/property leaves accessed on a request handle
        "body", "query", "params", "headers", "cookies", "cookie", "rawbody",
        "form", "postform", "queryparameters",
        # framework-specific first-class request accessors
        "session", "flash", "parameters", "FormValue", "PostFormValue",
        "gorillaVars", "mux.Vars",
    },
    "cli": {
        "argv", "args", "args_os", "argv0", "ARGV",
    },
    "env": {
        "environ", "os.environ", "getenv", "ENV", "env",
        "var", "var_os",           # Rust std::env::var
    },
    "network": {
        "recv", "recvfrom", "read", "fread", "fgets", "gets", "getline",
        "ReadFile", "read_line", "read_to_string", "stdin", "STDIN",
    },
}


# ── SINKS ─────────────────────────────────────────────────────────────────────
SINKS: dict[str, set[str]] = {
    "shell": {
        "system", "popen", "_popen", "_wsystem", "_system",
        "execl", "execlp", "execle", "execv", "execvp", "execvpe", "execvP",
        "_spawnv", "_spawnvp", "_spawnve", "_execv", "_execvp",
        "spawn", "spawnSync", "spawnFileSync", "execSync", "execFile", "execFileSync",
        "fork", "childProcess.exec", "child_process.exec",
        "os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "exec.Command", "exec.CommandContext",           # Go
        "Command::new",                                    # Rust (a marker: real check is more complex)
    },
    "sql": {
        "execute", "executemany", "executescript",
        "query", "query_all", "execute_batch",
        "raw", "unpreparedstatement", "text",
        "rawSql", "sqlQuery", "rawQuery", "sqlExec", "dbQuery",
        "executeQuery", "runQuery", "executeRaw", "queryRaw", "rawSqlQuery",
    },
    "code_exec": {
        "eval", "Function", "execScript", "newFunction",
        "runInNewContext", "runInContext", "runInThisContext",
        "vmRunInNewContext", "vmRunInContext",
        "compileFunction", "Script", "SourceTextModule",
        "setTimeout", "setInterval", "setImmediate",   # implicit-eval when arg0 is a string
        "require",                                       # dynamic module load with user-chosen path
    },
    "deserialize": {
        "pickle.loads", "cloudpickle.loads", "dill.loads", "jsonpickle.decode",
        "yaml.load", "unserialize", "marshal.loads",
        "ObjectInputStream", "XMLDecoder", "XStream.fromXML",
        "readObject", "fromXML", "jacksonAsObject",
        "deserialize", "unpickle",
    },
    "ssrf": {
        # LEAF/global names — the receiver-guarded regexes in security.py enforce
        # global vs member discrimination there. Vocab is the name pool.
        "fetch", "urlopen", "urlget", "urlgetter",
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "requests.patch", "requests.head",
        "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
        "axios", "http.Get", "http.NewRequest",
        "okhttp", "restclient", "webclient", "wget",
    },
    "xss": {
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
        "insertAdjacentHTML", "document.write", "document.writeln",
        "htmlSafeString", "htmlMarkSafe", "html_safe",
    },
    "path": {
        "open", "openfile", "readfile", "writefile",
        "createReadStream", "createWriteStream",
        "sendfile", "unlink", "rmdir", "renamefile",
    },
    "format": {
        # printf-family format-arg positions live in c_taint._FMT_SINKS with the
        # index — vocab.SINKS["format"] is the NAME pool for cross-language
        # migration; index metadata stays with the C-specific detector.
        "printf", "fprintf", "dprintf", "snprintf", "sprintf", "asprintf",
        "syslog", "warn", "err",
        "vprintf", "vfprintf", "vdprintf", "vsnprintf", "vsprintf", "vasprintf",
        "vsyslog",
    },
}


# ── SANITIZERS ────────────────────────────────────────────────────────────────
SANITIZERS: dict[str, set[str]] = {
    "shell": {
        # POSIX shell-quoter names in every language we cover — cross-language.
        "shlex.quote", "pipes.quote", "shlex.join",
        "shellescape", "Shellwords",                     # Ruby
        "snailquote::escape", "os_str_bytes",             # Rust helpers
    },
    "sql": {
        # SQL "sanitization" is only genuine via parametrized queries. There's no
        # standalone name-based SQL sanitizer that carries across languages, so
        # this set is left empty and the sink-shape check (arg1 is a container
        # literal) does the safe-toggle in each language's detector.
    },
    "html": {
        "escapeHtml", "html.escape", "escape", "encodeURIComponent",
        "Markup.escape", "htmlspecialchars",
    },
    "path": {
        "realpath", "canonicalize", "resolve",         # after an allowlist check
    },
}


# ── Public helpers ────────────────────────────────────────────────────────────

def _union(kind_dict: dict[str, set[str]], kinds: Iterable[str], extra) -> set[str]:
    out: set[str] = set()
    for k in kinds:
        out |= kind_dict.get(k, set())
    out |= set(extra or ())
    return out


def sources(*kinds: str, extra: Iterable[str] = ()) -> set[str]:
    """Return the union of the requested source kinds plus the caller's extras.

    Example (Python taint):
        _SOURCE_MARKS = vocab.sources("http_request", "cli", "env",
                                       extra={"input", "stdin"})
    """
    return _union(SOURCES, kinds, extra)


def sinks(*kinds: str, extra: Iterable[str] = ()) -> set[str]:
    """Return the union of the requested sink kinds plus the caller's extras."""
    return _union(SINKS, kinds, extra)


def sanitizers(*kinds: str, extra: Iterable[str] = ()) -> set[str]:
    """Return the union of the requested sanitizer domains plus the caller's extras.

    NOTE: sanitizer domains are SINK domains (shell / sql / html / path). Passing
    a source-kind here returns an empty set — that's intentional so the caller
    (a detector) can safely ask for `sanitizers("shell")` without having to know
    whether an entry exists in the table.
    """
    return _union(SANITIZERS, kinds, extra)


# ── Introspection (for tools/measure_accuracy.py and tests) ──────────────────

def catalog() -> dict:
    """Full snapshot of the vocabulary — used by the accuracy measurer to record
    which vocab version a baseline was captured against."""
    return {
        "sources": {k: sorted(v) for k, v in SOURCES.items()},
        "sinks": {k: sorted(v) for k, v in SINKS.items()},
        "sanitizers": {k: sorted(v) for k, v in SANITIZERS.items()},
    }
