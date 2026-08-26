"""CROSS-LANGUAGE INGEST (C / C++) for the trust/taint OPERATOR — OS command injection (CWE-78). The
operator `lattice.taint.trust_obstructions` is called VERBATIM; only this ingest is new — it builds the
`{value:{inputs}}` dependency dict + source/sink sets from the NATIVE Clang AST (`clang -Xclang
-ast-dump=json -fsyntax-only`). Clang IS the parser (no extra bridge binary).

THE BUG CLASS: `system(cmd)` / `popen(cmd, ...)` / `execlp(...)` where `cmd` is built from an
attacker-controllable value — `char *host = getenv("HOST"); sprintf(cmd, "ping %s", host); system(cmd);`.
The string-BUILDERS (sprintf/snprintf/strcpy/strcat/...) are modelled as `dest <- {other args}` so taint
flows through the C idiom of assembling the command in a buffer. `system`/`popen` always invoke a shell,
so a tainted command is injection; `exec*` flags a tainted program/args.
"""
import json
import pathlib
import shutil
import subprocess
from collections import Counter

from lattice.ingest.taint_common import module_sink_params_fixpoint, return_source_funcs
from lattice.taint import trust_obstructions, taint_propagate

# Source markers (function names that surface attacker input): env, network, stdin, CGI (getenv), argv.
_C_SOURCES = {"getenv", "recv", "read", "fgets", "scanf", "fscanf", "gets", "getline", "fread",
              "argv", "recvfrom", "ReadFile"}
# Shell-spawning sinks (system/popen always run /bin/sh -c); exec-family runs a chosen program.
_SHELL_SINKS = {"system", "popen", "_popen", "_wsystem", "_system"}
_EXEC_SINKS = {"execl", "execlp", "execle", "execv", "execvp", "execvpe", "execvP", "popen"}
# String builders: dest (1st arg) is written from the remaining args.
_BUILDERS = ("sprintf", "snprintf", "strcpy", "strcat", "strncpy", "strncat", "memcpy",
             "vsprintf", "vsnprintf", "stpcpy", "strlcpy", "strlcat")
# OUT-PARAMETER sources: these WRITE attacker input into a buffer ARGUMENT (they do not return it), so the
# buffer becomes tainted. Mapped to the real-argument index(es) written (idiom-sweep wk01jvye5).
_OUTPARAM_SOURCES = {"fgets": [0], "gets": [0], "fread": [0], "getline": [0],
                     "read": [1], "recv": [1], "recvfrom": [1], "ReadFile": [1]}
# scanf-family writes EVERY pointer argument after the format string (variadic) — first written real-index.
_SCANF_FAMILY = {"scanf": 1, "fscanf": 2, "sscanf": 2}

# ── CWE-134 UNCONTROLLED FORMAT STRING ────────────────────────────────────────
# printf-family sinks keyed on the callee name -> INDEX (into real args) of the format-string
# argument. A tainted value in that position is a CWE-134 lead (attacker chooses conversion
# specifiers -> arbitrary read of the stack / arbitrary write via %n). SAFE toggle: the format
# arg is a bare `StringLiteral` (no name footprint), so the operator's tainted set never
# includes it — the same "empty footprint = silent" pattern the SQL sink uses in python_taint.
_FMT_SINKS = {"printf": 0, "fprintf": 1, "dprintf": 1, "snprintf": 2, "sprintf": 1,
              "asprintf": 1, "syslog": 1, "warn": 0, "err": 0,
              "vprintf": 0, "vfprintf": 1, "vdprintf": 1, "vsnprintf": 2,
              "vsprintf": 1, "vasprintf": 1, "vsyslog": 1}


def _include_dirs(path: pathlib.Path) -> list:
    """Best-effort include search paths so a real project parses: the file's OWN directory (redis's
    src/*.c include "server.h" from src/) plus include/ and src/ found walking up a few parents. Real
    coverage needs the project's actual flags (compile_commands.json) — this is a heuristic for the common
    layout, not a substitute."""
    dirs: list = [str(path.parent)]
    for parent in list(path.parents)[:4]:
        for d in ("include", "src", "inc", "."):
            ip = parent / d
            if ip.is_dir() and str(ip) not in dirs:
                dirs.append(str(ip))
    return dirs


def _clang_ast(path: pathlib.Path):
    """(ast, complete): the Clang JSON AST and whether it parsed WITHOUT fatal errors. Clang dumps a
    PARTIAL AST even on missing headers, so `complete=False` marks an under-analyzed file — the caller
    escalates a blind-spot rather than reporting it silently clean (SILENCE≠proof)."""
    cc = "clang++" if path.suffix.lower() in (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".c++") else "clang"
    if shutil.which(cc) is None:
        return None, False
    inc: list = []
    for d in _include_dirs(path):
        inc += ["-I", d]
    try:
        r = subprocess.run([cc, "-Xclang", "-ast-dump=json", "-fsyntax-only", *inc, str(path)],
                           capture_output=True, text=True, timeout=45)
    except (subprocess.SubprocessError, OSError):
        return None, False
    if not r.stdout:
        return None, False
    # a "fatal error:" (a missing #include header) means clang could not see referenced types/decls and
    # the AST is genuinely PARTIAL. A plain "error:" (e.g. implicit-declaration of a known libc function
    # whose header is absent) still yields a usable AST — do NOT treat that as incomplete.
    complete = "fatal error:" not in (r.stderr or "")
    try:
        return json.loads(r.stdout), complete
    except (json.JSONDecodeError, ValueError):
        return None, False


def _local_call_key(fn: dict, callee: str) -> str | None:
    return (fn.get("_lattice_local_keys") or {}).get(callee)


def _refs(node, out: set, call_key_of=None) -> None:
    """Every variable name referenced (DeclRefExpr) in a subtree — the taint footprint of an expr."""
    if isinstance(node, dict):
        if node.get("kind") == "CallExpr" and call_key_of:
            key = call_key_of(_callee_name(node))
            if key:
                out.add(key)
        if node.get("kind") == "DeclRefExpr":
            nm = (node.get("referencedDecl") or {}).get("name")
            if nm:
                out.add(nm)
        for c in node.get("inner") or []:
            _refs(c, out, call_key_of)
    elif isinstance(node, list):
        for x in node:
            _refs(x, out, call_key_of)


def _callee_name(callexpr: dict) -> str:
    """The called function's name (the single DeclRefExpr in the callee position inner[0])."""
    inner = callexpr.get("inner") or []
    if not inner:
        return ""
    refs: set = set()
    _refs(inner[0], refs)
    return next(iter(refs)) if len(refs) == 1 else ""


def _is_builder(callee: str) -> bool:
    return any(b in callee for b in _BUILDERS)


def _func_params(fn: dict) -> list:
    """Ordered parameter names of a FunctionDecl (its ParmVarDecl children)."""
    return [c.get("name") for c in (fn.get("inner") or [])
            if c.get("kind") == "ParmVarDecl" and c.get("name")]


def _is_string_literal(node) -> bool:
    """A `StringLiteral` (or an ImplicitCastExpr wrapping one) — a compile-time constant format
    string cannot carry taint, so a tainted arg-list is fine (that's the whole point of printf).
    Only a NON-literal format arg is a CWE-134 lead."""
    if not isinstance(node, dict):
        return False
    if node.get("kind") == "StringLiteral":
        return True
    inner = node.get("inner") or []
    # Clang wraps a StringLiteral in an ImplicitCastExpr (LValueToRValue / ArrayToPointerDecay)
    if node.get("kind") in ("ImplicitCastExpr", "CStyleCastExpr", "ParenExpr") and inner:
        return _is_string_literal(inner[0])
    return False


def _build_func(fn: dict, sink_param_map: dict | None = None):
    """(deps, shell_sinks, fmt_sinks): walk a function body building deps (VarDecl/assignment/
    string-builders) and BOTH sink sets — shell-injection and format-string. With a
    sink_param_map, a call to a user-helper whose PARAMETER reaches a shell sink makes the
    corresponding tainted argument a shell sink too (one-hop interprocedural summary)."""
    deps: dict = {}
    sinks: set = set()
    call_key_of = lambda callee: _local_call_key(fn, callee)
    fmt_sinks: set = set()

    def add_dep(targets: set, srcs: set):
        for t in targets:
            deps[t] = deps.get(t, set()) | srcs

    def walk(node):
        if isinstance(node, list):
            for x in node:
                walk(x)
            return
        if not isinstance(node, dict):
            return
        k = node.get("kind")
        if k == "VarDecl" and node.get("name"):
            init: set = set()
            for c in node.get("inner") or []:
                _refs(c, init, call_key_of)
            add_dep({node["name"]}, init)
        elif k == "BinaryOperator" and node.get("opcode") == "=":
            inner = node.get("inner") or []
            if len(inner) >= 2:
                lhs: set = set()
                rhs: set = set()
                _refs(inner[0], lhs, call_key_of)
                _refs(inner[1], rhs, call_key_of)
                add_dep(lhs, rhs)
        elif k == "CallExpr":
            callee = _callee_name(node)
            args = node.get("inner") or []          # inner[0]=callee, inner[1:]=arguments
            real = args[1:]                          # real (non-callee) arguments
            # CWE-134 format-string: fire BEFORE the builder check, so sprintf/snprintf/vsprintf/
            # vsnprintf hit both classes when applicable (they're in both _BUILDERS and _FMT_SINKS).
            if callee in _FMT_SINKS:
                idx = _FMT_SINKS[callee]
                if idx < len(real) and not _is_string_literal(real[idx]):
                    _refs(real[idx], fmt_sinks)
            if _is_builder(callee):
                if len(args) >= 2:
                    dest: set = set()
                    _refs(args[1], dest, call_key_of)  # 1st real arg = the buffer written
                    rest: set = set()
                    for a in args[2:]:
                        _refs(a, rest, call_key_of)
                    add_dep(dest, rest)
            elif callee in _SHELL_SINKS:
                if len(args) >= 2:
                    _refs(args[1], sinks, call_key_of)  # the shell-interpreted command string
            elif callee in _EXEC_SINKS:
                for a in args[1:]:
                    _refs(a, sinks, call_key_of)     # program + args (attacker-chosen program)
            elif callee in _OUTPARAM_SOURCES:
                real2 = args[1:]                     # an out-param source taints the buffer it writes into
                for i in _OUTPARAM_SOURCES[callee]:
                    if i < len(real2):
                        buf: set = set()
                        _refs(real2[i], buf, call_key_of)
                        add_dep(buf, {callee})        # callee ∈ _C_SOURCES -> buf is now tainted
            elif callee in _SCANF_FAMILY:
                real2 = args[1:]
                # scanf/fscanf read a SOURCE (stdin/file) -> buffers depend on the source callee; sscanf
                # PARSES an existing string -> buffers depend on that input-string arg's footprint.
                src_names = {callee}
                if callee == "sscanf" and real2:
                    src_names = set()
                    _refs(real2[0], src_names, call_key_of)
                for a in real2[_SCANF_FAMILY[callee]:]:  # every pointer arg after the format string
                    buf = set()
                    _refs(a, buf, call_key_of)
                    add_dep(buf, src_names)
            elif sink_param_map:
                exact = _local_call_key(fn, callee)
                keys = (exact, callee) if exact else (callee,)
                idxs = next((sink_param_map[key] for key in keys
                             if key and sink_param_map.get(key)), None)
                if not idxs:
                    idxs = ()
                for i, a in enumerate(args[1:]):
                    if i in idxs:
                        _refs(a, sinks, call_key_of)
        for c in node.get("inner") or []:
            walk(c)

    walk(fn)
    return deps, sinks, fmt_sinks


def _func_sink_params(fn: dict, sink_param_map: dict | None = None) -> set:
    """Parameter names of `fn` whose taint reaches a shell OR format-string sink in its own body —
    with a sink_param_map, a param that flows into ANOTHER helper's sink-parameter also counts
    (the transitive middle hop). Both attack classes share the same interprocedural summary map:
    a helper `void log_msg(char *m){ syslog("%s", m); }` has NO tainted param w.r.t. CWE-134 (fmt
    is a literal), but a helper `void bad(char *fmt){ printf(fmt); }` DOES. The summary is unioned
    across both classes so a tainted arg to `bad` propagates to the caller."""
    params = _func_params(fn)
    if not params:
        return set()
    deps, sinks, fmt_sinks = _build_func(fn, sink_param_map)
    all_sinks = sinks | fmt_sinks
    if not all_sinks:
        return set()
    return {p for p in params if all_sinks & taint_propagate(deps, {p}, set())}


def _summary_key_fn(funcs: list):
    counts = Counter(fn.get("name") for fn in funcs if fn.get("name"))

    def keys(fn: dict) -> tuple[str, ...]:
        name = fn.get("name") or ""
        exact = _local_call_key(fn, name)
        out = [exact] if exact else []
        if name and counts[name] == 1:
            out.append(name)
        return tuple(dict.fromkeys(key for key in out if key))

    return keys


def _module_sink_params(funcs: list) -> dict:
    """{function name -> set of param INDICES that reach a shell sink}, iterated to a FIXPOINT so the
    summary is TRANSITIVE (handler -> mid -> sh) — taint_common.module_sink_params_fixpoint over the
    clang accessors (the loop is AST-shape-agnostic; only _func_params/_func_sink_params touch clang)."""
    return module_sink_params_fixpoint(
        funcs, _func_params, _func_sink_params,
        keys_of=_summary_key_fn(funcs))


def _return_footprints(fn: dict) -> list:
    """The name footprint of each ReturnStmt expression in the function (for the return-taint summary)."""
    out: list = []

    def rec(node):
        if isinstance(node, dict):
            if node.get("kind") == "ReturnStmt":
                refs: set = set()
                for c in node.get("inner") or []:
                    _refs(c, refs, lambda callee: _local_call_key(fn, callee))
                out.append(refs)
            for c in node.get("inner") or []:
                rec(c)
        elif isinstance(node, list):
            for x in node:
                rec(x)

    rec(fn)
    return out


def _return_source_funcs(funcs: list) -> set:
    """Names of functions whose RETURN value is tainted by a source in their body — `char* get_host(){
    return getenv("H"); }`. A caller `host = get_host()` then carries taint (the callee name is in host's
    footprint), so these names are added to the source set — taint_common.return_source_funcs over the
    clang accessors (the loop is AST-shape-agnostic, like _module_sink_params; fixpoint, FN-safe)."""
    return return_source_funcs(
        funcs, _C_SOURCES, returns_of=_return_footprints,
        deps_of=lambda fn: _build_func(fn)[0],
        keys_of=_summary_key_fn(funcs))


def _analyze_func(fn: dict, sink_param_map: dict | None = None, sources: set | None = None) -> list[dict]:
    deps, sinks, fmt_sinks = _build_func(fn, sink_param_map)
    out: list[dict] = []
    src_set = sources or _C_SOURCES
    if sinks and trust_obstructions(deps, src_set, sinks, set()):
        out.append({
            "kind": "command_injection",
            "severity": "critical",
            "function": fn.get("name", "<fn>"),
            "cwe": "CWE-78",
            "detail": ("an attacker-controllable value (getenv / argv / recv) is assembled into a command and "
                       "reaches system()/popen()/exec* — OS command injection"),
        })
    if fmt_sinks and trust_obstructions(deps, src_set, fmt_sinks, set()):
        out.append({
            "kind": "format_string",
            "severity": "critical",
            "function": fn.get("name", "<fn>"),
            "cwe": "CWE-134",
            "detail": ("an attacker-controllable value reaches the FORMAT argument of a printf-family call "
                       "(printf / fprintf / snprintf / syslog / …) — attacker chooses conversion specifiers "
                       "and can read the stack (%%x) or write memory (%%n); use a fixed literal format"),
        })
    return out


def _user_functions(ast: dict) -> list:
    """Top-level FunctionDecls WITH a body (skips the system-header / builtin declarations)."""
    out: list = []
    for n in ast.get("inner") or []:
        if (n.get("kind") == "FunctionDecl"
                and any((c or {}).get("kind") == "CompoundStmt" for c in (n.get("inner") or []))):
            out.append(n)
    return out


def c_taint_audit(source_root) -> list[dict]:
    """Audit every C/C++ file under `source_root` for OS command injection via the trust/taint operator.
    Emits one 'command_injection' per offending function. Clang is the parser."""
    root = pathlib.Path(source_root)
    exts = (".c", ".cpp", ".cc", ".cxx", ".c++")
    skip = {"node_modules", "build", "dist", "out", ".git", "vendor",
            "cmake-build-debug", "cmake-build-release", "third_party", "extern"}
    files = [root] if root.is_file() else [
        p for p in sorted(root.rglob("*"))
        if p.suffix.lower() in exts and not (skip & set(p.relative_to(root).parts))]
    out: list[dict] = []
    parsed: list = []
    all_funcs: list = []
    for path in files:
        ast, complete = _clang_ast(path)
        if ast is None:
            continue
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        if not complete:
            # Clang hit a fatal error (usually a missing project header) so the AST is PARTIAL — the file
            # was under-analyzed. Escalate a blind-spot so a 0-findings result is not read as 'clean'
            # (SILENCE≠proof). Pass the project's flags (compile_commands.json) for full coverage.
            out.append({"leg": "blindspot", "kind": "parse_incomplete", "severity": "review",
                        "confidence": "review", "file": rel,
                        "detail": "clang could not fully parse this file (missing headers / project flags) "
                                  "— it was only PARTIALLY analyzed; a command-injection in the unparsed "
                                  "region would be invisible. Provide -I include paths / compile_commands.json."})
        funcs = _user_functions(ast)
        local_counts = Counter(fn.get("name") for fn in funcs if fn.get("name"))
        local_keys = {
            name: f"c:{rel}:{name}"
            for name, count in local_counts.items()
            if count == 1
        }
        for fn in funcs:
            fn["_lattice_file"] = rel
            fn["_lattice_local_keys"] = local_keys
        parsed.append((rel, funcs))
        all_funcs.extend(funcs)
    # DIRECTORY-WIDE sink-param map over ALL functions, so a uniquely named sink-wrapping helper in
    # helper.c is visible to its caller in main.c. Duplicate bare definitions (especially file-local
    # `static` helpers) are not summarized until a call target can be qualified: assigning either one's
    # summary to every same-named call would invent critical flows. (wk01jvye5)
    sink_param_map = _module_sink_params(all_funcs)
    sources = _C_SOURCES | _return_source_funcs(all_funcs)   # source->return laundering, directory-wide
    for rel, funcs in parsed:
        for fn in funcs:
            for f in _analyze_func(fn, sink_param_map, sources):
                f["file"] = rel
                out.append(f)
    return out
