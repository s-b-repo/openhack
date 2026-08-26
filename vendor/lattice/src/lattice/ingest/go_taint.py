"""CROSS-LANGUAGE INGEST (Go) for the trust/taint OPERATOR — OS command injection (CWE-78). The operator
`lattice.taint.trust_obstructions` is called VERBATIM; only this ingest is new — it builds the
`{value:{inputs}}` dependency dict + source/sink name-sets from a native `go/parser` AST (via the
packaged `goast` bridge, the Go analog of solc's compact-JSON / the node+@babel bridge for JS).

THE BUG CLASS: `exec.Command(...)` where an attacker-controlled value (an HTTP request field, os.Args, an
env var) is interpreted by a SHELL — `exec.Command("sh", "-c", "ping "+userInput)` — OR is the program
name itself (`exec.Command(userBinary)`). The ARGV form `exec.Command("ping", userInput)` is SAFE: there
is no shell, so userInput is a single literal argument and cannot inject metacharacters (the Go analog of
Python `subprocess(shell=True)` vs the list form). The shell-form/argv-form discrimination keeps it
precise — a swept screen on every exec.Command would false-fire on the safe argv pattern.
"""
import pathlib
import re
from collections import Counter

from lattice.bridge_runtime import (BridgeRuntimeError, bridge_source, ensure_go_bridge,
                                    run_json_bridge_checked)
from lattice.ingest.taint_common import (deps_from_assigns, func_params,
                                         module_sink_params_fixpoint, return_source_funcs)
from lattice.taint import taint_propagate, trust_obstructions

# Kept as a source-asset compatibility handle for tests and callers that checked availability.  The
# executable itself always lives in the writable content-addressed bridge cache.
_BRIDGE = bridge_source("goast", "go_ast.go")
# Source markers (method/field names that surface attacker input): HTTP request, CLI, env.
_GO_SOURCES = {"FormValue", "PostFormValue", "Query", "Get", "Getenv", "Args", "Form", "PostForm",
               "Param", "Params", "Cookie", "Header", "ReadAll", "URL", "Vars"}
_EXEC_SINKS = {"exec.Command", "exec.CommandContext"}
# Shells: a literal first arg in this set + a `-c` arg means the next arg is a shell-interpreted string.
_SHELLS = {"sh", "bash", "zsh", "ash", "dash", "/bin/sh", "/bin/bash", "/bin/zsh",
           "cmd", "cmd.exe", "powershell", "pwsh"}
# POSIX shells accept the -c flag BUNDLED with other single-letter options: `bash -lc`, `sh -xc`,
# `sh -euxc` all run the next arg as a shell command. The exact-membership test missed them (FN,
# idiom-sweep ws6yh6pp7). Windows shells use /c or -Command.
_POSIX_SH_BASES = {"sh", "bash", "zsh", "ash", "dash", "ksh", "mksh", "busybox"}
# Launcher wrappers that prefix the real command — a shell smuggled behind one still runs a shell.
_LAUNCHERS = {"sudo", "doas", "env", "timeout", "nice", "ionice", "stdbuf", "nohup", "setsid", "chroot"}
_WIN_SHELL_FLAGS = {"/c", "/C", "-Command", "-command", "-EncodedCommand", "-encodedcommand"}
_POSIX_C_FLAG = re.compile(r"-[a-zA-Z]*c")
_LOCAL_CALL_PREFIX = "__lattice_local_call__:"


def _is_shell_flag(lit, prog_lit) -> bool:
    """Whether `lit` is the shell's 'run this string' flag, given the program. For a POSIX shell, ANY
    bundle ending in c (-c/-lc/-xc/-euxc); for Windows, /c or -Command."""
    if not lit:
        return False
    if lit in _WIN_SHELL_FLAGS:
        return True
    base = (prog_lit or "").rsplit("/", 1)[-1]
    if base in _POSIX_SH_BASES:
        return bool(_POSIX_C_FLAG.fullmatch(lit))
    return lit == "-c"


def _parse(path, bridge: pathlib.Path | None = None) -> list:
    """Per-function JSON from the native go/parser bridge; failures are explicit."""
    executable = bridge or ensure_go_bridge()
    parsed = run_json_bridge_checked(
        [str(executable), str(path)], purpose=f"parsing Go source {path}"
    )
    if not isinstance(parsed, list):
        raise BridgeRuntimeError(
            f"parsing Go source {path} returned {type(parsed).__name__}, expected a function list"
        )
    return parsed


def _go_callee_keys(callee: str) -> tuple:
    """Try a bridge-proven qualified identity before a legacy bare-name fallback.

    The summary map only contains a bare key when that name is globally unique in this audit. Thus an
    unknown receiver such as ``x.Load`` can still use an unambiguous helper, while duplicate methods
    never transfer a summary between unrelated receiver types.
    """
    bare = callee.split(".")[-1]
    return tuple(dict.fromkeys((callee, bare)))


def _package_identity(rel: str, package: str) -> str:
    """Stable audit-local Go package identity, including the package-relative directory.

    Different commands routinely both declare ``package main``. The declaration alone is therefore
    not an identity; the directory is part of Go's package/import boundary.
    """
    parent = pathlib.PurePosixPath(rel).parent.as_posix()
    return f"go:{parent}:{package}"


def _qualify_file_functions(rel: str, funcs: list) -> None:
    """Rewrite bridge-proven local identities into package-directory-qualified identities in place."""
    for func in funcs:
        package = func.get("package") or (func.get("qualified_name") or "").split(".", 1)[0]
        if not package:
            continue
        package_id = _package_identity(rel, package)
        old_prefix = f"{package}."

        qname = func.get("qualified_name") or ""
        if qname.startswith(old_prefix):
            func["qualified_name"] = f"{package_id}.{qname[len(old_prefix):]}"

        for call in func.get("calls") or []:
            callee = call.get("callee") or ""
            if call.get("local") and callee.startswith(old_prefix):
                callee = f"{package_id}.{callee[len(old_prefix):]}"
                call["callee"] = callee
                call["_summary_keys"] = (callee,)
            else:
                # A selector may name an imported package or a dynamic receiver. Without exact import
                # or type resolution, a bare-name fallback would manufacture a cross-package target.
                call["_summary_keys"] = ()

        def qualify_footprint(names) -> list:
            out = []
            for name in names or []:
                if isinstance(name, str) and name.startswith(_LOCAL_CALL_PREFIX + old_prefix):
                    name = f"{package_id}.{name[len(_LOCAL_CALL_PREFIX + old_prefix):]}"
                out.append(name)
            return out

        for assign in func.get("assigns") or []:
            assign["rhs"] = qualify_footprint(assign.get("rhs"))
        func["returns"] = [qualify_footprint(ret) for ret in (func.get("returns") or [])]


def _summary_key_fn(funcs: list):
    """Return a collision-safe key accessor for this directory-wide function set."""
    names = Counter(func.get("name") for func in funcs if func.get("name"))
    qualified = Counter(func.get("qualified_name") for func in funcs
                        if func.get("qualified_name"))

    def keys(func: dict) -> tuple[str, ...]:
        name = func.get("name") or ""
        qname = func.get("qualified_name") or name
        if not name:
            return ()
        if names[name] == 1:
            return tuple(dict.fromkeys((qname, name)))
        if qname != name and qualified[qname] == 1:
            return (qname,)
        # Duplicate definitions with no distinct proven identity are unverifiable. Emitting their bare
        # name would manufacture interprocedural taint on every unrelated same-named call.
        return ()

    return keys


def _sink_names(func: dict) -> set:
    """Names that reach a command-injection sink: the shell-interpreted string of a
    `exec.Command("sh","-c", X)` / an attacker-controlled program name `exec.Command(prog)`. The ARGV
    form `exec.Command("ping", x)` (literal program, no shell) is NOT a sink."""
    sinks: set = set()
    for c in func.get("calls") or []:
        if c.get("callee") not in _EXEC_SINKS:
            continue
        args = c.get("args") or []
        if c.get("callee") == "exec.CommandContext" and args:
            args = args[1:]                                   # skip the ctx first arg
        if not args:
            continue
        prog = args[0]
        prog_lit = prog.get("lit")
        # A shell flag (-c/-lc/.../ /c/-Command) means the next non-flag arg is a shell-interpreted command.
        # Shell-form holds when EITHER (a) a shell literal AND a shell flag both appear among the args — which
        # also covers a launcher/env prefix `exec.Command("sudo","sh","-c",X)` / `exec.Command("env","sh",
        # "-c",X)`; OR (b) the program is a known shell literal or a VARIABLE (prog_lit "") and a shell flag
        # is present (`sh:="/bin/sh"; exec.Command(sh,"-c",X)`). The shell-PRESENT gate is what keeps
        # `exec.Command("ping","-c","4",host)` SILENT — ping's -c is a count flag, no shell is present.
        lits = [a.get("lit") for a in args]
        shell_present = any(literal in _SHELLS for literal in lits)
        flag_present = any(_is_shell_flag(literal, "sh") for literal in lits)
        is_shell = flag_present and (shell_present or prog_lit in _SHELLS or not prog_lit)
        if is_shell:
            for a in args:                                    # the shell-command string (not sh/-c/launcher)
                lit = a.get("lit")
                if (lit in _SHELLS or lit in _LAUNCHERS or _is_shell_flag(lit, "sh")
                        or (lit and "=" in lit)):             # skip shell name, launcher, flag, env VAR=val
                    continue
                sinks |= set(a.get("names") or [])            # incl. the program var itself if attacker-controlled
        elif not prog_lit:
            sinks |= set(prog.get("names") or [])             # program NAME is attacker-controlled (no shell flag)
        # else: argv form with a literal program (no shell flag) -> no shell -> not a sink
    return sinks


def _sink_params(func: dict, sink_param_map: dict | None = None) -> set:
    """Param names of `func` whose taint reaches a shell sink in its body (the helper `func sh(cmd
    string){ exec.Command("sh","-c",cmd) }`) — taint_common.sink_params over Go's shell-form detector."""
    params = set(func_params(func))
    if not params:
        return set()
    sinks = _sink_names(func) | _interproc_sink_names(func, sink_param_map or {})
    if not sinks:
        return set()
    deps = deps_from_assigns(func)
    return {param for param in params if sinks & taint_propagate(deps, {param}, set())}


def _module_sink_params(funcs: list) -> dict:
    """{func name -> set of param INDICES that reach a shell sink}, iterated to a FIXPOINT so the one-hop
    summary becomes TRANSITIVE (h->mid->sh) — taint_common.module_sink_params_fixpoint (FN-safe widening)."""
    return module_sink_params_fixpoint(
        funcs, func_params, _sink_params, keys_of=_summary_key_fn(funcs))


def _interproc_sink_names(func: dict, sink_param_map: dict) -> set:
    """Arg names passed into a helper's SINK-parameter position — they reach the helper's shell sink."""
    out: set = set()
    if not sink_param_map:
        return out
    for call in func.get("calls") or []:
        if "_summary_keys" in call:
            keys = call["_summary_keys"]
        else:  # compatibility for synthetic/private callers that predate bridge identity metadata
            keys = _go_callee_keys(call.get("callee") or "")
        idxs = next((sink_param_map[key] for key in keys if sink_param_map.get(key)), None)
        if not idxs:
            continue
        for i, arg in enumerate(call.get("args") or []):
            if i in idxs:
                out |= set(arg.get("names") or [])
    return out


def _return_source_funcs(funcs: list) -> set:
    """Names of functions whose RETURN value is tainted by a source in their BODY — `func get(r){ return
    r.FormValue("c") }`. A caller `v := get(r)` carries the taint (the callee name is in v's footprint), so
    these names are added to the source set — taint_common.return_source_funcs over _GO_SOURCES (fixpoint
    for chains; FN-safe widening). (deep-sweep wk01jvye5)"""
    return return_source_funcs(
        funcs, _GO_SOURCES, keys_of=_summary_key_fn(funcs))


def _analyze(func: dict, sink_param_map: dict | None = None, sources: set | None = None) -> list[dict]:
    sinks = _sink_names(func) | _interproc_sink_names(func, sink_param_map or {})
    if not sinks:
        return []
    findings = trust_obstructions(deps_from_assigns(func), sources or _GO_SOURCES, sinks, set())
    if not findings:
        return []
    return [{
        "kind": "command_injection",
        "severity": "critical",
        "function": func.get("name", "<func>"),
        "cwe": "CWE-78",
        "detail": ("an attacker-controllable value (HTTP request field / os.Args / env) reaches a "
                   "shell-interpreted exec.Command(\"sh\",\"-c\",…) or an attacker-controlled program name "
                   "— OS command injection (the argv form exec.Command(prog, args…) is safe)"),
    }]


def go_taint_audit(source_root) -> list[dict]:
    """Audit every `.go` under `source_root` for OS command injection via the trust/taint operator.
    Skips *_test.go and vendor/. Emits one 'command_injection' per offending function."""
    root = pathlib.Path(source_root)
    files = [root] if root.is_file() else [
        p for p in sorted(root.rglob("*.go"))
        if not p.name.endswith("_test.go") and "vendor" not in p.parts]
    if not files:
        return []
    bridge = ensure_go_bridge()
    parsed: list = []
    all_funcs: list = []
    for path in files:
        funcs = _parse(path, bridge)
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        _qualify_file_functions(rel, funcs)
        parsed.append((rel, funcs))
        all_funcs.extend(funcs)
    # DIRECTORY-WIDE sink-param map over ALL functions (name-keyed), so a sink-wrapping helper in helper.go
    # is visible to its caller in main.go; the fixpoint also makes the cross-file summary TRANSITIVE. Pure
    # widening — can only add detections (FN-safe). (deep-sweep wk01jvye5)
    sink_param_map = _module_sink_params(all_funcs)
    sources = _GO_SOURCES | _return_source_funcs(all_funcs)   # source->return laundering, directory-wide
    out: list[dict] = []
    for rel, funcs in parsed:
        for func in funcs:
            for f in _analyze(func, sink_param_map, sources):
                f["file"] = rel
                out.append(f)
    return out
