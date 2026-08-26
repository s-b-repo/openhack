"""CROSS-LANGUAGE INGEST (Ruby) for the trust/taint OPERATOR — OS command injection (CWE-78). The operator
`lattice.taint.trust_obstructions` is called VERBATIM; only this ingest is new — it builds the
`{value:{inputs}}` dependency dict + source/sink sets from the native Ripper AST (walked in Ruby by the
packaged `rubyast/ruby_ast.rb` bridge). Ripper is stdlib — no extra deps.

THE BUG CLASS: `system("ping #{params[:host]}")` / a backtick `` `... #{x}` `` / `exec`/`IO.popen` /
`Open3.capture2/3` where an attacker-controllable value (Rails params, ENV, ARGV, gets) is interpolated
into a shell command. (A single string runs through a shell; the multi-arg array form does not — this v1
fires on any tainted arg, FIRE=lead, the array form a known over-flag.)
"""
import pathlib
from collections import Counter

from lattice.bridge_runtime import (BridgeRuntimeError, bridge_source, ruby_bridge,
                                    run_json_bridge_checked)
from lattice.ingest.taint_common import deps_from_assigns, return_source_funcs
from lattice.taint import trust_obstructions, taint_propagate

_BRIDGE = bridge_source("rubyast", "ruby_ast.rb")
# Source markers: Rails params, env, CLI, stdin, request. Extended in the accuracy sweep
# with a few Rails-specific entry points that were previously missed:
#   session               — Rails cookie/DB-backed session hash (user-writable in most stacks)
#   flash                 — Rails one-shot user-visible messages (attacker-influenced in some flows)
#   headers               — HTTP header table on the request (typically routed via `request.headers`
#                           but Rails 6+ exposes a bare `headers` inside controller actions)
#   parameters            — the aliased `parameters` on ActionDispatch::Request
_RUBY_SOURCES = {"params", "ARGV", "ENV", "gets", "request", "cookies", "query_parameters", "env", "STDIN",
                 "session", "flash", "headers", "parameters"}
# Shell-spawning sinks (a string arg runs through /bin/sh).
_RUBY_SINKS = {"system", "exec", "spawn", "syscall", "`backtick`", "popen", "capture2", "capture3",
               "capture2e", "popen3", "popen2"}
# Ruby's SHELL sanitizers: `x.shellescape` (String#shellescape) and the `Shellwords` module
# (Shellwords.escape / Shellwords.shellescape) neutralize shell metacharacters. NOT bare `escape`/`quote`
# — Regexp.quote / CGI.escape / URI.escape quote regex/HTML/URL, leaving `;`/`|`/`$()` shell-live; keying
# on them was a SILENT FN (idiom-sweep ws6yh6pp7). `Shellwords` is the qualifying const in the footprint.
_RUBY_SANITIZERS = {"shellescape", "Shellwords"}
_LOCAL_CALL_PREFIX = "__lattice_local_call__:"


def _ruby_callee_keys(callee: str) -> tuple[str, ...]:
    """Qualified receiver/class identity first; bare fallback is safe only if summarized."""
    bare = callee.rsplit("#", 1)[-1].rsplit(".", 1)[-1]
    return tuple(dict.fromkeys((callee, bare)))


def _summary_key_fn(funcs: list):
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
        return ()

    return keys


def _qualify_file_functions(rel: str, funcs: list) -> None:
    """Attach file-qualified identities to top-level Ruby methods and their lexical calls."""
    local_counts = Counter(
        func.get("name") for func in funcs
        if func.get("name") and func.get("qualified_name") == func.get("name")
        and func.get("name") != "<main>"
    )
    local_keys = {
        name: f"ruby:{rel}:{name}"
        for name, count in local_counts.items()
        if count == 1
    }
    for func in funcs:
        name = func.get("name") or ""
        qname = func.get("qualified_name") or name
        if name == "<main>":
            func["qualified_name"] = f"ruby:{rel}:<main>"
        elif qname == name and name in local_keys:
            func["qualified_name"] = local_keys[name]

        for call in func.get("calls") or []:
            qualified = call.get("qualified_callee")
            callee = call.get("callee") or ""
            if qualified:
                call["_summary_keys"] = (qualified,)
            elif callee in local_keys:
                call["_summary_keys"] = (local_keys[callee],)

        def qualify_footprint(names) -> list:
            out = []
            for item in names or []:
                if isinstance(item, str) and item.startswith(_LOCAL_CALL_PREFIX):
                    local = local_keys.get(item[len(_LOCAL_CALL_PREFIX):])
                    if local:
                        out.append(local)
                    continue
                out.append(item)
            return out

        for assign in func.get("assigns") or []:
            assign["rhs"] = qualify_footprint(assign.get("rhs"))
        func["returns"] = [qualify_footprint(ret) for ret in (func.get("returns") or [])]


def _sanitized_names(func: dict) -> set:
    """Values assembled THROUGH a shell sanitizer (their assignment footprint names shellescape/escape) —
    passed to the operator as sanitizers so taint does not propagate through them (the fastlane FP)."""
    out: set = set()
    for a in func.get("assigns") or []:
        if set(a.get("rhs") or []) & _RUBY_SANITIZERS:
            out |= set(a.get("lhs") or [])
    return out


def _parse(path, bridge: pathlib.Path | None = None) -> list:
    script = bridge or ruby_bridge("ruby_ast.rb")
    parsed = run_json_bridge_checked(
        ["ruby", str(script), str(path)], purpose=f"parsing Ruby source {path}"
    )
    if not isinstance(parsed, list):
        raise BridgeRuntimeError(
            f"parsing Ruby source {path} returned {type(parsed).__name__}, expected a function list"
        )
    return parsed


def _sink_names(func: dict) -> set:
    sinks: set = set()
    for c in func.get("calls") or []:
        if c.get("callee") in _RUBY_SINKS:
            args = set(c.get("args") or [])
            # INLINE sanitizer: `system("ping #{x.shellescape}")` — the shell quoter sits in the command
            # arg itself. Its presence neutralizes that command, so contribute no sink names (the inline
            # analog of _sanitized_names, which only covers the bound `safe = x.shellescape` form).
            if args & _RUBY_SANITIZERS:
                continue
            sinks |= args
    return sinks


def _interproc_sink_names(func: dict, wrappers: set) -> set:
    """Arg names passed to a known sink-wrapper helper reach that helper's shell sink. Ruby's bridge gives
    a FLAT per-call arg name-set (not per-arg), so this is index-blind: ANY arg name passed into a wrapper
    is treated as reaching the sink — an FN-safe over-approximation consistent with the name-set design."""
    out: set = set()
    if not wrappers:
        return out
    for c in func.get("calls") or []:
        if "_summary_keys" in c:
            keys = c["_summary_keys"]
        else:
            callee = c.get("qualified_callee") or c.get("callee") or ""
            keys = _ruby_callee_keys(callee)
        if any(key in wrappers for key in keys):
            out |= set(c.get("args") or [])
    return out


def _sink_wrapper_names(funcs: list) -> set:
    """Names of helper methods that pass a PARAMETER into a shell sink — calling one with a tainted arg
    reaches the sink (the interprocedural summary Ruby lacked entirely). Iterated to a FIXPOINT so a chain
    h -> mid -> sh is transitive, and computed over ALL files so cross-file helpers resolve. Monotone
    widening only — can add detections, never drop one (FN-safe). (deep-sweep wk01jvye5)"""
    wrappers: set = set()
    keys_of = _summary_key_fn(funcs)
    while True:
        grew = False
        for func in funcs:
            keys = keys_of(func)
            if not keys or set(keys) <= wrappers:
                continue
            params = set(func.get("params") or [])
            if not params:
                continue
            sinks = _sink_names(func) | _interproc_sink_names(func, wrappers)
            if not sinks:
                continue
            deps = deps_from_assigns(func)
            san = _sanitized_names(func)
            if any(sinks & taint_propagate(deps, {p}, san) for p in params):
                before = len(wrappers)
                wrappers.update(keys)
                grew |= len(wrappers) != before
        if not grew:
            return wrappers


def _return_source_funcs(funcs: list) -> set:
    """Names of methods whose RETURN value (explicit or Ruby's implicit last-statement) is tainted by a
    source in their body — `def build; raw=params[:host]; "ping #{raw}"; end`. A caller `cmd = build()`
    then carries taint (the callee name lands in cmd's footprint), so these names join the source set —
    taint_common.return_source_funcs over _RUBY_SOURCES with the shellescape sanitizer seam (fixpoint
    for chains; FN-safe widening). (deep-sweep wk01jvye5)"""
    return return_source_funcs(
        funcs, _RUBY_SOURCES, sanitized_of=_sanitized_names,
        keys_of=_summary_key_fn(funcs))


def _analyze(func: dict, wrappers: set | None = None, sources: set | None = None) -> list[dict]:
    sinks = _sink_names(func) | _interproc_sink_names(func, wrappers or set())
    if not sinks:
        return []
    findings = trust_obstructions(deps_from_assigns(func), sources or _RUBY_SOURCES, sinks,
                                  _sanitized_names(func))
    if not findings:
        return []
    return [{
        "kind": "command_injection",
        "severity": "critical",
        "function": func.get("name", "<fn>"),
        "cwe": "CWE-78",
        "detail": ("an attacker-controllable value (params / ENV / ARGV / gets) is interpolated into a "
                   "shell command via system()/backticks/exec/IO.popen — OS command injection"),
    }]


def ruby_taint_audit(source_root) -> list[dict]:
    """Audit every `.rb` under `source_root` for OS command injection via the trust/taint operator.
    Emits one 'command_injection' per offending method/scope."""
    root = pathlib.Path(source_root)
    skip = {"vendor", "node_modules", ".git", ".bundle", "tmp"}
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*.rb")
        if not (skip & set(p.relative_to(root).parts)))
    if not files:
        return []
    bridge = ruby_bridge("ruby_ast.rb")
    parsed: list = []
    all_funcs: list = []
    for path in files:
        funcs = _parse(path, bridge)
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        _qualify_file_functions(rel, funcs)
        parsed.append((rel, funcs))
        all_funcs.extend(funcs)
    # DIRECTORY-WIDE sink-wrapper set over ALL methods, so a helper in helper.rb is seen by its caller in
    # app.rb (cross-file). Pure widening — only adds detections (FN-safe). (deep-sweep wk01jvye5)
    wrappers = _sink_wrapper_names(all_funcs)
    sources = _RUBY_SOURCES | _return_source_funcs(all_funcs)   # source->return laundering, directory-wide
    out: list[dict] = []
    for rel, funcs in parsed:
        for func in funcs:
            for f in _analyze(func, wrappers, sources):
                f["file"] = rel
                out.append(f)
    return out
