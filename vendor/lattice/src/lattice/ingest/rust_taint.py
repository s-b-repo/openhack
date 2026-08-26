"""CROSS-LANGUAGE INGEST (Rust) for the trust/taint OPERATOR — OS command injection (CWE-78). The
operator `lattice.taint.trust_obstructions` is called VERBATIM; only this ingest is new — it builds the
`{value:{inputs}}` dependency dict + source/sink sets from a native `syn` AST (via the
packaged `rustast` bridge, the Rust analog of the Go/JS bridges).

THE BUG CLASS: `std::process::Command::new("sh").arg("-c").arg(format!("ping {}", user))` — an
attacker-controlled value (env::args, env::var, an HTTP request field) interpreted by a SHELL — or the
program name itself `Command::new(user_bin)`. The ARGV form `Command::new("ping").arg(user)` is SAFE (no
shell). The builder chain is flattened by the bridge into a Command::new call + .arg/.args method calls;
this ingest reconstructs the shell form per function. `format!`'s interpolated vars are recovered from the
macro token stream by the bridge, so taint flows through the common command-building idiom.
"""
import pathlib
import re
from collections import Counter

from lattice.bridge_runtime import (BridgeRuntimeError, bridge_source, ensure_rust_bridge,
                                    run_json_bridge_checked)
from lattice.ingest.taint_common import (deps_from_assigns, func_params, interproc_sink_names,
                                         sink_params)
from lattice.taint import taint_propagate, trust_obstructions

# Compatibility handle for checking whether the packaged bridge source exists.  The executable is built
# lazily into the writable content-addressed cache by ensure_rust_bridge().
_BRIDGE = bridge_source("rustast", "Cargo.toml")
# Source markers: env::args / env::var (CLI, env), HTTP request fields, stdin.
# Extended in the accuracy sweep — modern async web frameworks expose typed extractors
# whose leaf names weren't previously recognized:
#   Query      — axum::extract::Query<T> and actix_web::web::Query<T>
#   Path       — axum::extract::Path<T> / actix_web::web::Path<T> (URL segment)
#   Form       — actix_web::web::Form<T>
#   Json       — actix_web::web::Json<T> / axum::extract::Json<T>
#   headers    — axum::http::HeaderMap accessor
_RUST_SOURCES = {"args", "var", "var_os", "args_os", "stdin", "read_line", "read_to_string",
                 "form", "query", "param", "body", "header", "cookie",
                 "Query", "Path", "Form", "Json", "headers"}
_SHELLS = {"sh", "bash", "zsh", "ash", "dash", "/bin/sh", "/bin/bash", "/bin/zsh",
           "cmd", "cmd.exe", "powershell", "pwsh"}
_SHELL_FLAGS = {"-c", "/c", "/C", "-Command", "-command"}


def _parse(path, bridge: pathlib.Path | None = None, module_path: str = "",
           crate_path: str = "") -> list:
    executable = bridge or ensure_rust_bridge("rustast", binary="rust_ast")
    command = [str(executable), str(path)]
    if module_path or crate_path:
        command.append(module_path)
        command.append(crate_path)
    parsed = run_json_bridge_checked(
        command, purpose=f"parsing Rust source {path}"
    )
    if not isinstance(parsed, list):
        raise BridgeRuntimeError(
            f"parsing Rust source {path} returned {type(parsed).__name__}, expected a function list"
        )
    return parsed


def _rust_callee_keys(callee: str) -> tuple:
    """Summary-map keys for a Rust callee path: the EXACT path first (a fully-qualified local helper),
    then the last ::-segment (`util::sh` -> `sh`), matching the name-keyed sink-param map."""
    return (callee, callee.split("::")[-1])


def _is_command_new(callee: str) -> bool:
    return callee.split("::")[-2:] == ["Command", "new"]


_C_FLAG = re.compile(r"-[a-zA-Z]*c")


def _is_shell_flag(lit) -> bool:
    """A shell 'run this string' flag: -c / -lc / -euxc (combined POSIX) or /c / -Command (Windows)."""
    if not lit:
        return False
    return lit in _SHELL_FLAGS or bool(_C_FLAG.fullmatch(lit))


def _sink_names(func: dict) -> set:
    """Reconstruct the Process::Command builder for this function: a `Command::new("sh")` + `.arg("-c")`
    + `.arg(X)` means X is shell-interpreted (sink); a `Command::new(var)` means the program is
    attacker-chosen (sink). The argv form `Command::new("ping").arg(x)` (literal program, no shell) is
    not a sink."""
    cmd_progs: list = []
    arg_vals: list = []
    for c in func.get("calls") or []:
        callee = c.get("callee", "")
        if _is_command_new(callee):
            if c.get("args"):
                cmd_progs.append(c["args"][0])
        elif callee in ("arg", "args"):
            for a in c.get("args") or []:
                arg_vals.append(a)
    sinks: set = set()
    # shell_mode: the program is a shell (Command::new("sh")), OR a launcher prefix smuggles the shell
    # into the arg list — e.g. Command::new("env").arg("sh").arg("-c").arg(X). The arg-list form is gated
    # on a shell-FLAG literal (-c / -Command) also being present, so a benign `env MYVAR=1 ping x` (a shell
    # name absent or no -c) stays SILENT. This is strictly additive (OR), so it never drops a detection.
    prog_is_shell = any(p.get("lit") in _SHELLS for p in cmd_progs)
    prog_is_var = any(not p.get("lit") for p in cmd_progs)    # Command::new(shellVar) — literal unknown
    flag_present = any(_is_shell_flag(a.get("lit")) for a in arg_vals)
    shell_in_args = any(a.get("lit") in _SHELLS for a in arg_vals)   # launcher/env prefix smuggles the shell
    # shell-form when: the program is a literal shell; OR a shell flag is present together with a shell in the
    # args (launcher prefix) or a VARIABLE program (`let sh="/bin/sh"; Command::new(sh).arg("-c")`). The flag
    # gate keeps `Command::new("ping").arg("-c").arg(host)` SILENT — ping's -c is a count flag, no shell.
    shell_mode = prog_is_shell or (flag_present and (shell_in_args or prog_is_var))
    if shell_mode:
        for a in arg_vals:
            if not _is_shell_flag(a.get("lit")) and a.get("lit") not in _SHELLS:
                sinks |= set(a.get("names") or [])
    for p in cmd_progs:
        if not p.get("lit"):                              # program is a variable -> attacker-chosen binary
            sinks |= set(p.get("names") or [])
    return sinks


def _sink_params(func: dict, sink_param_map: dict | None = None) -> set:
    """Param names of `func` whose taint reaches a shell sink in its body (the helper `fn sh(cmd: &str){
    Command::new("sh").arg("-c").arg(cmd); }`) — taint_common.sink_params over Rust's builder detector."""
    return sink_params(func, sink_param_map, _sink_names, _rust_callee_keys)


def _module_sink_params(funcs: list) -> dict:
    """{fn name -> set of param INDICES that reach a shell sink}, iterated to a FIXPOINT so the summary is
    TRANSITIVE (h -> mid -> sh). Qualified keys keep duplicate impl-method names collision-safe."""
    counts = Counter(func.get("name") for func in funcs if func.get("name"))
    out: dict = {}
    while True:
        grew = False
        for func in funcs:
            keys = _summary_keys(func, counts)
            if not keys:
                continue
            params = func_params(func)
            sink_names = _sink_params(func, out)
            indices = {i for i, param in enumerate(params) if param in sink_names}
            for key in keys:
                if indices - out.get(key, set()):
                    out[key] = out.get(key, set()) | indices
                    grew = True
        if not grew:
            return out


def _interproc_sink_names(func: dict, sink_param_map: dict) -> set:
    """Arg names passed into a helper's SINK-parameter position — they reach the helper's shell sink."""
    return interproc_sink_names(func, sink_param_map, _rust_callee_keys)


# Genuine SHELL sanitizers, matched by their consecutive path tokens in an assignment's RHS footprint:
# shell_escape::escape, shlex::quote. NOT a bare `escape`/`quote` (regex/HTML/URL quoters are not shell-safe).
_RUST_SHELL_SANITIZERS = (("shell_escape", "escape"), ("shlex", "quote"))


def _sanitized_names(func: dict) -> set:
    """LHS names assigned DIRECTLY from a genuine shell sanitizer (`let safe = shell_escape::escape(x)`).
    Restricted to SINGLE-binding assigns so a tuple-unpack union cannot leak sanitizer membership onto a
    sibling (the FN landmine); a tuple containing a sanitizer just stays tainted (FP, FIRE=lead)."""
    out: set = set()
    for a in func.get("assigns") or []:
        lhs = a.get("lhs") or []
        rhs = set(a.get("rhs") or [])
        if len(lhs) == 1 and any(t0 in rhs and t1 in rhs for t0, t1 in _RUST_SHELL_SANITIZERS):
            out |= set(lhs)
    return out


def _return_source_funcs(funcs: list) -> set:
    """Names of functions whose RETURN value (explicit `return` or the implicit trailing expression) is
    tainted by a source in their body — `fn get() -> String { env::var("C").unwrap() }`. A caller
    `let v = get();` carries the taint (the callee name lands in v's footprint), so these names join the
    source set. This is the shared return-source fixpoint with qualified Rust identities and the
    shell_escape/shlex sanitizer seam."""
    counts = Counter(func.get("name") for func in funcs if func.get("name"))
    work: list = []
    for func in funcs:
        keys = _summary_keys(func, counts)
        returns = [set(value or []) for value in (func.get("returns") or [])]
        if keys and returns:
            work.append((keys, returns, deps_from_assigns(func), _sanitized_names(func)))

    sources: set = set()
    while True:
        grew = False
        current = _RUST_SOURCES | sources
        for keys, returns, deps, sanitizers in work:
            if set(keys) <= sources:
                continue
            tainted = taint_propagate(deps, current, sanitizers)
            if any(value & tainted for value in returns):
                before = len(sources)
                sources.update(keys)
                grew |= len(sources) != before
        if not grew:
            return sources


def _summary_keys(func: dict, counts: Counter) -> tuple[str, ...]:
    """Safe interprocedural keys for a Rust function or impl method.

    Unique names keep their legacy bare key so instance calls such as ``s.get()`` remain supported.
    Duplicate impl-method names expose only their qualified identity (``Dirty::load``), preventing a
    tainted method on one type from contaminating a same-named clean method on another.  Duplicates with
    no qualified identity are deliberately not summarized because selecting either would invent a fact.
    """
    name = func.get("name") or ""
    if not name:
        return ()
    qualified = func.get("qualified_name") or name
    if counts[name] == 1:
        return tuple(dict.fromkeys((qualified, name)))
    if qualified != name:
        return (qualified,)
    return ()


def _analyze(func: dict, sink_param_map: dict | None = None, sources: set | None = None) -> list[dict]:
    sinks = _sink_names(func) | _interproc_sink_names(func, sink_param_map or {})
    if not sinks:
        return []
    findings = trust_obstructions(deps_from_assigns(func), sources or _RUST_SOURCES, sinks,
                                  _sanitized_names(func))
    if not findings:
        return []
    return [{
        "kind": "command_injection",
        "severity": "critical",
        "function": func.get("qualified_name") or func.get("name", "<fn>"),
        "cwe": "CWE-78",
        "detail": ("an attacker-controllable value (env::args / env::var / request) reaches a "
                   "shell-interpreted Command::new(\"sh\").arg(\"-c\").arg(…) or an attacker-controlled "
                   "program name — OS command injection (the argv form Command::new(prog).arg(x) is safe)"),
    }]


def rust_taint_audit(source_root) -> list[dict]:
    """Audit every `.rs` under `source_root` for OS command injection via the trust/taint operator.
    Emits one 'command_injection' per offending function."""
    root = pathlib.Path(source_root)
    files = [root] if root.is_file() else [
        p for p in sorted(root.rglob("*.rs")) if "target" not in p.parts]
    if not files:
        return []
    bridge = ensure_rust_bridge("rustast", binary="rust_ast")
    parsed: list = []
    all_funcs: list = []
    for path in files:
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        module_path, crate_path = (("", "") if root.is_file()
                                   else _file_module_context(rel))
        funcs = _parse(path, bridge, module_path, crate_path)
        parsed.append((rel, funcs))
        all_funcs.extend(funcs)
    # DIRECTORY-WIDE sink-param map over ALL functions, with qualified keys for duplicate impl methods, so
    # a sink-wrapping helper in helper.rs is visible without conflating same-named methods on other types.
    sink_param_map = _module_sink_params(all_funcs)
    sources = _RUST_SOURCES | _return_source_funcs(all_funcs)   # source->return laundering, directory-wide
    out: list[dict] = []
    for rel, funcs in parsed:
        for func in funcs:
            for f in _analyze(func, sink_param_map, sources):
                f["file"] = rel
                out.append(f)
    return out


def _file_module_context(relative_file: str) -> tuple[str, str]:
    """Return stable ``(module, crate)`` identities for a project-relative Rust file."""
    path = pathlib.PurePosixPath(relative_file)
    parts = list(path.with_suffix("").parts)
    crate_parts: list[str] = []
    if "src" in parts:
        src_index = len(parts) - 1 - parts[::-1].index("src")
        crate_parts = parts[:src_index]
        parts = parts[src_index + 1:]
    if parts and parts[-1] in {"lib", "main"}:
        parts.pop()
    elif parts and parts[-1] == "mod":
        parts.pop()
    module_parts = [*crate_parts, *parts]
    return "::".join(module_parts), "::".join(crate_parts)
