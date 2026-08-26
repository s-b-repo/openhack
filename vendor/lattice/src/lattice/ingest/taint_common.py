"""SHARED structural helpers for the bridge-JSON taint frontends (Go / Rust / Ruby, + the C fixpoint).

The per-language ingests each parse source through a native-AST bridge into the SAME per-function JSON
shape — `{"name", "params": [..], "assigns": [{"lhs": [..], "rhs": [..]}], "calls": [{"callee",
"args": [{"lit", "names": [..]}]}]}` — and then ran byte-identical structural code over it, copy-pasted
per file. This module is that code, extracted ONCE: dep-map construction, the interprocedural
sink-param lookup, the one-hop->N-hop summary fixpoint, and the bridge runner. What stays PER-LANGUAGE
(in each frontend, as config passed in): the source/sink/sanitizer name sets, the `sink_names(func)`
detector (shell-form discrimination differs per language), and the `callee_keys(callee)` summary-key
resolution (Go strips the last `.`-segment; Rust tries the exact path then the last `::`-segment).

NOT unified here: the Python (stdlib `ast`) and C (clang JSON) frontends' AST walking — they operate on
different node shapes, and only bodies that were ACTUALLY identical were extracted. C delegates its two
fixpoint loops (`_module_sink_params`, `_return_source_funcs` — AST-agnostic via callable accessors);
Python's single-pass, non-transitive summary is a different design and keeps its own code.
"""
import json
import subprocess

from lattice.taint import taint_propagate


def run_json_bridge(cmd: list, timeout: int = 30):
    """Run an AST-bridge command and return its parsed-JSON stdout, or None on ANY failure (honest
    skip): spawn error, non-zero exit, empty output, or non-JSON output. The caller owns the
    bridge-existence check and argv construction."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def func_params(func: dict) -> list:
    """Ordered parameter names of a bridge-JSON function dict."""
    return func.get("params") or []


def deps_from_assigns(func: dict) -> dict:
    """`{lhs name -> set(rhs footprint names)}` from the function's assignments — the value-dependency
    dict the taint operator runs on. Repeated assignments to one name UNION their footprints (flow- and
    path-insensitive: any write that could taint the name taints it, FN-safe)."""
    deps: dict = {}
    for a in func.get("assigns") or []:
        rhs = set(a.get("rhs") or [])
        for l in a.get("lhs") or []:
            deps[l] = deps.get(l, set()) | rhs
    return deps


def interproc_sink_names(func: dict, sink_param_map: dict, callee_keys) -> set:
    """Arg names passed into a helper's SINK-parameter position — they reach the helper's shell sink.
    `callee_keys(callee)` yields the summary-map keys to try IN ORDER for a callee path; the first key
    with a non-empty index set wins (Go: the bare name after the last dot; Rust: the exact path, then
    the last ::-segment)."""
    out: set = set()
    if not sink_param_map:
        return out
    for c in func.get("calls") or []:
        idxs = None
        for key in callee_keys(c.get("callee") or ""):
            idxs = sink_param_map.get(key)
            if idxs:
                break
        if not idxs:
            continue
        for i, a in enumerate(c.get("args") or []):
            if i in idxs:
                out |= set(a.get("names") or [])
    return out


def sink_params(func: dict, sink_param_map: dict | None, sink_names, callee_keys) -> set:
    """Param names of `func` whose taint reaches a shell sink in its body — a tainted arg passed into
    that position reaches the sink (the helper `sh(cmd){ exec("sh","-c",cmd) }`). When a
    `sink_param_map` is supplied, an arg passed into ANOTHER helper's sink-parameter is ALSO a sink, so
    a middle hop (`mid(c){ sh(c) }`) counts — this is what makes the summary transitive (N-hop).
    `sink_names(func)` is the per-language direct-sink detector."""
    params = set(func_params(func))
    if not params:
        return set()
    sinks = sink_names(func) | interproc_sink_names(func, sink_param_map or {}, callee_keys)
    if not sinks:
        return set()
    deps = deps_from_assigns(func)
    return {p for p in params if sinks & taint_propagate(deps, {p}, set())}


def module_sink_params_fixpoint(funcs: list, params_of, sink_params_of, keys_of=None) -> dict:
    """{func name -> set of param INDICES that reach a shell sink}. Makes taint INTERPROCEDURAL: a
    caller passing a tainted arg into a sink-parameter position reaches the helper's sink. Iterated to
    a FIXPOINT so the one-hop summary becomes transitive (h -> mid -> sh): each round recomputes
    `sink_params_of(func, summary-so-far)`, growing the map MONOTONICALLY until it stops (bounded by
    func*param count; pure widening — can only add detections, FN-safe). `params_of(func)` returns the
    ordered param names, so the loop itself is AST-shape-agnostic (C passes its clang accessors).

    `keys_of(func)` optionally returns one or more collision-safe call identities for the definition.
    This is required for languages with methods or directory-wide duplicate static functions: an
    ambiguous bare name must not transfer a sink summary from one definition to an unrelated call.
    The legacy single `func["name"]` key remains the default for callers that have already established
    uniqueness in their own scope.
    """
    out: dict = {}
    while True:
        grew = False
        for func in funcs:
            params = params_of(func)
            sps = sink_params_of(func, out)
            idxs = {i for i, p in enumerate(params) if p in sps}
            keys = tuple(keys_of(func)) if keys_of else (func.get("name"),)
            for key in (key for key in keys if key):
                if idxs - out.get(key, set()):
                    out[key] = out.get(key, set()) | idxs
                    grew = True
        if not grew:
            return out


def return_source_funcs(funcs: list, base_sources: set, sanitized_of=None,
                        returns_of=None, deps_of=None, keys_of=None) -> set:
    """Names of functions whose RETURN value is tainted by a source in their body — `func get(r){ return
    r.FormValue("c") }`. A caller `v = get(r)` then carries the taint (the callee name lands in v's
    footprint), so the caller ADDS these names to its source set. Iterated to a FIXPOINT for chains
    (g returns f()); monotone widening — can only add detections (FN-safe). Per-language seams:
    `sanitized_of(func)` -> sanitizer name-set (Ruby's shellescape bindings; None = none), and
    `returns_of(func)` / `deps_of(func)` -> the return footprints / value-dep dict (defaults read the
    bridge-JSON `func["returns"]` / deps_from_assigns; C passes its clang accessors).

    `keys_of(func)` has the same collision-safety contract as in
    `module_sink_params_fixpoint`: it may return a qualified identity, a provably unique bare name, or
    no key when the definition cannot be distinguished safely.
    """
    returns_of = returns_of or (lambda func: func.get("returns") or [])
    deps_of = deps_of or deps_from_assigns
    # Per-func footprints are PURE in func — compute them ONCE, not per fixpoint round (C's deps_of
    # walks the whole clang AST; recomputing it every round made the fixpoint needlessly quadratic).
    work: list = []
    for func in funcs:
        keys = tuple(keys_of(func)) if keys_of else (func.get("name"),)
        keys = tuple(dict.fromkeys(key for key in keys if key))
        if not keys:
            continue
        rets = [set(r or []) for r in returns_of(func)]
        if not rets:
            continue
        san = sanitized_of(func) if sanitized_of else set()
        work.append((keys, rets, deps_of(func), san))
    rs: set = set()
    while True:
        grew = False
        cur = base_sources | rs
        for keys, rets, deps, san in work:
            if set(keys) <= rs:
                continue
            tainted = taint_propagate(deps, cur, san)
            if any(r & tainted for r in rets):
                before = len(rs)
                rs.update(keys)
                grew |= len(rs) != before
        if not grew:
            return rs
