"""CROSS-LANGUAGE INGEST (JS/TS) — the ARBITRARY-CALL detector ported from solidity_arbitrary_call.py.
Same trust/taint OPERATOR (`lattice.taint.trust_obstructions`) called VERBATIM; only this ingest is new:
a Babel AST (via the packaged `jsast/parse.js` bridge, the analog of solc's compact-JSON AST) classified
into a `{value:{inputs}}` dependency dict + source / sink / sanitizer name-sets.

THE BUG CLASS — JS analog of Damn-Vulnerable-DeFi `truster`: an external call whose TARGET derives from
untrusted input, so the attacker chooses what the program runs. Two sink shapes:
  - DYNAMIC DISPATCH  `obj[KEY](...)`  — a computed-member call whose KEY is attacker-controlled (high);
  - CODE EXECUTION    `eval(X)` / `new Function(X)` / `require(X)` / `import(X)` / `vm.runIn*(X)` (critical).

SOLIDITY -> JS port:
  address-parameter source       -> request object (req/request/ctx/event) + process.argv
  X.call/.delegatecall(...) sink  -> computed-member dispatch + eval/require/Function/import
  fixed state-var target SILENT   -> constant key `handlers['delete']` SILENT (no attacker name in the key)
  (sanitizer)                     -> a validate()/allowlist wrap on the key/arg SILENT (sanitizer-aware)

NOTE on access-control: the Solidity port suppresses an `onlyOwner`-gated arbitrary call (a clear trust
boundary). That is DELIBERATELY NOT ported to JS — JS auth gates are ad-hoc and unreliable to detect, and
an admin-only `eval` is still frequently a real finding, so suppressing on a heuristic would be a
silent-FN. FIRE=lead / SILENCE≠proof.
"""
import pathlib
import shutil

from lattice.bridge_runtime import (BridgeRuntimeError, bridge_source, ensure_node_bridge,
                                    run_json_bridge_checked)
from lattice.ingest.types import RawReference
from lattice.taint import trust_obstructions, taint_propagate

_BRIDGE = bridge_source("jsast", "parse.js")
_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
_PARSER_ERRORS_KEY = "__latticeParserErrors"

# A source is detected by USAGE, not by a magic identifier name (adversarial-verify w2iuqm74n): the
# request param is whatever identifier is member-accessed via one of these properties — so `req`, `r`,
# `ctx`, `httpReq` all work, and a local merely NAMED `request` but never `.body`-accessed does NOT taint.
_REQUEST_PROPS = {"body", "query", "params", "headers", "cookies", "cookie", "rawbody"}
_PROCESS_PROPS = {"argv", "env", "argv0"}                      # process.argv / process.env (CLI/global)
# Callee identifier names that EXECUTE CODE from a string argument (critical).
_CODE_EXEC_CALLEES = {"eval", "Function", "require", "execScript",
                      # setTimeout/setInterval/setImmediate with a STRING first arg are implicit eval
                      # (CWE-95); a function-literal arg contributes no top-level identifier so the common
                      # safe `setTimeout(()=>..., t)` stays silent. (deep-sweep wk01jvye5)
                      "setTimeout", "setInterval", "setImmediate"}
# Member-method names that execute code (vm module) — `new vm.Script(X)` carries the tainted source.
# Extended in the accuracy sweep with a couple of newer surfaces:
#   compileFunction   — vm.compileFunction(source, params, opts) — added in Node 10, missed before
#   SourceTextModule  — ESM runtime evaluation (experimental, but real)
# These are the same shape as the existing entries: `<vm>.<member>(sourceStr)` where sourceStr is
# the code that gets executed.
_CODE_EXEC_MEMBERS = {"runInNewContext", "runInContext", "runInThisContext", "compileFunction",
                      "Script", "SourceTextModule"}
# child_process process-spawn family — THE canonical Node RCE. Gated on a child_process import binding so
# `regex.exec(userInput)` (RegExp.prototype.exec, extremely common) does NOT false-fire.
_SPAWN_MEMBERS = {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"}
# worker_threads: `new Worker(path)` runs a JS file in a subthread — an attacker-controlled
# path is an RCE via a user-supplied module (same threat model as child_process). Gated on a
# `worker_threads` import binding so a random `new Worker(...)` (Web Worker) doesn't false-fire.
_WORKER_THREADS_MEMBERS = {"Worker"}
# Deno process-spawn API: `Deno.run({cmd})` / `Deno.Command(cmd)` — same shape as Node's child_process
# but on a global namespace so no import binding gate; the leading `Deno.` receiver is unambiguous.
_DENO_SPAWN_MEMBERS = {"run", "Command"}
# Callee names that SANITIZE a key/arg = ALLOW-LIST / VALIDATION membership only. Output-encoders
# (escape/encodeURIComponent) and generic accessors (lookup) were REMOVED — they do not make a code-exec
# sink safe (eval(escape(x)) is still RCE), so leaving them in was a fake-toggle silent-FN.
_SANITIZERS = {"validate", "sanitize", "allowlist", "whitelist", "isallowed", "assertvalid", "checkkey"}
# Array/Promise iterators whose callback's first param is bound to elements of the receiver (one-hop taint).
_ITERATORS = {"foreach", "map", "filter", "some", "every", "flatmap", "find", "findindex",
              "reduce", "reduceright", "then", "catch"}
_FN_TYPES = {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression",
             "ObjectMethod", "ClassMethod", "ClassPrivateMethod"}


def _parse(path, bridge: pathlib.Path | None = None,
           parser_errors: list[dict] | None = None) -> dict:
    """Babel Program plus optionally retained recovery diagnostics.

    With ``parser_errors`` supplied, recovery-mode syntax errors are appended while the
    usable partial AST is returned. Standalone callers that cannot carry diagnostics
    fail explicitly instead of silently treating recovered invalid syntax as clean.
    """
    script = bridge or ensure_node_bridge()
    node = shutil.which("node") or "node"  # ensure_node_bridge already validates PATH
    parsed = run_json_bridge_checked(
        [node, str(script), str(path)], purpose=f"parsing JavaScript/TypeScript source {path}"
    )
    if not isinstance(parsed, dict) or parsed.get("type") != "Program":
        shape = type(parsed).__name__
        if isinstance(parsed, dict):
            shape = f"object type={parsed.get('type')!r}"
        raise BridgeRuntimeError(
            f"parsing JavaScript/TypeScript source {path} returned {shape}, expected a Babel Program"
        )
    recovered = parsed.pop(_PARSER_ERRORS_KEY, [])
    if not isinstance(recovered, list) or any(not isinstance(item, dict) for item in recovered):
        raise BridgeRuntimeError(
            f"parsing JavaScript/TypeScript source {path} returned malformed parser diagnostics"
        )
    if recovered and parser_errors is None:
        first = recovered[0]
        raise BridgeRuntimeError(
            f"parsing JavaScript/TypeScript source {path} recovered "
            f"{len(recovered)} syntax error(s): {first.get('message', 'unknown parser error')}"
        )
    if parser_errors is not None:
        parser_errors.extend(recovered)
    return parsed


def _walk(node):
    """Yield every dict node in the Babel AST (skipping position keys)."""
    if isinstance(node, dict):
        yield node
        for k, v in node.items():
            if k in ("loc", "start", "end", "range", "leadingComments", "trailingComments"):
                continue
            yield from _walk(v)
    elif isinstance(node, list):
        for x in node:
            yield from _walk(x)


def dynamic_dispatch_refs(rel_files, root, diagnostics: list[dict] | None = None,
                          language: str | None = None) -> list:
    """RawReferences (kind='dyn_dispatch') for `obj[<dynamic>](...)` computed-member calls
    where obj is a plain identifier. Feeds the builder's Pass 9: such a call reaches every
    member of obj's container (the methods LSP flattened off it). Static member access
    (`o.cmd()`, `o['cmd']()` with a literal key) is excluded. Bridge and parse failures
    are raised so callers cannot mistake an unavailable frontend for a clean result."""
    # Detect ANY computed-member access `obj[<dynamic>]` on a plain identifier — not only
    # `obj[k]()` immediately called. The dispatched function is often read first
    # (`const f = formatters[entry.kind]; f(entry)`). The builder (Pass 9) gates on whether
    # obj resolves to a container with callable members, so data lookups like `arr[i]`
    # (no method members) yield no edges — frontend over-detects, builder filters.
    out: list = []
    seen: set = set()
    base = pathlib.Path(root)
    eligible = [rel for rel in rel_files if str(rel).endswith(_EXTS)]
    if not eligible:
        return out
    bridge = ensure_node_bridge()
    for rel in eligible:
        recovered: list[dict] | None = [] if diagnostics is not None else None
        ast = _parse(base / rel, bridge, recovered)
        if diagnostics is not None:
            file_language = language or (
                "typescript" if pathlib.Path(rel).suffix.lower() in (".ts", ".tsx")
                else "javascript")
            for item in recovered or []:
                diagnostics.append({
                    "kind": "parse_error", "language": file_language,
                    "file": str(rel), "line": int(item.get("line") or 1),
                    "column": int(item.get("column") or 0), "severity": "error",
                    "message": item.get("message") or "Babel recovered a syntax error",
                    "code": item.get("reasonCode") or item.get("code"),
                    "parser": "babel",
                })
        for node in _walk(ast):
            if (node.get("type") not in ("MemberExpression", "OptionalMemberExpression")
                    or not node.get("computed")):
                continue
            obj = node.get("object") or {}
            prop = node.get("property") or {}
            if obj.get("type") != "Identifier" or not obj.get("name"):
                continue
            if prop.get("type") in ("StringLiteral", "NumericLiteral"):
                continue   # static member access by literal key, not dynamic dispatch
            line = ((node.get("loc") or {}).get("start") or {}).get("line")
            if not line:
                continue
            key = (str(rel), int(line), obj["name"])
            if key not in seen:
                seen.add(key)
                out.append(RawReference(kind="dyn_dispatch", from_file=str(rel),
                                        from_line=int(line), name=obj["name"]))
    return out


def _callee_final_name(callee: dict) -> str:
    """The name keyed for sink/sanitizer classification: an Identifier's name, or a non-computed
    member's property name (`vm.runInNewContext` -> 'runInNewContext')."""
    if callee.get("type") == "Identifier":
        return callee.get("name", "")
    if callee.get("type") == "MemberExpression" and not callee.get("computed"):
        prop = callee.get("property") or {}
        return prop.get("name", "") if prop.get("type") == "Identifier" else ""
    return ""


def _is_sanitizer_call(node: dict) -> bool:
    if node.get("type") not in ("CallExpression", "OptionalCallExpression", "NewExpression"):
        return False
    return _callee_final_name(node.get("callee") or {}).lower() in _SANITIZERS


def _names_in(node) -> set:
    """Every Identifier name in the subtree, EXCEPT names inside a sanitizer call (sanitizer-aware —
    a key/arg through validate()/allowlist carries no taint even though the source is lexically inside)."""
    out: set = set()
    if isinstance(node, dict):
        if _is_sanitizer_call(node):
            return out
        if node.get("type") == "Identifier":
            n = node.get("name")
            if n:
                out.add(n)
        for k, v in node.items():
            if k in ("loc", "start", "end", "range", "leadingComments", "trailingComments"):
                continue
            out |= _names_in(v)
    elif isinstance(node, list):
        for x in node:
            out |= _names_in(x)
    return out


def _names_in_args(call: dict) -> set:
    out: set = set()
    for a in call.get("arguments") or []:
        out |= _names_in(a)
    return out


def _excluded_ids(root: dict) -> set:
    """ids() of all nodes inside a NESTED function under root (so the module pass skips function bodies
    and each function pass skips its own nested defs) — one scope per pass."""
    out: set = set()
    for n in _walk(root):
        if isinstance(n, dict) and n.get("type") in _FN_TYPES and n is not root:
            for sub in _walk(n):
                if isinstance(sub, dict):
                    out.add(id(sub))
    return out


def _own(root: dict, types: set):
    excl = _excluded_ids(root)
    for n in _walk(root):
        if isinstance(n, dict) and n.get("type") in types and id(n) not in excl:
            yield n


def _binding_names(target: dict) -> list:
    """Names bound by an assignment/declarator target (Identifier or a destructuring pattern)."""
    t = target.get("type")
    if t == "Identifier":
        return [target.get("name")] if target.get("name") else []
    if t == "ArrayPattern":
        out = []
        for e in target.get("elements") or []:
            if e:
                out += _binding_names(e)
        return out
    if t == "ObjectPattern":
        out = []
        for p in target.get("properties") or []:
            val = p.get("value") or p.get("argument")
            if val:
                out += _binding_names(val)
        return out
    if t in ("AssignmentPattern", "RestElement"):
        inner = target.get("left") or target.get("argument")
        return _binding_names(inner) if inner else []
    if t in ("MemberExpression", "OptionalMemberExpression") and not target.get("computed"):
        nm = _member_final_name(target)                 # `this.cmd =` / `obj.cmd =` -> binds `cmd`
        return [nm] if nm else []
    return []


def _build_deps(scope: dict):
    """`{value:{inputs}}` from declarators + assignments (sanitizer-aware RHS), plus the names BOUND
    from a sanitizer call (sanitizer-wins)."""
    deps: dict = {}
    sanitizers: set = set()
    for kind, lhs_key, rhs_key in (("VariableDeclarator", "id", "init"),
                                   ("AssignmentExpression", "left", "right")):
        for node in _own(scope, {kind}):
            rhs = node.get(rhs_key)
            if rhs is None:
                continue
            targets = _binding_names(node.get(lhs_key) or {})
            if not targets:
                continue
            if _is_sanitizer_call(rhs):
                sanitizers |= set(targets)
            names = _names_in(rhs)
            for t in targets:
                deps[t] = deps.get(t, set()) | names
    return deps, sanitizers


def _root_id(node) -> str | None:
    """Root identifier of a member chain: `req` for `req.body`, `ctx` for `ctx.request.body`."""
    while isinstance(node, dict) and node.get("type") in ("MemberExpression", "OptionalMemberExpression"):
        node = node.get("object") or {}
    return node.get("name") if isinstance(node, dict) and node.get("type") == "Identifier" else None


def _scope_sources(scope: dict) -> set:
    """USAGE-based taint roots in a scope: an identifier member-accessed via a request property
    (`X.body`/`.query`/`.params`/`.headers`/`.cookies` — any spelling of the request param) or
    `process.argv`/`process.env`. No magic-name sourcing, so a local named `request` that is never
    request-accessed does not taint (kills the name-collision FPs)."""
    sources: set = set()
    for m in _own(scope, {"MemberExpression", "OptionalMemberExpression"}):
        if m.get("computed"):
            continue
        prop = (m.get("property") or {})
        pname = prop.get("name", "")
        if not pname:
            continue
        low = pname.lower()
        obj = m.get("object") or {}
        if low in _REQUEST_PROPS:
            r = _root_id(obj)                                       # req.body -> req ; ctx.request.body -> ctx
            if r:
                sources.add(r)
        elif low in _PROCESS_PROPS and obj.get("type") == "Identifier" and obj.get("name") == "process":
            sources.add(pname)                                      # process.argv -> 'argv'
    return sources


def _child_process_bindings(prog: dict) -> tuple[set, set]:
    """(module identifiers, destructured fn names) bound from require('child_process') / import — so a
    spawn sink fires for `cp.exec(...)` and `const {exec}=require('child_process'); exec(...)` but NOT
    for `regex.exec(userInput)` (RegExp.exec, which has no such binding)."""
    return _module_bindings(prog, "child_process")


def _worker_threads_bindings(prog: dict) -> tuple[set, set]:
    """(module identifiers, destructured fn names) bound from require('worker_threads') / import —
    so `new Worker(userPath)` fires ONLY when `Worker` was imported from worker_threads (not a Web
    Worker or an unrelated class in a browser bundle)."""
    return _module_bindings(prog, "worker_threads")


def _module_bindings(prog: dict, module_name: str) -> tuple[set, set]:
    """Generic factor-out: bindings from require('<module>') / import * / import {…}.

    Returns (namespace idents, named-export idents). Parallels _child_process_bindings so a new
    sensitive module (worker_threads, Deno FFI, …) can be added without duplicating the walk."""
    modules: set = set()
    fns: set = set()
    for n in _walk(prog):
        if not isinstance(n, dict):
            continue
        if n.get("type") == "VariableDeclarator":
            init = n.get("init") or {}
            if (init.get("type") == "CallExpression"
                    and (init.get("callee") or {}).get("name") == "require"):
                args = init.get("arguments") or []
                if args and args[0].get("value") == module_name:
                    idn = n.get("id") or {}
                    if idn.get("type") == "Identifier" and idn.get("name"):
                        modules.add(idn["name"])
                    elif idn.get("type") == "ObjectPattern":
                        for p in idn.get("properties") or []:
                            val = p.get("value") or p.get("key") or {}
                            if val.get("name"):
                                fns.add(val["name"])
        elif n.get("type") == "ImportDeclaration" and (n.get("source") or {}).get("value") == module_name:
            for spec in n.get("specifiers") or []:
                st = spec.get("type")
                local = (spec.get("local") or {}).get("name")
                if st in ("ImportDefaultSpecifier", "ImportNamespaceSpecifier") and local:
                    modules.add(local)
                elif st == "ImportSpecifier":
                    nm = (spec.get("imported") or {}).get("name") or local
                    if nm:
                        fns.add(nm)
    return modules, fns


def _expr_has_request_source(node: dict) -> bool:
    """Does an expression's subtree contain a request property access (so an iterator's receiver, e.g.
    `req.body.ops`, is attacker-derived)?"""
    for m in _walk(node):
        if isinstance(m, dict) and m.get("type") in ("MemberExpression", "OptionalMemberExpression") \
                and not m.get("computed"):
            if (m.get("property") or {}).get("name", "").lower() in _REQUEST_PROPS:
                return True
    return False


def _tainted_callback_params(prog: dict) -> dict:
    """One hop across a callback boundary: for `RECV.forEach/map/.../then(CB)` where RECV is
    request-derived, the CB's first parameter is bound to attacker-controlled elements — seed it as a
    source in CB's scope. Returns {id(CB function node): {param name}}."""
    seeded: dict = {}
    for call in _walk(prog):
        if not isinstance(call, dict) or call.get("type") not in ("CallExpression", "OptionalCallExpression"):
            continue
        callee = call.get("callee") or {}
        if callee.get("type") not in ("MemberExpression", "OptionalMemberExpression"):
            continue
        if (callee.get("property") or {}).get("name", "").lower() not in _ITERATORS:
            continue
        if not _expr_has_request_source(callee.get("object") or {}):
            continue
        for arg in call.get("arguments") or []:
            if arg.get("type") in _FN_TYPES:
                params = arg.get("params") or []
                if params:
                    nm = (params[0] or {}).get("name")
                    if nm:
                        seeded.setdefault(id(arg), set()).add(nm)
                break
    return seeded


def _call_sinks(scope: dict, cp_modules: set, cp_fns: set,
                wt_modules: set | None = None, wt_fns: set | None = None):
    """(code_exec_names, dispatch_names): names feeding a code-exec sink (eval/Function/require/import/vm/
    child_process/worker_threads/Deno) and names in a computed-member dispatch KEY (`obj[KEY](...)`).

    wt_modules / wt_fns are the bindings from `require('worker_threads')` — a `new Worker(path)` fires
    only when Worker was imported from that module (so Web Worker constructions and unrelated Worker
    classes stay silent). Deno spawn (`Deno.run` / `Deno.Command`) is gated on the leading `Deno.`
    receiver name, which is unambiguous — no import binding needed."""
    wt_modules = wt_modules or set()
    wt_fns = wt_fns or set()
    code_exec: set = set()
    dispatch: set = set()
    for node in _own(scope, {"CallExpression", "OptionalCallExpression", "NewExpression"}):
        callee = node.get("callee") or {}
        ct = callee.get("type")
        fname = _callee_final_name(callee)
        obj_name = (callee.get("object") or {}).get("name") if isinstance(callee.get("object"), dict) else None
        if ct == "Import":                                          # dynamic import(X)
            code_exec |= _names_in_args(node)
        elif ct == "Identifier" and callee.get("name") in _CODE_EXEC_CALLEES:
            code_exec |= _names_in_args(node)                       # eval/require/Function/execScript
        elif ct == "Identifier" and callee.get("name") in cp_fns and fname in _SPAWN_MEMBERS:
            code_exec |= _names_in_args(node)                       # destructured child_process exec/spawn
        elif (ct == "Identifier" and callee.get("name") in wt_fns
                and fname in _WORKER_THREADS_MEMBERS):
            code_exec |= _names_in_args(node)                       # destructured worker_threads.Worker
        elif fname in _CODE_EXEC_MEMBERS:
            code_exec |= _names_in_args(node)                       # vm.runInNewContext / new vm.Script(X)
        elif (fname in _SPAWN_MEMBERS and ct in ("MemberExpression", "OptionalMemberExpression")
                and obj_name in cp_modules):
            code_exec |= _names_in_args(node)                       # cp.exec(X) — gated on the cp import
        elif (fname in _WORKER_THREADS_MEMBERS
                and ct in ("MemberExpression", "OptionalMemberExpression", "NewExpression")
                and obj_name in wt_modules):
            code_exec |= _names_in_args(node)                       # wt.Worker(path) — gated on wt import
        elif (fname in _DENO_SPAWN_MEMBERS
                and ct in ("MemberExpression", "OptionalMemberExpression", "NewExpression")
                and obj_name == "Deno"):
            code_exec |= _names_in_args(node)                       # Deno.run / new Deno.Command
        elif ct in ("MemberExpression", "OptionalMemberExpression") and callee.get("computed"):
            dispatch |= _names_in(callee.get("property"))           # obj[KEY](...) — attacker-chosen target
    return code_exec, dispatch


def _member_final_name(node: dict) -> str:
    """Final name of an assignment target: `handleUpdate` for `this.handleUpdate`, `x` for `obj.x`,
    `route` for a bare `route`."""
    t = node.get("type")
    if t == "Identifier":
        return node.get("name", "")
    if t in ("MemberExpression", "OptionalMemberExpression") and not node.get("computed"):
        prop = node.get("property") or {}
        return prop.get("name", "") if prop.get("type") == "Identifier" else ""
    return ""


def _scope_names(prog: dict) -> dict:
    """Map id(function-node) -> the name it is BOUND to syntactically — real Node/Express code assigns
    arrow/function handlers to a var, a member (`this.handleUpdate = (req)=>...`), or an object/class
    property, so the function itself is anonymous; recover the binding name for triage."""
    names: dict = {}

    def _key_name(node):
        k = node.get("key") or {}
        return k.get("name") or (k.get("value") if k.get("type") in ("StringLiteral", "Literal") else None)

    for n in _walk(prog):
        if not isinstance(n, dict):
            continue
        t = n.get("type")
        if t == "FunctionDeclaration":
            idn = n.get("id") or {}
            if idn.get("name"):
                names[id(n)] = idn["name"]
        elif t == "VariableDeclarator":
            init = n.get("init") or {}
            idn = n.get("id") or {}
            if init.get("type") in _FN_TYPES and idn.get("type") == "Identifier" and idn.get("name"):
                names[id(init)] = idn["name"]
        elif t == "AssignmentExpression":
            right = n.get("right") or {}
            if right.get("type") in _FN_TYPES:
                nm = _member_final_name(n.get("left") or {})
                if nm:
                    names[id(right)] = nm
        elif t in ("ObjectMethod", "ClassMethod", "ClassPrivateMethod"):
            kn = _key_name(n)
            if kn:
                names[id(n)] = kn
        elif t in ("ObjectProperty", "Property"):
            val = n.get("value") or {}
            kn = _key_name(n)
            if val.get("type") in _FN_TYPES and kn:
                names[id(val)] = kn
    return names


def _scope_name(scope: dict, name_map: dict) -> str:
    if scope.get("type") == "Program":
        return "<module>"
    if id(scope) in name_map:
        return name_map[id(scope)]
    idn = scope.get("id") or {}
    if idn.get("type") == "Identifier" and idn.get("name"):
        return idn["name"]
    return "<anonymous>"


def _fn_param_names(fn: dict) -> list:
    """Ordered Identifier parameter names of a function (destructuring patterns skipped for v1)."""
    return [(p or {}).get("name") for p in (fn.get("params") or []) if (p or {}).get("type") == "Identifier"]


def _sink_params(scope: dict, cp_modules: set, cp_fns: set,
                 sink_param_map: dict | None = None,
                 wt_modules: set | None = None, wt_fns: set | None = None) -> set:
    """Parameter names of `scope` that flow to an arbitrary-call/code-exec sink — so a tainted arg passed
    there reaches the sink (the helper `function run(cmd){ eval(cmd); }`). With a sink_param_map, a param
    that flows into ANOTHER helper's sink-parameter also counts (the transitive middle hop)."""
    params = set(_fn_param_names(scope))
    if not params:
        return set()
    code_exec, dispatch = _call_sinks(scope, cp_modules, cp_fns, wt_modules, wt_fns)
    sinks = code_exec | dispatch | _interproc_sink_names(scope, sink_param_map or {})
    if not sinks:
        return set()
    deps, sanitizers = _build_deps(scope)
    return {p for p in params if sinks & taint_propagate(deps, {p}, sanitizers)}


def _module_sink_params(prog: dict, name_map: dict, cp_modules: set, cp_fns: set,
                        wt_modules: set | None = None, wt_fns: set | None = None) -> dict:
    """{function name -> set of parameter INDICES that reach a sink} — makes taint INTERPROCEDURAL.
    Iterated to a FIXPOINT so the summary is TRANSITIVE (h -> mid -> sink); monotone (FN-safe)."""
    fns: list = []
    for fn in _walk(prog):
        if isinstance(fn, dict) and fn.get("type") in _FN_TYPES:
            name = name_map.get(id(fn)) or ((fn.get("id") or {}).get("name"))
            if name:
                fns.append((name, fn))
    out: dict = {}
    while True:
        grew = False
        for name, fn in fns:
            params = _fn_param_names(fn)
            idxs = {i for i, p in enumerate(params)
                    if p in _sink_params(fn, cp_modules, cp_fns, out, wt_modules, wt_fns)}
            if idxs - out.get(name, set()):
                out[name] = out.get(name, set()) | idxs
                grew = True
        if not grew:
            return out


def _interproc_sink_names(scope: dict, sink_param_map: dict) -> set:
    """Arg names passed into a helper's SINK-parameter position — they reach the helper's sink."""
    out: set = set()
    if not sink_param_map:
        return out
    for call in _own(scope, {"CallExpression", "OptionalCallExpression"}):
        idxs = sink_param_map.get(_callee_final_name(call.get("callee") or {}))
        if not idxs:
            continue
        for i, arg in enumerate(call.get("arguments") or []):
            if i in idxs:
                out |= _names_in(arg)
    return out


def _returns_in(scope: dict) -> list:
    """Name footprints of this function's RETURN values: each `return X` (own scope) plus an arrow's
    expression body (`req => req.body.x`). Used for the return-taint summary."""
    out: list = []
    for n in _own(scope, {"ReturnStatement"}):
        arg = n.get("argument")
        if arg:
            out.append(_names_in(arg))
    if scope.get("type") == "ArrowFunctionExpression" and (scope.get("body") or {}).get("type") != "BlockStatement":
        out.append(_names_in(scope.get("body") or {}))
    return out


def _return_source_fixpoint(all_fns: list) -> set:
    """Names of functions whose RETURN value is tainted by a request source in their body — `function
    get(req){ return req.body.x }`. A caller `const x = get(req)` then carries taint (the callee name is in
    x's footprint), so these names join the source set. Fixpoint for chains; monotone (FN-safe).
    `all_fns` = [(name, fn-node)] across ALL files, so return-chains resolve cross-file too. (wk01jvye5)"""
    rs: set = set()
    while True:
        grew = False
        for name, fn in all_fns:
            if not name or name in rs:
                continue
            rets = _returns_in(fn)
            if not rets:
                continue
            deps, san = _build_deps(fn)
            cur = _scope_sources(fn) | rs
            tainted = taint_propagate(deps, cur, san)
            if any(set(r) & tainted for r in rets):
                rs.add(name)
                grew = True
        if not grew:
            return rs


def _analyze_scope(scope: dict, name_map: dict, cp_modules: set, cp_fns: set, seeded: dict,
                   sink_param_map: dict | None = None, return_sources: set | None = None,
                   wt_modules: set | None = None, wt_fns: set | None = None) -> list[dict]:
    code_exec, dispatch = _call_sinks(scope, cp_modules, cp_fns, wt_modules, wt_fns)
    interproc = _interproc_sink_names(scope, sink_param_map or {})   # helper-wrapped sinks (one hop)
    sinks = code_exec | dispatch | interproc
    if not sinks:
        return []
    deps, sanitizers = _build_deps(scope)
    # usage-based + one-hop callback seed + names of helpers that RETURN taint (return-taint laundering)
    sources = _scope_sources(scope) | seeded.get(id(scope), set()) | (return_sources or set())
    findings = trust_obstructions(deps, sources, sinks, sanitizers)
    if not findings:
        return []
    fired = {f["sink"] for f in findings}
    critical = bool(fired & (code_exec | interproc))     # helper-wrapped sinks are typically code-exec
    via_helper = bool(fired & interproc)
    return [{
        "kind": "arbitrary_call",
        "severity": "critical" if critical else "high",
        "function": _scope_name(scope, name_map),
        "detail": ("an external call's TARGET/code derives from untrusted input (request / argv) — the "
                   "caller chooses what runs: "
                   + ("untrusted input flows through a helper into a sink (interprocedural)" if via_helper else
                      ("a code-execution sink (eval/Function/require/import/vm) with an attacker-controlled "
                       "argument" if critical else
                       "a computed dispatch obj[KEY](...) with an attacker-controlled key"))
                   + " (the JS analog of DVD `truster`)"),
    }]


def js_arbitrary_call_audit(source_root) -> list[dict]:
    """Audit every JS/TS file under `source_root` for an external call whose target/code derives from
    untrusted input. Analyses the module scope and each function. Emits 'arbitrary_call' per scope."""
    root = pathlib.Path(source_root)
    files = [root] if root.is_file() else [
        p for p in sorted(root.rglob("*")) if p.suffix in _EXTS and "node_modules" not in p.parts]
    if not files:
        return []
    bridge = ensure_node_bridge()
    out: list[dict] = []
    parsed: list = []
    merged: dict = {}
    all_fns: list = []
    for path in files:
        prog = _parse(path, bridge)
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        name_map = _scope_names(prog)
        cp_modules, cp_fns = _child_process_bindings(prog)
        wt_modules, wt_fns = _worker_threads_bindings(prog)
        seeded = _tainted_callback_params(prog)
        own_map = _module_sink_params(prog, name_map, cp_modules, cp_fns, wt_modules, wt_fns)
        parsed.append((rel, prog, name_map, cp_modules, cp_fns, seeded, wt_modules, wt_fns))
        for fn_name, idxs in own_map.items():                              # union into the DIRECTORY-WIDE map
            merged[fn_name] = merged.get(fn_name, set()) | idxs
        for fn in _walk(prog):                                             # collect fns for return-taint
            if isinstance(fn, dict) and fn.get("type") in _FN_TYPES:
                nm = name_map.get(id(fn)) or ((fn.get("id") or {}).get("name"))
                if nm:
                    all_fns.append((nm, fn))
    return_sources = _return_source_fixpoint(all_fns)                      # source->return laundering, dir-wide
    # PASS 2 — analyze each file against the merged map, so a sink-wrapping helper exported from helper.js is
    # seen by its caller in route.js. Pure widening of each file's own map — only adds detections (FN-safe).
    for rel, prog, name_map, cp_modules, cp_fns, seeded, wt_modules, wt_fns in parsed:
        scopes = [prog] + [n for n in _walk(prog) if isinstance(n, dict) and n.get("type") in _FN_TYPES]
        for scope in scopes:
            for f in _analyze_scope(scope, name_map, cp_modules, cp_fns, seeded, merged, return_sources,
                                    wt_modules, wt_fns):
                f["file"] = rel
                out.append(f)
    return out
