"""CROSS-LANGUAGE INGEST (Python) for the trust/taint OPERATOR — proves the operator
(`lattice.taint.trust_obstructions`) is language-agnostic: it is called VERBATIM, exactly as the
Solidity legs call it. Only this ingest is new — it builds the `{value: {inputs}}` dependency dict and
the source / sink / sanitizer NAME-SETS from a stdlib-`ast` parse, the Python analog of what
solidity_taint.py does with the solc AST.

FIRST CLASS PROVEN: OS command injection (CWE-78) — an attacker-controlled value (a request field, a
CLI arg, an env var) reaching a shell-spawning sink (`os.system` / `os.popen` / `subprocess.*(shell=True)`)
with no `shlex.quote`-style sanitizer on the path. Genuine TOGGLE: the byte-identical `shlex.quote`-
wrapped version is SILENT. This carries because the toggle is NAME-LEVEL (a sanitizer name enters the
value's footprint), which is the only kind of safe-toggle the flow-insensitive operator can honor — the
load-bearing constraint the cross-language design verification surfaced.

Three defects the adversarial verifier found are fixed here:
  (1) INLINE SOURCE — `os.system(request.args['h'])` with no intermediate binding: the source-marker
      names (`request`, `argv`, `environ`, `input`) are SEEDED as sources, so a bare `request.*` chain in
      a sink position is tainted without a deps entry (the inline-read FN solidity_taint patched).
  (2) DOTTED callee — sinks/sanitizers key on the DOTTED name (`os.system`, `shlex.quote`), so
      `pickle.loads` != `json.loads` and a `quote` method is not confused with an unrelated `quote`.
  (3) SANITIZER-AWARE footprint — names inside a `shlex.quote(...)` (or other sanitizer) call do NOT
      reach the sink, so the inline-sanitized version is silent even though `request` is lexically present.
"""
import ast
import pathlib
from collections import Counter

from lattice.taint import trust_obstructions, taint_propagate

# Untrusted roots: web request objects, CLI args, env, stdin. Seeded as tainted sources (fix #1).
_SOURCE_MARKS = {"request", "argv", "environ", "input", "stdin"}
# Shell-spawning sinks, keyed on the DOTTED callee (fix #2). os.system/os.popen always spawn a shell;
# subprocess.* only when shell=True (a list arg with no shell is safe).
# os.system/os.popen AND subprocess.getoutput/getstatusoutput always run `/bin/sh -c <arg>` — there is no
# shell= opt-out, so arg[0] is shell-interpreted unconditionally (getoutput was the FN: it had been gated
# on shell=True, which it never carries).
_ALWAYS_SHELL = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
_SUBPROCESS = {"subprocess.call", "subprocess.run", "subprocess.Popen",
               "subprocess.check_output", "subprocess.check_call"}
# ONLY genuine shell quoters sanitize a shell command, keyed on the DOTTED callee. html.escape /
# cgi.escape / urllib.parse.quote / json.dumps / a bare `*.escape` do NOT neutralize shell metacharacters
# — treating them as sanitizers was a SILENT FN (a real injection through html.escape was reported clean).
# shlex.quote / pipes.quote / shlex.join are the real shell quoters (idiom-sweep ws6yh6pp7).
_SHELL_SANITIZERS = {"shlex.quote", "pipes.quote", "shlex.join"}

# ── SQL INJECTION (CWE-89) ────────────────────────────────────────────────────
# Any `.execute` / `.executemany` / `.executescript` call whose arg0 carries a tainted name
# is a SQLi lead. The `.query`/.raw pattern of SQLAlchemy/ORMs is caught the same way.
# LEAF names (method endings) — we can't know the receiver's real type from AST alone, so any
# object with these member names is treated as a SQL execution surface (FIRE=lead). A safe
# call (parametrized: arg0 is a bare string constant AND arg1 is a tuple/dict/list) is silent
# because arg0's name-footprint is empty — the operator will not taint an empty set.
_SQL_SINK_LEAVES = {"execute", "executemany", "executescript"}
# Full-dotted SQL sinks: bare imported helpers or explicitly SQL-flavored calls.
_SQL_SINK_DOTTED = {"text",                  # sqlalchemy.text(sql)
                    "sqlalchemy.text",
                    "sql.text",
                    "session.query",
                    "session.execute",
                    "db.session.execute"}
# SQL sanitizers: no in-band string-quoting for SQL is safe (that's the whole point of SQLi);
# the ONLY safe pattern is parametrized queries. We recognize the shape at the sink site
# (arg1 is a tuple/list/dict literal AND arg0 is a bare string constant) — see `_is_parametrized`.
# The operator itself gets an empty sanitizer set for SQL — the parametrization check is applied
# at sink-detection time, before names ever enter the sink footprint.
_SQL_SANITIZERS: set = set()


def _dotted(node) -> str:
    """Dotted name of an attribute/name chain: `os.system`, `shlex.quote`, `subprocess.run`."""
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_sanitizer_call(node) -> bool:
    """A call whose DOTTED callee is a genuine shell quoter (shlex.quote / pipes.quote / shlex.join).
    Keyed on the full dotted name so html.escape / urllib.parse.quote are NOT mistaken for shell-safe."""
    return isinstance(node, ast.Call) and _dotted(node.func) in _SHELL_SANITIZERS


def _value_names(node) -> set:
    """The untrusted name footprint of an expression: every Name id and Attribute attr it reads —
    EXCEPT names inside a sanitizer call, which are stripped (fix #3: a value through shlex.quote does
    not carry shell-injection taint even though the source name is lexically inside it)."""
    out: set = set()
    if node is None:
        return out
    if isinstance(node, ast.Call) and _is_sanitizer_call(node):
        return out                                   # sanitized span — nothing inside reaches the sink
    if isinstance(node, ast.Name):
        out.add(node.id)
    elif isinstance(node, ast.Attribute):
        out.add(node.attr)
        out |= _value_names(node.value)
    else:
        for child in ast.iter_child_nodes(node):
            out |= _value_names(child)
    return out


def _target_names(tgt) -> list:
    """Bound names of an assignment target (a plain name, or names inside a tuple/list unpack)."""
    if isinstance(tgt, ast.Name):
        return [tgt.id]
    if isinstance(tgt, (ast.Tuple, ast.List)):
        out = []
        for e in tgt.elts:
            out += _target_names(e)
        return out
    return []


def _has_shell_true(call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


# A nested SCOPE boundary — statements inside one are analysed on that scope's own pass, so a call is
# attributed to exactly one scope (the module body and each function are separate scopes).
_SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _excluded_nodes(root):
    """All AST nodes inside a nested scope under `root` (so the module pass skips function bodies and
    each function pass skips its own nested defs)."""
    out: set = set()
    for n in ast.walk(root):
        if isinstance(n, _SCOPE_TYPES) and n is not root:
            for sub in ast.walk(n):
                out.add(sub)
    return out


def _own_calls(root):
    """Calls directly in `root`'s scope (module body or a function body), not in a nested scope."""
    excl = _excluded_nodes(root)
    for n in ast.walk(root):
        if isinstance(n, ast.Call) and n not in excl:
            yield n


def _own_assigns(root):
    excl = _excluded_nodes(root)
    for n in ast.walk(root):
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and n not in excl:
            yield n


def _build_deps(fn_node):
    """`{value: {input names}}` from assignments (sanitizer-aware RHS) + the names BOUND from a
    sanitizer call (passed to the operator as sanitizers — sanitizer-wins)."""
    deps: dict = {}
    sanitizers: set = set()
    for node in _own_assigns(fn_node):
        value = node.value
        targets = []
        if isinstance(node, ast.Assign):
            for t in node.targets:
                targets += _target_names(t)
        elif node.target is not None:                # AnnAssign / AugAssign — a single target
            targets += _target_names(node.target)
        if value is None:
            continue
        if _is_sanitizer_call(value):
            sanitizers |= set(targets)               # `safe = shlex.quote(x)` -> safe is sanitized
        names = _value_names(value)
        if isinstance(node, ast.AugAssign):
            names = names | set(targets)             # `cmd += x` also READS cmd's prior (tainted) value
        for t in targets:
            deps[t] = deps.get(t, set()) | names
    return deps, sanitizers


def _command_sink_names(fn_node) -> set:
    """Names that flow into a shell-spawning sink's command argument (sanitizer-aware)."""
    sinks: set = set()
    for call in _own_calls(fn_node):
        d = _dotted(call.func)
        # `from os import system; system(x)` / `from subprocess import getoutput` — a BARE imported leaf
        # binds the same shell-spawning callable; the dotted check alone missed it (idiom-sweep ws6yh6pp7).
        bare_leaf = (isinstance(call.func, ast.Name)
                     and call.func.id in ("system", "popen", "getoutput", "getstatusoutput"))
        if d in _ALWAYS_SHELL or bare_leaf:
            for a in call.args:
                sinks |= _value_names(a)
        elif d in _SUBPROCESS and _has_shell_true(call):
            if call.args:
                sinks |= _value_names(call.args[0])
    return sinks


def _is_parametrized_sql(call) -> bool:
    """The ONE safe SQLi pattern: `cur.execute("SELECT ... WHERE x = ?", (val,))` — arg0 is a
    bare string constant AND arg1 is a tuple/list/dict literal. If arg0 is any composition
    (concat, f-string, .format), the query is built from untrusted inputs and parametrization
    doesn't apply. Two args required; positional only (kwargs `params=` are still safe but rarer)."""
    if len(call.args) < 2:
        return False
    if not (isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)):
        return False
    return isinstance(call.args[1], (ast.Tuple, ast.List, ast.Dict))


def _sql_sink_names(fn_node) -> set:
    """Names flowing into a SQL execution sink's query argument. A parametrized call is
    silent (arg0 is bare constant, arg1 is a container literal); everything else contributes
    arg0's name footprint (composed queries: concat, f-string, .format)."""
    sinks: set = set()
    for call in _own_calls(fn_node):
        d = _dotted(call.func)
        # leaf method call: any receiver `.execute(sql)` / `.executemany(sql)` / `.executescript(sql)`
        leaf = d.rsplit(".", 1)[-1] if "." in d else None
        is_sql_sink = (d in _SQL_SINK_DOTTED
                       or (leaf in _SQL_SINK_LEAVES)
                       or (isinstance(call.func, ast.Name) and call.func.id in _SQL_SINK_LEAVES))
        if not is_sql_sink:
            continue
        if _is_parametrized_sql(call):
            continue                                  # safe: bound values passed separately
        if call.args:
            sinks |= _value_names(call.args[0])
    return sinks


def _params_of(fn_node) -> list:
    a = fn_node.args
    return [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)]


def _sink_params(fn_node) -> tuple[set, set]:
    """Parameter names of `fn_node` that flow to (shell_sink, sql_sink) in its body — so a TAINTED
    arg passed into that position reaches the corresponding sink. Returns two sets so the interproc
    map can attribute each hit to the right attack class."""
    params = set(_params_of(fn_node))
    if not params:
        return set(), set()
    shell_sinks = _command_sink_names(fn_node)
    sql_sinks = _sql_sink_names(fn_node)
    if not (shell_sinks or sql_sinks):
        return set(), set()
    deps, sanitizers = _build_deps(fn_node)
    sh = {p for p in params if shell_sinks
          and shell_sinks & taint_propagate(deps, {p}, sanitizers)}
    sq = {p for p in params if sql_sinks
          and sql_sinks & taint_propagate(deps, {p}, _SQL_SANITIZERS)}
    return sh, sq


def _module_sink_params(tree) -> tuple[dict, dict]:
    """{function name -> set of parameter INDICES that reach a sink}, one dict per attack class.
    Used to make taint INTERPROCEDURAL: a caller passing a tainted arg into a sink-parameter
    position reaches the sink."""
    shell_out: dict = {}
    sql_out: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = _params_of(node)
            sh, sq = _sink_params(node)
            sh_idxs = {i for i, p in enumerate(params) if p in sh}
            sq_idxs = {i for i, p in enumerate(params) if p in sq}
            if sh_idxs:
                shell_out[node.name] = sh_idxs
            if sq_idxs:
                sql_out[node.name] = sq_idxs
    return shell_out, sql_out


def _module_name(rel: str) -> str:
    path = pathlib.PurePosixPath(rel)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _function_entries(tree, module: str) -> list[dict]:
    """Index function definitions by stable module + lexical identity."""
    out: list[dict] = []

    def walk_body(body, lexical=(), classes=(), in_function=False, parent_identity=None):
        for statement in body or []:
            if isinstance(statement, ast.ClassDef):
                walk_body(statement.body, lexical + (statement.name,),
                          classes + (statement.name,), False, parent_identity)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = lexical + (statement.name,)
                identity = f"py:{module}:{'.'.join(qual)}"
                entry = {"node": statement, "name": statement.name, "qual": qual,
                         "classes": classes, "identity": identity,
                         "parent_identity": parent_identity,
                         "bound_method": bool(classes) and not in_function,
                         "top_level": not lexical}
                out.append(entry)
                # Nested functions have a real lexical parent; index them without treating a method's
                # surrounding class as a bare-name lookup scope.
                walk_body(statement.body, qual, classes, True, identity)

    walk_body(tree.body)
    return out


def _call_params(entry: dict) -> list[str]:
    """Parameters supplied at a call site (drop an implicitly bound self/cls receiver)."""
    params = _params_of(entry["node"])
    if not entry["bound_method"] or not params:
        return params
    decorators = {_dotted(decorator) for decorator in entry["node"].decorator_list}
    if "staticmethod" not in decorators:
        return params[1:]
    return params


def _relative_import(current_module: str, module: str | None, level: int, is_package: bool) -> str:
    if not level:
        return module or ""
    package = current_module if is_package else current_module.rpartition(".")[0]
    parts = package.split(".") if package else []
    keep = max(0, len(parts) - (level - 1))
    prefix = parts[:keep]
    if module:
        prefix.extend(module.split("."))
    return ".".join(part for part in prefix if part)


def _scope_import_bindings(root, module: str, module_defs: dict, is_package: bool) -> dict:
    """Imports bound directly in one lexical scope, excluding every nested scope."""
    imported_symbols: dict[str, str] = {}
    imported_names: set[str] = set()
    module_aliases: dict[str, str] = {}
    excluded = _excluded_nodes(root)
    imports = sorted(
        (node for node in ast.walk(root)
         if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in excluded),
        key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)))
    for statement in imports:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                binding = alias.asname or alias.name.split(".", 1)[0]
                target = alias.name if alias.asname else binding
                module_aliases[binding] = target
        else:
            target_module = _relative_import(module, statement.module, statement.level, is_package)
            for alias in statement.names:
                if alias.name == "*":
                    continue
                binding = alias.asname or alias.name
                imported_names.add(binding)
                candidates = module_defs.get(target_module, {}).get(alias.name, [])
                if len(candidates) == 1:
                    imported_symbols[binding] = candidates[0]
    return {"imported_symbols": imported_symbols, "imported_names": imported_names,
            "module_aliases": module_aliases}


def _file_resolution_context(rel: str, tree, entries: list[dict], module_defs: dict) -> dict:
    module = _module_name(rel)
    top_defs: dict[str, list[str]] = {}
    class_defs: dict[tuple[str, str], list[str]] = {}
    for entry in entries:
        if entry["top_level"]:
            top_defs.setdefault(entry["name"], []).append(entry["identity"])
        if entry["bound_method"]:
            class_defs.setdefault((".".join(entry["classes"]), entry["name"]), []).append(
                entry["identity"])

    is_package = pathlib.PurePosixPath(rel).name == "__init__.py"
    module_imports = _scope_import_bindings(tree, module, module_defs, is_package)
    scope_imports = {
        entry["identity"]: _scope_import_bindings(
            entry["node"], module, module_defs, is_package)
        for entry in entries
    }
    scope_parents = {
        entry["identity"]: entry["parent_identity"]
        for entry in entries
    }

    return {"module": module, "top_defs": top_defs, "class_defs": class_defs,
            **module_imports, "scope_imports": scope_imports,
            "scope_parents": scope_parents,
            "module_defs": module_defs}


def _python_import_scopes(context: dict, scope_entry: dict | None):
    """Yield import bindings from the current function outward, then the module scope."""
    identity = scope_entry["identity"] if scope_entry else None
    while identity:
        yield context["scope_imports"][identity]
        identity = context["scope_parents"].get(identity)
    yield context


def _python_callee_keys(call, context: dict, scope_entry: dict | None) -> tuple[str, ...]:
    """Resolve only identities proven by Python lexical or import syntax."""
    import_scopes = tuple(_python_import_scopes(context, scope_entry))
    if isinstance(call.func, ast.Name):
        name = call.func.id
        for bindings in import_scopes:
            imported = bindings["imported_symbols"].get(name)
            if imported:
                return (imported,)
            if name in bindings["imported_names"] or name in bindings["module_aliases"]:
                return ()
        local = context["top_defs"].get(name, [])
        if len(local) == 1:
            return (local[0],)
        return (name,)  # admitted only when the global definition is unique

    dotted = _dotted(call.func)
    if not dotted:
        return ()
    parts = dotted.split(".")
    if len(parts) >= 2:
        for bindings in import_scopes:
            if parts[0] in bindings["module_aliases"]:
                target_module = bindings["module_aliases"][parts[0]]
                if len(parts) > 2:
                    target_module = ".".join((target_module, *parts[1:-1]))
                candidates = context["module_defs"].get(target_module, {}).get(parts[-1], [])
                return (candidates[0],) if len(candidates) == 1 else ()
            if parts[0] in bindings["imported_names"]:
                return ()

    if (scope_entry and len(parts) == 2 and parts[0] in {"self", "cls"}
            and scope_entry["classes"]):
        candidates = context["class_defs"].get(
            (".".join(scope_entry["classes"]), parts[-1]), [])
        return (candidates[0],) if len(candidates) == 1 else ()

    if len(parts) == 2:
        candidates = context["class_defs"].get((parts[0], parts[1]), [])
        return (candidates[0],) if len(candidates) == 1 else ()
    # An arbitrary receiver is not evidence that a same-named local method is its target.
    return ()


def _interproc_sink_names(scope, sink_param_map: dict, resolver=None) -> set:
    """Arg names passed into a helper's SINK-parameter position — they reach the helper's sink."""
    out: set = set()
    if not sink_param_map:
        return out
    for call in _own_calls(scope):
        keys = resolver(call) if resolver else (_dotted(call.func).split(".")[-1],)
        idxs = next((sink_param_map[key] for key in keys if sink_param_map.get(key)), None)
        if not idxs:
            continue
        for i, arg in enumerate(call.args):
            if i in idxs:
                out |= _value_names(arg)
    return out


def _analyze_scope(root, scope_name: str,
                   shell_map: dict | None = None,
                   sql_map: dict | None = None,
                   resolver=None) -> list[dict]:
    """Analyze one scope (a function body OR the module top level — real scripts wire source->sink at
    module level, the shape of every Bandit example). Emits findings for BOTH attack classes."""
    deps, sanitizers = _build_deps(root)
    out: list[dict] = []

    # Attack class 1 — OS command injection (CWE-78)
    shell_sinks = _command_sink_names(root) | _interproc_sink_names(root, shell_map or {}, resolver)
    if shell_sinks:
        if trust_obstructions(deps, _SOURCE_MARKS, shell_sinks, sanitizers):
            out.append({
                "kind": "command_injection",
                "severity": "critical",
                "function": scope_name,
                "cwe": "CWE-78",
                "detail": ("an attacker-controllable value (request field / argv / env) reaches a "
                           "shell-spawning sink (os.system / os.popen / subprocess(shell=True)) with no "
                           "shlex.quote sanitizer on the path — OS command injection"),
            })

    # Attack class 2 — SQL injection (CWE-89)
    sql_sinks = _sql_sink_names(root) | _interproc_sink_names(root, sql_map or {}, resolver)
    if sql_sinks:
        if trust_obstructions(deps, _SOURCE_MARKS, sql_sinks, _SQL_SANITIZERS):
            out.append({
                "kind": "sql_injection",
                "severity": "critical",
                "function": scope_name,
                "cwe": "CWE-89",
                "detail": ("an attacker-controllable value (request field / argv / env) is composed into "
                           "a SQL string passed to `.execute` / `.executemany` / `text` / `.query` — "
                           "parametrize the query (arg1 = tuple/list/dict of bound values) instead"),
            })
    return out


_SKIP_DIRS = {"node_modules", ".venv", "venv", "site-packages", "__pycache__",
              ".git", "dist", "build", ".tox", ".mypy_cache"}


def python_taint_audit(source_root) -> list[dict]:
    """Audit every `.py` under `source_root` for OS command injection via the trust/taint operator.
    Analyses both the MODULE top-level scope and each function. Emits one 'command_injection' finding
    per offending scope. FIRE=lead / SILENCE≠proof."""
    root = pathlib.Path(source_root)
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*.py")
        if not (_SKIP_DIRS & set(p.relative_to(root).parts)))
    parsed: list = []
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, UnicodeDecodeError, ValueError):
            continue                                  # unparsable — an honest skip, never a false clean
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        parsed.append((rel, tree))
    # PASS 1 — build exact module/lexical identities. A bare key is only a compatibility fallback for a
    # globally unique top-level definition; same-file calls and explicit imports resolve exact identities
    # first, so an unrelated duplicate can neither suppress nor receive a summary. This subsumes the old
    # directory-wide widening (a sink-wrapping helper in helper.py stays visible to its caller in app.py)
    # while being precise. ONE merged map PER attack class so a shell-sink helper doesn't inflate SQL
    # findings and vice-versa (deep-sweep wk01jvye5).
    indexed: list = []
    module_defs: dict[str, dict[str, list[str]]] = {}
    exact_counts: Counter = Counter()
    bare_counts: Counter = Counter()
    for rel, tree in parsed:
        module = _module_name(rel)
        entries = _function_entries(tree, module)
        indexed.append((rel, tree, entries))
        for entry in entries:
            exact_counts[entry["identity"]] += 1
            if entry["top_level"]:
                bare_counts[entry["name"]] += 1
                module_defs.setdefault(module, {}).setdefault(entry["name"], []).append(
                    entry["identity"])

    merged_shell: dict = {}
    merged_sql: dict = {}
    for _rel, _tree, entries in indexed:
        for entry in entries:
            if exact_counts[entry["identity"]] != 1:
                continue
            params = _call_params(entry)
            sh_names, sq_names = _sink_params(entry["node"])
            sh_idxs = {i for i, param in enumerate(params) if param in sh_names}
            sq_idxs = {i for i, param in enumerate(params) if param in sq_names}
            bare_unique = entry["top_level"] and bare_counts[entry["name"]] == 1
            if sh_idxs:
                merged_shell[entry["identity"]] = merged_shell.get(entry["identity"], set()) | sh_idxs
                if bare_unique:
                    merged_shell[entry["name"]] = merged_shell.get(entry["name"], set()) | sh_idxs
            if sq_idxs:
                merged_sql[entry["identity"]] = merged_sql.get(entry["identity"], set()) | sq_idxs
                if bare_unique:
                    merged_sql[entry["name"]] = merged_sql.get(entry["name"], set()) | sq_idxs

    # PASS 2 — analyze each file's scopes with its lexical/import resolver.
    out: list[dict] = []
    for rel, tree, entries in indexed:
        context = _file_resolution_context(rel, tree, entries, module_defs)
        scopes = [(tree, "<module>", None)]           # the module body is a scope too
        scopes.extend((entry["node"], entry["name"], entry) for entry in entries)
        for scope, name, entry in scopes:
            resolver = lambda call, ctx=context, ent=entry: _python_callee_keys(call, ctx, ent)
            for f in _analyze_scope(scope, name, merged_shell, merged_sql, resolver):
                f["file"] = rel
                out.append(f)
    return out
