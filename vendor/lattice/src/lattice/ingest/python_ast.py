# src/lattice/ingest/python_ast.py
"""Python ingest backend — via the stdlib `ast`, fact-grade and dependency-free.

Same shape as the Solidity backend: parse each file's AST, emit the universal RawIngest
(functions, classes with bases -> inheritance, methods, imports, safely resolved call edges),
and let the language-agnostic builder + every analysis work unchanged. "Public" follows
the Python convention: a name without a leading underscore is the inbound surface.

Calls resolve by qualified/module/container identity where syntax proves it. Unknown receiver
types remain unresolved rather than becoming a confidence-1 edge to the first duplicate name.
Secaudit's source scan (eval/os.system/pickle/...) already speaks Python, so security analysis
works on the result too.
"""
from __future__ import annotations
import ast
import pathlib
import posixpath
from dataclasses import dataclass

from lattice.ingest.types import RawIngest, RawSymbol, RawReference

_SKIP_DIRS = {"node_modules", ".venv", "venv", "site-packages", "__pycache__",
              ".git", "dist", "build", ".tox", ".mypy_cache"}


def _public(name: str) -> bool:
    return not name.startswith("_")


def _is_stub_body(body: list[ast.stmt]) -> bool:
    """A body that admits it isn't implemented: only pass/Ellipsis/docstring, or a
    lone `raise NotImplementedError(...)`. The TS frontend has carried is_stub since
    phase 1; this is the Python analogue so public_path_to_stub works here too."""
    stmts = list(body)
    if stmts and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant) \
            and isinstance(stmts[0].value.value, str):
        stmts = stmts[1:]                      # leading docstring
    if not stmts:
        return True
    if all(isinstance(s, ast.Pass)
           or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
               and s.value.value is Ellipsis)
           for s in stmts):
        return True
    if len(stmts) == 1 and isinstance(stmts[0], ast.Raise):
        exc = stmts[0].exc
        if isinstance(exc, ast.Call):
            exc = exc.func
        return isinstance(exc, ast.Name) and exc.id == "NotImplementedError"
    return False


def _base_names(cls: ast.ClassDef) -> list[str]:
    out: list[str] = []
    for b in cls.bases:
        if isinstance(b, ast.Name):
            out.append(b.id)
        elif isinstance(b, ast.Attribute):
            out.append(b.attr)                     # pkg.Base -> Base
    return out


def _expr_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


_Scope = tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _ImportBinding:
    target_file: str
    # Source-expression prefix that denotes ``target_file``. For ``import pkg.util``
    # this is ("pkg", "util"); for ``import pkg.util as u`` it is ("u",).
    expression_prefix: tuple[str, ...]
    imported_symbol: str | None = None
    ambiguous: bool = False


class _ModuleBindingNames(ast.NodeVisitor):
    """Names a package initializer may expose, excluding nested local scopes."""

    def __init__(self):
        self.names: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef):
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda):
        return

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.names.add(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            if alias.name != "*":
                self.names.add(alias.asname or alias.name)


def _module_binding_names(tree: ast.Module) -> set[str]:
    visitor = _ModuleBindingNames()
    visitor.visit(tree)
    return visitor.names


class _Walker(ast.NodeVisitor):
    """Collect symbols + pending call edges, tracking the enclosing class (for method
    container) and the enclosing def (so a call is attributed to the function it's in)."""

    def __init__(self, rel: str):
        self.rel = rel
        self.symbols: list[RawSymbol] = []
        self.pending: list[tuple] = []      # (from_line, bare, qualified, lexical scope)
        self.imports: list[tuple[ast.Import | ast.ImportFrom, _Scope, bool]] = []
        self._scope: list[str] = []
        self._scope_kinds: list[str] = []
        self._class: str | None = None
        self._func_line: int | None = None
        self._direct_body = False

    def _scope_key(self) -> _Scope:
        return tuple(zip(self._scope, self._scope_kinds))

    def _visit_body(self, body: list[ast.stmt]):
        previous = self._direct_body
        for child in body:
            self._direct_body = True
            self.visit(child)
        self._direct_body = previous

    def visit_Module(self, node: ast.Module):
        self._visit_body(node.body)

    def generic_visit(self, node):
        # An import nested in an if/try/loop is real import evidence, but execution of
        # that branch is not proven, so it must not become a fact-grade lexical binding.
        previous = self._direct_body
        self._direct_body = False
        super().generic_visit(node)
        self._direct_body = previous

    def visit_Import(self, node: ast.Import):
        self.imports.append((node, self._scope_key(), self._direct_body))

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self.imports.append((node, self._scope_key(), self._direct_body))

    def visit_ClassDef(self, node: ast.ClassDef):
        container = ".".join(self._scope) or None
        qualified = f"{container}.{node.name}" if container else node.name
        self.symbols.append(RawSymbol(
            name=node.name, kind="class", file=self.rel,
            start_line=node.lineno, end_line=getattr(node, "end_lineno", node.lineno),
            container=container,
            exported=_public(node.name) and "function" not in self._scope_kinds,
            extends=_base_names(node)))
        prev = self._class
        self._class = qualified
        self._scope.append(node.name)
        self._scope_kinds.append("class")
        self._visit_body(node.body)
        self._scope_kinds.pop()
        self._scope.pop()
        self._class = prev

    def _visit_func(self, node):
        kind = "method" if self._class else "function"
        container = ".".join(self._scope) or None
        params = [a.arg for a in node.args.args]
        if node.args.vararg:
            params.append("..." + node.args.vararg.arg)
        self.symbols.append(RawSymbol(
            name=node.name, kind=kind, file=self.rel,
            start_line=node.lineno, end_line=getattr(node, "end_lineno", node.lineno),
            container=container,
            exported=_public(node.name) and "function" not in self._scope_kinds,
            params=params,
            is_stub=_is_stub_body(node.body)))
        prev_f, prev_c = self._func_line, self._class
        self._func_line = node.lineno
        self._class = None                          # nested defs aren't methods of the class
        self._scope.append(node.name)
        self._scope_kinds.append("function")
        self._visit_body(node.body)
        self._scope_kinds.pop()
        self._scope.pop()
        self._func_line, self._class = prev_f, prev_c

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_Call(self, node: ast.Call):
        full = _expr_name(node.func)
        name = full.rsplit(".", 1)[-1] if full else None
        if name:
            # Inside a def: anchor at the def line so the builder lands on the function
            # vertex. Outside any def (module/class body): anchor at the call's own line —
            # the builder attributes spans outside every symbol to the module vertex, so
            # top-level-invoked functions (`main()` under the __main__ guard) aren't
            # seen as uncalled.
            self.pending.append((self._func_line if self._func_line is not None
                                 else node.lineno, name, full, self._scope_key()))
        self.generic_visit(node)


def _is_main_guard(node: ast.stmt) -> bool:
    """`if __name__ == "__main__":` (either operand order) — Python's executed-directly
    marker, the analogue of package.json bin/main on the TS side."""
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        return False
    t = node.test
    if len(t.ops) != 1 or not isinstance(t.ops[0], ast.Eq):
        return False
    sides = [t.left, *t.comparators]
    return (any(isinstance(s, ast.Name) and s.id == "__name__" for s in sides)
            and any(isinstance(s, ast.Constant) and s.value == "__main__" for s in sides))


def python_ingest(root, language: str = "python") -> RawIngest:
    root = pathlib.Path(root)
    direct_file = root if root.is_file() else None
    if direct_file is not None:
        py_files = [direct_file] if direct_file.suffix == ".py" else []
        root = root.parent
    else:
        py_files = sorted(
            p for p in root.rglob("*.py")
            if not (_SKIP_DIRS & set(p.relative_to(root).parts)))

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    diagnostics: list[dict] = []
    files = [path.relative_to(root).as_posix() for path in py_files]
    entry_files: set[str] = set()
    pending: list[tuple] = []               # (rel, from_line, bare, qualified, scope)
    parsed: list[tuple[str, ast.Module, list[tuple]]] = []

    if not py_files:
        kind = "unsupported_source_file" if direct_file is not None else "no_source_files"
        diagnostics.append({
            "kind": kind, "severity": "error", "language": "python",
            **({"file": direct_file.name} if direct_file is not None else {}),
            "message": (f"expected a .py source file, got {direct_file.name}"
                        if direct_file is not None
                        else "no Python source files found"),
        })
        return RawIngest(language="python", root=str(root), diagnostics=diagnostics,
                         files=files)

    for path in py_files:
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text)
        except (OSError, SyntaxError, ValueError) as exc:
            diagnostics.append({
                "kind": "read_error" if isinstance(exc, OSError) else "parse_error",
                "severity": "error", "language": "python",
                "file": rel, "message": str(exc),
            })
            continue
        # Shebang or a __main__ guard marks a file meant to be EXECUTED directly — a
        # program entrypoint. The builder roots reachability there, so functions invoked
        # only at program start (and sinks reached from them) are provably reachable.
        if text.startswith("#!") or any(_is_main_guard(n) for n in tree.body):
            entry_files.add(rel)
        w = _Walker(rel)
        w.visit(tree)
        parsed.append((rel, tree, w.imports))
        symbols.extend(w.symbols)
        for from_line, callee, full, scope in w.pending:
            pending.append((rel, from_line, callee, full, scope))

    known = set(files)
    module_names = {rel: _module_binding_names(tree) for rel, tree, _ in parsed}
    # (file, lexical scope) -> local root name -> exact import identity. Module imports
    # live at scope (); function imports live only in that function/nested closures.
    import_bindings: dict[tuple[str, _Scope], dict[str, _ImportBinding]] = {}

    def module_target(module: str, base: pathlib.PurePosixPath | None = None):
        stem = base or pathlib.PurePosixPath()
        if module:
            stem = stem.joinpath(*module.split("."))
        candidates = [posixpath.normpath(str(stem) + ".py"),
                      posixpath.normpath(str(stem / "__init__.py"))]
        for candidate in candidates:
            if candidate in known:
                return candidate, True
        return candidates[0], False

    def bind(rel: str, scope: _Scope, local: str, binding: _ImportBinding,
             visible: bool) -> None:
        if visible and local != "*":
            import_bindings.setdefault((rel, scope), {})[local] = binding

    for rel, _tree, imports in parsed:
        for node, scope, binding_visible in imports:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target, resolved = module_target(alias.name)
                    references.append(RawReference(
                        kind="imports", from_file=rel, from_line=node.lineno,
                        to_file=target if resolved else None,
                        to_line=1 if resolved else None,
                        resolved=resolved, name=alias.name))
                    if resolved:
                        local = alias.asname or alias.name.split(".", 1)[0]
                        expression_prefix = ((alias.asname,) if alias.asname
                                             else tuple(alias.name.split(".")))
                        bind(rel, scope, local, _ImportBinding(
                            target_file=target,
                            expression_prefix=expression_prefix,
                        ), binding_visible)
                continue

            # ``from package import item`` always imports/initializes the package. The
            # item is a submodule only if that file exists and the package initializer
            # does not expose a same-name top-level attribute. When both exist, Python's
            # runtime attribute/import order matters, so retain the import edge but mark
            # the lexical binding ambiguous rather than selecting a fact-grade target.
            base: pathlib.PurePosixPath | None = None
            if node.level:
                base = pathlib.PurePosixPath(rel).parent
                for _ in range(node.level - 1):
                    base = base.parent
            package_module = node.module or ""
            if node.level and not package_module:
                package_target = posixpath.normpath(str(base / "__init__.py"))
                package_resolved = package_target in known
            else:
                package_target, package_resolved = module_target(package_module, base)
            package_is_init = package_target.endswith("/__init__.py") \
                or package_target == "__init__.py"
            for alias in node.names:
                if alias.name == "*":
                    references.append(RawReference(
                        kind="imports", from_file=rel, from_line=node.lineno,
                        to_file=package_target if package_resolved or node.level else None,
                        to_line=1 if package_resolved else None,
                        resolved=package_resolved,
                        name="." * node.level + package_module,
                    ))
                    continue

                submodule_name = ".".join(
                    part for part in (package_module, alias.name) if part)
                submodule_target, submodule_resolved = module_target(submodule_name, base)
                init_exports_name = (package_resolved and package_is_init
                                     and alias.name in module_names.get(package_target, set()))
                ambiguous = submodule_resolved and init_exports_name
                local = alias.asname or alias.name

                if submodule_resolved and not init_exports_name:
                    item_target, item_resolved = submodule_target, True
                    binding = _ImportBinding(
                        target_file=submodule_target,
                        expression_prefix=(local,),
                    )
                else:
                    item_target, item_resolved = package_target, package_resolved
                    binding = _ImportBinding(
                        target_file=package_target,
                        expression_prefix=(local,),
                        imported_symbol=alias.name,
                        ambiguous=ambiguous,
                    )
                # Preserve the written import module in evidence. The selected alias may
                # refine its target to a real submodule, but `from .api import run` is
                # still the `.api` import contract, not a fictional `.api.run` module.
                spec = "." * node.level + (package_module or alias.name)
                references.append(RawReference(
                    kind="imports", from_file=rel, from_line=node.lineno,
                    to_file=item_target if item_resolved or node.level else None,
                    to_line=1 if item_resolved else None,
                    resolved=item_resolved, name=spec))
                if item_resolved:
                    bind(rel, scope, local, binding, binding_visible)

    by_name: dict[str, list[RawSymbol]] = {}
    for symbol in symbols:
        if symbol.kind in ("function", "method", "class"):
            by_name.setdefault(symbol.name, []).append(symbol)

    def enclosing(rel: str, line: int) -> RawSymbol | None:
        matches = [s for s in symbols if s.file == rel and s.kind in ("function", "method")
                   and s.start_line <= line <= s.end_line]
        return min(matches, key=lambda s: s.end_line - s.start_line) if matches else None

    def visible_scopes(scope: _Scope):
        """Python lexical import scopes: exact, enclosing functions, then module.

        A class namespace is not a closure for its methods, so class-only parents are
        intentionally skipped. This prevents a function-local alias from leaking to a
        sibling while still allowing a nested function to capture its outer binding.
        """
        yielded: set[_Scope] = set()
        for candidate in [scope, *[scope[:i] for i in range(len(scope) - 1, 0, -1)], ()]:
            if candidate in yielded:
                continue
            if candidate and candidate != scope and candidate[-1][1] != "function":
                continue
            yielded.add(candidate)
            yield candidate

    def imported_binding(rel: str, scope: _Scope, name: str) -> _ImportBinding | None:
        for candidate_scope in visible_scopes(scope):
            binding = import_bindings.get((rel, candidate_scope), {}).get(name)
            if binding is not None:
                return binding
        return None

    for rel, from_line, callee, full, scope in pending:
        caller = enclosing(rel, from_line)
        candidates: list[RawSymbol] = []
        exact_identity = False
        intended_file: str | None = None
        if "." in full:
            parts = tuple(full.split("."))
            qualifier_parts = parts[:-1]
            qualifier = ".".join(qualifier_parts)
            root_qualifier = parts[0]
            if qualifier in {"self", "cls"} and caller and caller.container:
                candidates = [s for s in by_name.get(callee, [])
                              if s.container == caller.container]
                exact_identity = True
                intended_file = rel
            else:
                binding = imported_binding(rel, scope, root_qualifier)
                if binding is not None:
                    exact_identity = True
                    if (binding.ambiguous
                            or qualifier_parts[:len(binding.expression_prefix)]
                            != binding.expression_prefix):
                        intended_file = binding.target_file if binding.ambiguous else None
                    else:
                        intended_file = binding.target_file
                        tail = qualifier_parts[len(binding.expression_prefix):]
                        container_parts = ([binding.imported_symbol]
                                           if binding.imported_symbol else []) + list(tail)
                        target_container = ".".join(container_parts) or None
                        candidates = [s for s in by_name.get(callee, [])
                                      if s.file == binding.target_file
                                      and s.container == target_container]
                        if not candidates:
                            intended_file = None
                elif qualifier.rsplit(".", 1)[-1][:1].isupper():
                    candidates = [s for s in by_name.get(callee, [])
                                  if s.file == rel and s.container == qualifier]
                    exact_identity = True
                    intended_file = rel
        else:
            binding = imported_binding(rel, scope, callee)
            if binding is not None:
                exact_identity = True
                intended_file = binding.target_file
                if not binding.ambiguous and binding.imported_symbol is not None:
                    candidates = [s for s in by_name.get(binding.imported_symbol, [])
                                  if s.file == binding.target_file]
            elif caller:
                caller_identity = (f"{caller.container}.{caller.name}"
                                   if caller.container else caller.name)
                lexical_containers = {caller_identity}
                if caller.container:
                    lexical_containers.add(caller.container)
                candidates = [s for s in by_name.get(callee, [])
                              if s.file == rel and s.container in lexical_containers]
                exact_identity = bool(candidates)
                intended_file = rel if candidates else None
                if not candidates:
                    candidates = [s for s in by_name.get(callee, [])
                                  if s.file == rel and s.container is None
                                  and s.kind in ("function", "class")]
                    if candidates:
                        intended_file = rel
            else:
                candidates = [s for s in by_name.get(callee, [])
                              if s.file == rel and s.container is None
                              and s.kind in ("function", "class")]
                if candidates:
                    intended_file = rel

        if len(candidates) == 1:
            tgt = candidates[0]
            references.append(RawReference(kind="references", from_file=rel, from_line=from_line,
                                           to_file=tgt.file, to_line=tgt.start_line, resolved=True,
                                           name=full if exact_identity else callee,
                                           allow_name_match=not exact_identity))
        else:
            references.append(RawReference(kind="references", from_file=rel,
                                           from_line=from_line, to_file=intended_file,
                                           resolved=False,
                                           name=callee,
                                           allow_name_match=not exact_identity))

    return RawIngest(language="python", root=str(root), symbols=symbols,
                     references=references, diagnostics=diagnostics,
                     files=files, entry_files=entry_files)
