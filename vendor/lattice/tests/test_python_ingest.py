from lattice.ingest.python_ast import python_ingest


def test_python_ingest_defs_inside_module_level_compound_statements(tmp_path):
    """Functions defined inside module-level compound statements -- `if __name__ ==
    "__main__":`, `try:/except:`, `with:` -- are real symbols. If the walker skips
    them, dead-code/hunt/secaudit silently miss the entrypoint side of a project."""
    (tmp_path / "cli.py").write_text(
        "import os\n"
        "def cleanup():\n"
        "    return 0\n"
        "try:\n"
        "    def fast_path():\n"
        "        return 1\n"
        "except ImportError:\n"
        "    def fallback_path():\n"
        "        return 2\n"
        "with open(os.devnull) as fh:\n"
        "    def scoped():\n"
        "        return fh\n"
        "if __name__ == \"__main__\":\n"
        "    def main():\n"
        "        return cleanup()\n"
        "    main()\n")
    raw = python_ingest(tmp_path)
    by_name = {s.name: s for s in raw.symbols}
    assert {"main", "fast_path", "fallback_path", "scoped"} <= set(by_name), set(by_name)
    # module level, not inside any class: plain functions
    assert by_name["main"].kind == "function" and by_name["main"].container is None


def test_python_ingest_module_level_calls_are_attributed(tmp_path):
    """A call at module level (the `main()` under the `__main__` guard, a top-level
    `X = compute()`) is a real import-time use. The builder attributes call sites
    outside any def to the module vertex -- but only if the walker EMITS them."""
    (tmp_path / "cli.py").write_text(
        "def _helper():\n"
        "    return 1\n"
        "if __name__ == \"__main__\":\n"
        "    _helper()\n")
    raw = python_ingest(tmp_path)
    assert any(r.resolved and r.to_line == 1 for r in raw.references), \
        [r.__dict__ for r in raw.references]


def test_python_ingest_main_guard_and_shebang_mark_entry_files(tmp_path):
    """`if __name__ == "__main__":` and a shebang are Python's executed-directly
    markers -- the analogue of package.json bin/main for TS. They must populate
    RawIngest.entry_files so the builder roots reachability at program entry."""
    (tmp_path / "cli.py").write_text(
        "def main():\n"
        "    return 0\n"
        "if __name__ == \"__main__\":\n"
        "    main()\n")
    (tmp_path / "script.py").write_text(
        "#!/usr/bin/env python3\n"
        "print(1)\n")
    (tmp_path / "lib.py").write_text(
        "def util():\n"
        "    return 1\n")
    raw = python_ingest(tmp_path)
    assert raw.entry_files == {"cli.py", "script.py"}, raw.entry_files


def test_python_dead_code_spares_functions_invoked_from_main_guard(tmp_path):
    """End-to-end symptom guard: a private function called only from the `__main__`
    guard is live at program entry -- dead-code must not flag it."""
    from lattice.graph.builder import build
    from lattice.graph.query import GraphView

    (tmp_path / "cli.py").write_text(
        "def _helper():\n"
        "    return 1\n"
        "if __name__ == \"__main__\":\n"
        "    _helper()\n")
    view = GraphView(build(python_ingest(tmp_path)))
    assert view.dead_code() == [], view.dead_code()


def test_python_ingest_nested_def_is_not_a_method(tmp_path):
    """Characterization guard: a def nested inside a method body belongs to the
    function, not the enclosing class -- the fix must preserve this rule."""
    (tmp_path / "svc.py").write_text(
        "class Svc:\n"
        "    def handle(self):\n"
        "        def helper():\n"
        "            return 1\n"
        "        return helper()\n")
    raw = python_ingest(tmp_path)
    by_name = {s.name: s for s in raw.symbols}
    assert by_name["handle"].kind == "method" and by_name["handle"].container == "Svc"
    assert by_name["helper"].kind == "function"
    assert by_name["helper"].container == "Svc.handle"
    assert not by_name["helper"].exported


def test_python_ingest_functions_classes_inheritance_and_calls(tmp_path):
    """A Python frontend via stdlib `ast`: defs -> functions, classes (with bases ->
    inheritance), methods, and call edges by name. Public (no leading _) = inbound."""
    (tmp_path / "app.py").write_text(
        "import os\n"
        "class Base:\n"
        "    def tag(self):\n"
        "        return 1\n"
        "class Handler(Base):\n"
        "    def handle(self, cmd):\n"
        "        return run(cmd)\n"
        "def run(cmd):\n"
        "    return os.system(cmd)\n"
        "def _private():\n"
        "    return 0\n")
    raw = python_ingest(tmp_path)
    names = {s.name for s in raw.symbols}
    assert {"Base", "Handler", "handle", "run"} <= names, names
    handler = next(s for s in raw.symbols if s.name == "Handler")
    assert "Base" in handler.extends                      # class inheritance
    assert next(s for s in raw.symbols if s.name == "run").exported           # public
    assert not next(s for s in raw.symbols if s.name == "_private").exported  # _ = internal
    # handle() calls run() -> a resolved internal reference
    assert any(r.kind == "references" and (r.to_file or "").endswith("app.py")
               for r in raw.references), [r.__dict__ for r in raw.references]


def test_python_ingest_emits_callee_name(tmp_path):
    # The callee name on each call ref feeds the builder's shared name-resolution pass.
    (tmp_path / "m.py").write_text(
        "class A:\n"
        "    def process(self):\n"
        "        return 1\n"
        "class B:\n"
        "    def process(self):\n"
        "        return 2\n"
        "def run(x):\n"
        "    return x.process()\n")
    raw = python_ingest(tmp_path)
    assert "process" in {r.name for r in raw.references if r.name}


def test_python_ambiguous_method_recovers_sibling_dispatch(tmp_path):
    # An unknown receiver may be either implementation. Preserve that uncertainty as
    # low-confidence dispatch; never promote the first definition to a fact-grade edge.
    from lattice.graph.builder import build
    (tmp_path / "m.py").write_text(
        "class A:\n"
        "    def process(self):\n"
        "        return 1\n"
        "class B:\n"
        "    def process(self):\n"
        "        return 2\n"
        "def run(x):\n"
        "    return x.process()\n")
    net = build(python_ingest(tmp_path))
    disp = {e.members[-1] for e in net.hyperedges
            if e.kind == "dispatch" and e.provenance == "name-match"}
    assert disp == {"py-sym:m.py#A.process", "py-sym:m.py#B.process"}
    assert all(e.confidence < 1.0 for e in net.hyperedges
               if e.kind == "dispatch" and e.provenance == "name-match")
    assert not any(e.kind == "references" and e.confidence == 1.0
                   and e.members[-1] in disp for e in net.hyperedges)


def _assert_exact_util_submodule_call(tmp_path, source):
    from lattice.complete.gate import check
    from lattice.graph.builder import build

    package = tmp_path / "pkg"
    package.mkdir()
    package.joinpath("__init__.py").write_text("")
    package.joinpath("util.py").write_text("def run():\n    return 'pkg'\n")
    (tmp_path / "other.py").write_text("def run():\n    return 'other'\n")
    (tmp_path / "app.py").write_text(source)

    raw = python_ingest(tmp_path)
    imports = [ref for ref in raw.references
               if ref.kind == "imports" and ref.from_file == "app.py"]
    calls = [ref for ref in raw.references
             if ref.kind == "references" and ref.from_file == "app.py"]
    assert any(ref.resolved and ref.to_file == "pkg/util.py" for ref in imports), imports
    assert len(calls) == 1 and calls[0].resolved
    assert (calls[0].to_file, calls[0].to_line) == ("pkg/util.py", 1)

    net = build(raw)
    invoke = "py-sym:app.py#invoke"
    util_run = "py-sym:pkg/util.py#run"
    other_run = "py-sym:other.py#run"
    outgoing = [edge for edge in net.hyperedges if edge.members[0] == invoke]
    assert any(edge.resolved and edge.members[-1] == util_run for edge in outgoing), outgoing
    assert not any(edge.members[-1] == other_run for edge in outgoing)
    assert check(net).verdict == "pass"


def test_python_from_package_import_resolves_real_submodule_identity(tmp_path):
    _assert_exact_util_submodule_call(
        tmp_path,
        "from pkg import util\n\ndef invoke():\n    return util.run()\n",
    )


def test_python_dotted_import_without_as_binds_full_module_path(tmp_path):
    _assert_exact_util_submodule_call(
        tmp_path,
        "import pkg.util\n\ndef invoke():\n    return pkg.util.run()\n",
    )


def test_python_function_local_import_binding_is_scoped_to_that_function(tmp_path):
    from lattice.complete.gate import check
    from lattice.graph.builder import build

    (tmp_path / "util.py").write_text("def run():\n    return 'util'\n")
    (tmp_path / "other.py").write_text("def run():\n    return 'other'\n")
    (tmp_path / "app.py").write_text(
        "def invoke():\n"
        "    import util\n"
        "    return util.run()\n\n"
        "def untouched():\n"
        "    return util.run()\n")

    raw = python_ingest(tmp_path)
    invoke_call = next(ref for ref in raw.references
                       if ref.kind == "references" and ref.from_file == "app.py"
                       and ref.from_line == 1)
    untouched_call = next(ref for ref in raw.references
                          if ref.kind == "references" and ref.from_file == "app.py"
                          and ref.from_line == 5)
    assert invoke_call.resolved and invoke_call.to_file == "util.py"
    assert not untouched_call.resolved and untouched_call.to_file is None

    net = build(raw)
    invoke = "py-sym:app.py#invoke"
    untouched = "py-sym:app.py#untouched"
    util_run = "py-sym:util.py#run"
    other_run = "py-sym:other.py#run"
    assert any(edge.members == [invoke, util_run] and edge.resolved
               for edge in net.hyperedges)
    assert not any(edge.members[0] == untouched
                   and edge.members[-1] in {util_run, other_run}
                   for edge in net.hyperedges)
    assert check(net).verdict == "pass"


def test_python_from_import_does_not_choose_submodule_when_init_exports_name(tmp_path):
    from lattice.complete.gate import check
    from lattice.graph.builder import build

    package = tmp_path / "pkg"
    package.mkdir()
    package.joinpath("__init__.py").write_text(
        "class util:\n"
        "    @staticmethod\n"
        "    def run():\n"
        "        return 'attribute'\n")
    package.joinpath("util.py").write_text("def run():\n    return 'module'\n")
    (tmp_path / "app.py").write_text(
        "from pkg import util\n\ndef invoke():\n    return util.run()\n")

    raw = python_ingest(tmp_path)
    imported = next(ref for ref in raw.references if ref.kind == "imports")
    call = next(ref for ref in raw.references if ref.kind == "references"
                and ref.from_file == "app.py")
    assert imported.resolved and imported.to_file == "pkg/__init__.py"
    assert not call.resolved and call.to_file == "pkg/__init__.py"

    net = build(raw)
    outgoing = [edge for edge in net.hyperedges
                if edge.members[0] == "py-sym:app.py#invoke"]
    assert outgoing and all(not edge.resolved for edge in outgoing)
    assert not any(edge.members[-1] in {
        "py-sym:pkg/__init__.py#util.run", "py-sym:pkg/util.py#run",
    } for edge in outgoing)
    assert "dangling_edges" in check(net).failing_checks
