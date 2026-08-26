"""Contract tests for the shared source/sink/sanitizer registry `vocab.py`.

Two purposes:
  1. Prove the SHAPE of the public API (`sources`/`sinks`/`sanitizers` return
     sets; `catalog` snapshots the full table).
  2. Prove the MIGRATION GUARD holds — every term in a taint detector's local
     set is ALREADY present in vocab.py (as a subset of the union of its
     applicable kinds). This way, a future migration is a mechanical
     replacement of the local set with `vocab.sinks(...)`; if a new detector
     adds a term that's not in vocab, this test fails and points the author at
     the migration hazard.
"""
from lattice.ingest import vocab


# ── shape / API ───────────────────────────────────────────────────────────────

def test_sources_returns_a_set():
    out = vocab.sources("http_request")
    assert isinstance(out, set)
    assert out                             # non-empty for a real kind


def test_unknown_kind_returns_empty_set():
    """Calling with an unknown kind is not an error — returns empty union so
    detectors don't need to guard-check every key."""
    assert vocab.sources("nope") == set()
    assert vocab.sinks("nope") == set()
    assert vocab.sanitizers("nope") == set()


def test_extras_are_unioned():
    base = vocab.sources("http_request")
    ext = vocab.sources("http_request", extra={"custom_source"})
    assert "custom_source" in ext
    assert ext == base | {"custom_source"}


def test_multiple_kinds_are_unioned():
    both = vocab.sources("cli", "env")
    cli = vocab.sources("cli")
    env = vocab.sources("env")
    assert both == cli | env


def test_catalog_is_stable():
    """The catalog snapshot must return SORTED lists so JSON diffs are readable
    (the accuracy baseline diff relies on this)."""
    c = vocab.catalog()
    for kind_group in c.values():
        for name, lst in kind_group.items():
            assert lst == sorted(lst), f"{name} is not sorted: {lst}"


def test_sinks_kinds_are_stable():
    """The set of sink-kind KEYS is a public contract — detectors and the corpus
    baseline reference these strings. If a kind is added, this test fails and
    the plan/baseline must be updated deliberately."""
    assert set(vocab.SINKS.keys()) == {
        "shell", "sql", "code_exec", "deserialize", "ssrf", "xss", "path", "format"
    }


# ── migration guard: every existing local set is a subset of vocab ────────────

def test_python_taint_shell_sinks_subset_of_vocab_shell():
    """python_taint's `_ALWAYS_SHELL` (os.system/os.popen/…) must be entirely covered
    by vocab.sinks("shell"). Migration = drop `_ALWAYS_SHELL` and derive it from
    `vocab.sinks("shell", extra=...)`.
    """
    from lattice.ingest.python_taint import _ALWAYS_SHELL, _SUBPROCESS
    shell = vocab.sinks("shell")
    missing_always = _ALWAYS_SHELL - shell
    missing_sub = _SUBPROCESS - shell
    # We only assert each name IS in vocab; extras that stay in the detector
    # are fine. Missing names must be added to vocab.SINKS["shell"] before migration.
    assert not missing_always, f"vocab.SINKS['shell'] missing: {missing_always}"
    assert not missing_sub, f"vocab.SINKS['shell'] missing: {missing_sub}"


def test_python_taint_shell_sanitizers_subset_of_vocab():
    from lattice.ingest.python_taint import _SHELL_SANITIZERS
    assert _SHELL_SANITIZERS.issubset(vocab.sanitizers("shell"))


def test_python_taint_sql_sinks_subset_of_vocab_sql():
    from lattice.ingest.python_taint import _SQL_SINK_LEAVES
    assert _SQL_SINK_LEAVES.issubset(vocab.sinks("sql"))


def test_c_taint_shell_sinks_subset_of_vocab_shell():
    from lattice.ingest.c_taint import _SHELL_SINKS, _EXEC_SINKS
    shell = vocab.sinks("shell")
    assert _SHELL_SINKS.issubset(shell), f"missing: {_SHELL_SINKS - shell}"
    # exec-family is also shell in our taxonomy
    missing = _EXEC_SINKS - shell
    assert not missing, f"vocab.SINKS['shell'] missing exec family: {missing}"


def test_c_taint_format_sinks_subset_of_vocab_format():
    from lattice.ingest.c_taint import _FMT_SINKS
    fmt = vocab.sinks("format")
    missing = set(_FMT_SINKS.keys()) - fmt
    assert not missing, f"vocab.SINKS['format'] missing: {missing}"


def test_ruby_taint_sanitizers_subset_of_vocab_shell():
    from lattice.ingest.ruby_taint import _RUBY_SANITIZERS
    assert _RUBY_SANITIZERS.issubset(vocab.sanitizers("shell")), \
        f"missing: {_RUBY_SANITIZERS - vocab.sanitizers('shell')}"


def test_js_arbitrary_call_code_exec_subset_of_vocab_code_exec():
    from lattice.ingest.js_arbitrary_call import _CODE_EXEC_CALLEES, _CODE_EXEC_MEMBERS
    code_exec = vocab.sinks("code_exec")
    missing = (_CODE_EXEC_CALLEES | _CODE_EXEC_MEMBERS) - code_exec
    assert not missing, f"vocab.SINKS['code_exec'] missing: {missing}"


def test_no_import_from_detectors():
    """vocab MUST NOT import any detector. If this test fails, someone violated
    the one-way flow rule — vocab is imported BY detectors, never the reverse."""
    import ast
    import pathlib
    src = pathlib.Path(vocab.__file__).read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = ([node.module] if isinstance(node, ast.ImportFrom) and node.module
                     else [a.name for a in node.names])
            for n in names:
                assert not (n or "").startswith("lattice.ingest."), \
                    f"vocab imports detector: {n}"
                assert not (n or "").startswith("lattice.security"), \
                    f"vocab imports lattice.security: {n}"


# ── recipe examples: prove the intended migration idiom works ────────────────

def test_python_taint_migration_recipe():
    """The RECIPE the plan proposes: derive the local set from vocab, keep the
    truly-language-specific term as an extra. This exact call shape must work.
    Migration: replace `_ALWAYS_SHELL = {...}` with the RHS below."""
    always_shell = vocab.sinks("shell", extra={"os.system", "os.popen",
                                               "subprocess.getoutput",
                                               "subprocess.getstatusoutput"})
    assert "os.system" in always_shell
    assert "os.popen" in always_shell


def test_ruby_migration_recipe():
    ruby_sanitizers = vocab.sanitizers("shell", extra={"shellescape", "Shellwords"})
    assert "shellescape" in ruby_sanitizers
    assert "Shellwords" in ruby_sanitizers
    # shlex.quote is Python-only but shares the shell domain
    assert "shlex.quote" in ruby_sanitizers
