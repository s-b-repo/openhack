"""FIRES / SILENT tests for the Wave-3 vocabulary extensions.

Each block asserts that a newly-added trigger fires on the vulnerable idiom AND
that a nearby common-noise idiom stays silent. These aren't full new attack
classes (those live in test_python_sqli.py and test_c_format_string.py); they
prove the vocabulary additions in the smaller detectors do not silently expand
into false-positive space.
"""
import shutil

import pytest


# ── python_locks: RLock / Semaphore recognized ────────────────────────────────

def test_rlock_participates_in_acquire_order():
    """A codebase mixing Lock and RLock previously dropped the RLock's edges — an
    Lock->RLock->Lock inversion between two functions was silently missed."""
    import ast
    from lattice.ingest.python_locks import _walk

    src = ast.parse(
        "def a():\n"
        "    with threading.Lock() as l1:\n"
        "        with threading.RLock() as l2:\n"
        "            pass\n"
    )
    edges: set = set()
    for node in src.body:
        _walk(node, [], edges)
    assert ("Lock", "RLock") in edges, f"Lock -> RLock edge missing: {edges}"


def test_semaphore_participates_in_acquire_order():
    import ast
    from lattice.ingest.python_locks import _walk

    src = ast.parse(
        "def a():\n"
        "    with threading.Semaphore() as s1:\n"
        "        with threading.Lock() as l2:\n"
        "            pass\n"
    )
    edges: set = set()
    for node in src.body:
        _walk(node, [], edges)
    assert ("Semaphore", "Lock") in edges, f"edge missing: {edges}"


# ── python_resource: extended acquire/release vocab ───────────────────────────

def test_async_client_acquire_recognized(tmp_path):
    from lattice.ingest.python_resource import resource_audit
    src = ("def h():\n"
           "    c = AsyncClient()\n")  # unbalanced acquire
    p = tmp_path / "leak.py"
    p.write_text(src)
    findings = resource_audit(p)
    assert findings, "AsyncClient without a release must leak"


def test_thread_pool_executor_shutdown_balances(tmp_path):
    from lattice.ingest.python_resource import resource_audit
    src = ("def h():\n"
           "    e = ThreadPoolExecutor()\n"
           "    e.shutdown()\n")
    p = tmp_path / "safe.py"
    p.write_text(src)
    findings = resource_audit(p)
    assert findings == [], "shutdown balances the executor acquire"


# ── c_unions: stdint / size_t offset normalization ────────────────────────────

def test_size_t_and_uint64_in_sizeof_table():
    """The offset table must know these widths — otherwise a struct using them has its
    subsequent members mis-aligned and the union collision check silently misses."""
    from lattice.ingest.c_unions import _SIZEOF
    for typ in ("size_t", "uint64_t", "uintptr_t", "int32_t", "intptr_t",
                "ssize_t", "ptrdiff_t"):
        assert typ in _SIZEOF, f"{typ} missing from _SIZEOF"


# ── solidity_taint: extended spot/sanitizer marks ─────────────────────────────

def test_solidity_spot_reads_extended():
    from lattice.ingest.solidity_taint import _SPOT_READS
    for name in ("getPair", "slot0", "observe"):
        assert name in _SPOT_READS, f"{name} missing from _SPOT_READS"


def test_solidity_sanitizer_marks_extended():
    from lattice.ingest.solidity_taint import _SANITIZER_MARKS
    for name in ("getPriceFromSqrtRatio", "computeAmountOut", "oracleObserve"):
        assert name in _SANITIZER_MARKS, f"{name} missing from _SANITIZER_MARKS"


# ── ruby_taint / rust_taint: source vocab extension ───────────────────────────

def test_rust_source_vocab_extended():
    from lattice.ingest.rust_taint import _RUST_SOURCES
    for name in ("Query", "Path", "Form", "Json", "headers"):
        assert name in _RUST_SOURCES, f"{name} missing from _RUST_SOURCES"


def test_ruby_source_vocab_extended():
    from lattice.ingest.ruby_taint import _RUBY_SOURCES
    for name in ("session", "flash", "headers", "parameters"):
        assert name in _RUBY_SOURCES, f"{name} missing from _RUBY_SOURCES"


# ── js_arbitrary_call: worker_threads + Deno gates ────────────────────────────


def _has_node():
    return shutil.which("node") is not None


@pytest.mark.skipif(not _has_node(), reason="node not installed")
def test_worker_threads_worker_tainted_path_FIRES(tmp_path):
    from lattice.ingest.js_arbitrary_call import js_arbitrary_call_audit
    src = ("const {Worker} = require('worker_threads');\n"
           "function handler(req) {\n"
           "  const path = req.body.script;\n"
           "  new Worker(path);\n"
           "}\n")
    p = tmp_path / "wt.js"
    p.write_text(src)
    findings = js_arbitrary_call_audit(p)
    kinds = {f.get("kind") for f in findings}
    assert "arbitrary_call" in kinds, findings


@pytest.mark.skipif(not _has_node(), reason="node not installed")
def test_worker_threads_constant_path_SILENT(tmp_path):
    from lattice.ingest.js_arbitrary_call import js_arbitrary_call_audit
    src = ("const {Worker} = require('worker_threads');\n"
           "function handler() {\n"
           "  new Worker('./worker.js');\n"
           "}\n")
    p = tmp_path / "safe.js"
    p.write_text(src)
    assert js_arbitrary_call_audit(p) == [], "constant path is not attacker-chosen"


@pytest.mark.skipif(not _has_node(), reason="node not installed")
def test_web_worker_unrelated_SILENT(tmp_path):
    """A `new Worker(...)` with NO `worker_threads` import is a browser Web Worker (or
    an unrelated class) — must not false-fire."""
    from lattice.ingest.js_arbitrary_call import js_arbitrary_call_audit
    src = ("function handler(req) {\n"
           "  const path = req.body.script;\n"
           "  new Worker(path);\n"       # no worker_threads import
           "}\n")
    p = tmp_path / "web.js"
    p.write_text(src)
    assert js_arbitrary_call_audit(p) == [], "Worker without worker_threads binding must not fire"


@pytest.mark.skipif(not _has_node(), reason="node not installed")
def test_deno_run_tainted_cmd_FIRES(tmp_path):
    from lattice.ingest.js_arbitrary_call import js_arbitrary_call_audit
    src = ("function handler(req) {\n"
           "  const cmd = req.body.cmd;\n"
           "  Deno.run({cmd: [cmd]});\n"
           "}\n")
    p = tmp_path / "d.js"
    p.write_text(src)
    findings = js_arbitrary_call_audit(p)
    assert findings, "Deno.run with tainted cmd must fire"


@pytest.mark.skipif(not _has_node(), reason="node not installed")
def test_deno_command_tainted_FIRES(tmp_path):
    from lattice.ingest.js_arbitrary_call import js_arbitrary_call_audit
    src = ("function handler(req) {\n"
           "  const cmd = req.body.cmd;\n"
           "  new Deno.Command(cmd);\n"
           "}\n")
    p = tmp_path / "d.js"
    p.write_text(src)
    findings = js_arbitrary_call_audit(p)
    assert findings, "new Deno.Command with tainted arg must fire"


@pytest.mark.skipif(not _has_node(), reason="node not installed")
def test_deno_command_constant_SILENT(tmp_path):
    from lattice.ingest.js_arbitrary_call import js_arbitrary_call_audit
    src = ("function handler() {\n"
           "  new Deno.Command('ls');\n"
           "}\n")
    p = tmp_path / "safe.js"
    p.write_text(src)
    assert js_arbitrary_call_audit(p) == []
