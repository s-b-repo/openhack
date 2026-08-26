# tests/test_import_resolver.py
import asyncio
import contextlib
import shutil
import threading
import time

import pytest

from lattice.bridge_runtime import BridgeRuntimeError
from lattice.ingest.lsp_client import (
    _append_dynamic_dispatch_refs,
    _module_specifiers,
    _request_reference_locations,
    _resolve_import,
    _started_server,
)


def _setup(tmp_path):
    (tmp_path / "a.ts").write_text("export const a = 1;\n")
    (tmp_path / "data.json").write_text("{}\n")
    (tmp_path / "comp.tsx").write_text("export const C = 1;\n")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "index.ts").write_text("export const x = 1;\n")
    (tmp_path / "legacy.ts").write_text("export const y = 1;\n")
    return "main.ts"


def test_resolves_bare_extensionless_to_ts(tmp_path):
    f = _setup(tmp_path)
    assert _resolve_import("./a", f, tmp_path) == "a.ts"


def test_resolves_explicit_json(tmp_path):
    f = _setup(tmp_path)
    assert _resolve_import("./data.json", f, tmp_path) == "data.json"


def test_resolves_tsx(tmp_path):
    f = _setup(tmp_path)
    assert _resolve_import("./comp", f, tmp_path) == "comp.tsx"


def test_resolves_index_barrel(tmp_path):
    f = _setup(tmp_path)
    assert _resolve_import("./lib", f, tmp_path) == "lib/index.ts"


def test_resolves_js_specifier_to_ts(tmp_path):
    f = _setup(tmp_path)                       # TS: import './legacy.js' resolves to legacy.ts
    assert _resolve_import("./legacy.js", f, tmp_path) == "legacy.ts"


def test_genuinely_missing_is_none(tmp_path):
    f = _setup(tmp_path)
    assert _resolve_import("./nope", f, tmp_path) is None      # no such file -> truly broken


def test_external_package_is_none(tmp_path):
    f = _setup(tmp_path)
    assert _resolve_import("react", f, tmp_path) is None       # bare specifier -> external
    assert _resolve_import("@scope/pkg", f, tmp_path) is None


def test_extensionless_resolution_follows_importing_language(tmp_path):
    (tmp_path / "dep.ts").write_text("export const flavor = 'ts'\n")
    (tmp_path / "dep.js").write_text("exports.flavor = 'js'\n")
    assert _resolve_import("./dep", "main.js", tmp_path) == "dep.js"
    assert _resolve_import("./dep", "main.ts", tmp_path) == "dep.ts"


def test_module_scanner_handles_multiline_side_effect_commonjs_and_reexports():
    lines = [
        "import {",
        "  alpha,",
        "} from './esm';",
        "import './side-effect';",
        "const common = require('./common');",
        "const dynamic = require(name);",
        "// require('./comment-only');",
        "const text = \"require('./inside-string')\";",
        "export { beta } from './reexport';",
        "const lazy = import('./lazy', { with: { type: 'json' } });",
        "const pattern = /require('not-a-module')/;",
    ]
    assert _module_specifiers(lines) == [
        (1, "./esm"),
        (4, "./side-effect"),
        (5, "./common"),
        (9, "./reexport"),
        (10, "./lazy"),
    ]


def test_module_scanner_does_not_treat_member_import_as_module_syntax():
    assert _module_specifiers(["obj.import('./ghost')", "obj.require('./also-ghost')"]) == []


def test_language_server_startup_has_a_finite_actionable_timeout():
    cleanup_finished = threading.Event()
    handler_stopped = threading.Event()

    class Handler:
        process = None

        async def stop(self):
            handler_stopped.set()

    class SlowLanguageServer:
        server = Handler()

        @contextlib.asynccontextmanager
        async def start_server(self):
            try:
                await asyncio.Event().wait()
                yield self
            finally:
                cleanup_finished.set()

    class FakeSyncServer:
        language_server = SlowLanguageServer()
        loop = None
        loop_thread = None

    started = time.monotonic()
    fake = FakeSyncServer()
    with pytest.raises(RuntimeError, match="startup timed out after"):
        with _started_server(fake, timeout=0.02):
            pass
    assert time.monotonic() - started < 1.0
    assert cleanup_finished.wait(0.2)
    assert handler_stopped.wait(0.2)
    assert fake.loop_thread is not None and not fake.loop_thread.is_alive()
    assert fake.loop is not None and fake.loop.is_closed()


def test_empty_lsp_project_is_gate_visible_without_starting_a_server(tmp_path):
    from lattice.cache import GraphIngestError, load_network
    from lattice.ingest.lsp_client import ingest

    raw = ingest(tmp_path, "typescript")
    assert raw.files == []
    assert raw.diagnostics[0]["kind"] == "no_source_files"
    with pytest.raises(GraphIngestError, match="no typescript source files"):
        load_network(tmp_path, "typescript")


def test_dynamic_dispatch_bridge_failure_is_gate_visible(monkeypatch, tmp_path):
    from lattice.ingest import js_arbitrary_call

    monkeypatch.setattr(
        js_arbitrary_call, "dynamic_dispatch_refs",
        lambda *_: (_ for _ in ()).throw(BridgeRuntimeError("node unavailable")),
    )
    references, diagnostics = [], []
    _append_dynamic_dispatch_refs(
        ["app.js"], tmp_path, "javascript", references, diagnostics)
    assert references == []
    assert diagnostics == [{
        "kind": "bridge_error", "language": "javascript", "file": "<project>",
        "line": 1, "severity": "error", "message": "node unavailable",
    }]


@pytest.mark.skipif(shutil.which("node") is None, reason="node unavailable")
def test_babel_recovery_errors_are_gate_visible_but_partial_ast_is_retained(tmp_path):
    from lattice.complete.gate import check
    from lattice.graph.builder import build
    from lattice.ingest.types import RawIngest

    (tmp_path / "broken.js").write_text(
        "let duplicate; let duplicate;\nconst picked = handlers[key];\n")
    references, diagnostics = [], []
    _append_dynamic_dispatch_refs(
        ["broken.js"], tmp_path, "javascript", references, diagnostics)

    assert any(d["kind"] == "parse_error" and d["file"] == "broken.js"
               and "duplicate" in d["message"].lower() for d in diagnostics), diagnostics
    assert any(r.kind == "dyn_dispatch" and r.name == "handlers" for r in references)
    raw = RawIngest(language="javascript", root=str(tmp_path), files=["broken.js"],
                    references=references, diagnostics=diagnostics)
    assert check(build(raw)).verdict == "fail"


@pytest.mark.skipif(shutil.which("node") is None, reason="node unavailable")
def test_babel_tolerant_modern_syntax_remains_usable(tmp_path):
    (tmp_path / "valid.js").write_text("const picked = handlers?.[key];\n")
    references, diagnostics = [], []
    _append_dynamic_dispatch_refs(
        ["valid.js"], tmp_path, "javascript", references, diagnostics)
    assert diagnostics == []
    assert any(r.kind == "dyn_dispatch" and r.name == "handlers" for r in references)


def test_reference_request_failure_is_recorded_but_timeout_propagates():
    class BrokenReferences:
        def request_references(self, *_):
            raise ValueError("bad response")

    diagnostics = []
    assert _request_reference_locations(
        BrokenReferences(), "a.ts", 0, 0, 1, "typescript", diagnostics) == []
    assert diagnostics and diagnostics[0]["kind"] == "reference_error"

    class TimedOutReferences:
        def request_references(self, *_):
            raise TimeoutError("slow")

    with pytest.raises(TimeoutError, match="slow"):
        _request_reference_locations(
            TimedOutReferences(), "a.ts", 0, 0, 1, "typescript", [])


def test_lsp_direct_source_file_fails_explicitly_instead_of_returning_empty(
        tmp_path, capsys):
    from lattice.cache import build_auto, detect_languages
    from lattice.cli import main as cli
    from lattice.ingest.lsp_client import ingest

    source = tmp_path / "main.ts"
    source.write_text("export const main = 1\n")
    assert detect_languages(source) == ["typescript"]
    with pytest.raises(RuntimeError, match="requires a project directory"):
        ingest(source, "typescript")
    with pytest.raises(RuntimeError, match="requires a project directory"):
        build_auto(source)
    assert cli.main(["hunt", str(source), "--lang", "ts"]) == 2
    assert "requires a project directory" in capsys.readouterr().err
