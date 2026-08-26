import pathlib, pytest
from lattice.ingest.lsp_client import ingest, _resolve_import

FIX = pathlib.Path(__file__).parent / "fixtures" / "ts_sample"

@pytest.mark.integration
def test_ingest_ts_fixture():
    raw = ingest(FIX, "typescript")
    names = {s.name for s in raw.symbols}
    assert {"foo", "bar", "stubbed"} <= names
    assert any(r.kind == "imports" and r.from_file.endswith("a.ts") for r in raw.references)
    assert next(s for s in raw.symbols if s.name == "stubbed").is_stub is True


@pytest.mark.integration
def test_ingest_resolves_b_import():
    """The './b' import in a.ts must resolve to b.ts (resolved=True, to_file ends with b.ts)."""
    raw = ingest(FIX, "typescript")
    assert any(
        r.kind == "imports" and r.resolved and (r.to_file or "").endswith("b.ts")
        for r in raw.references
    ), f"no resolved import to b.ts found; refs={[(r.kind,r.to_file,r.resolved) for r in raw.references]}"


@pytest.mark.integration
def test_repeated_ingest_restarts_typescript_server_cleanly():
    for _ in range(2):
        raw = ingest(FIX, "typescript")
        assert {"foo", "bar", "stubbed"} <= {symbol.name for symbol in raw.symbols}


@pytest.mark.integration
def test_repeated_ingest_restarts_javascript_server_cleanly(tmp_path):
    (tmp_path / "main.js").write_text(
        "export function run() { return 1; }\nrun();\n"
    )

    for _ in range(2):
        raw = ingest(tmp_path, "javascript")
        assert "run" in {symbol.name for symbol in raw.symbols}


def test_resolve_import_dotdot_normalized(tmp_path):
    """'../foo' imports resolve to a normalized path — when the file exists."""
    (tmp_path / "adapters").mkdir()
    (tmp_path / "ingestion.ts").write_text("export const x = 1;\n")
    result = _resolve_import("../ingestion", "adapters/x.ts", tmp_path)
    assert result == "ingestion.ts", f"got {result!r}"


def test_resolve_import_subdir(tmp_path):
    """A subdir path normalizes correctly — when the file exists."""
    (tmp_path / "utils").mkdir()
    (tmp_path / "utils" / "helper.ts").write_text("export const h = 1;\n")
    result = _resolve_import("./utils/helper", "a.ts", tmp_path)
    assert result == "utils/helper.ts", f"got {result!r}"


def test_resolve_import_external_returns_none():
    """Non-relative imports should return None."""
    root = pathlib.Path("/project")
    assert _resolve_import("lodash", "a.ts", root) is None
    assert _resolve_import("@scope/pkg", "a.ts", root) is None


def test_resolve_import_outside_root_returns_none():
    """An import that escapes the project root should return None."""
    root = pathlib.Path("/project/src")
    # '../../outside' from 'a.ts' escapes /project/src
    result = _resolve_import("../../outside", "a.ts", root)
    assert result is None, f"expected None, got {result!r}"
