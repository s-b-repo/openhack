import pathlib, pytest
from lattice.ingest.lsp_client import ingest

FIX = pathlib.Path(__file__).parent / "fixtures" / "tsx_sample"


@pytest.mark.integration
def test_tsx_files_are_ingested_and_referenced():
    """A .tsx component that imports+calls a .ts function must register both the
    component's symbol AND its reference to the function. .tsx files are first-class
    in any React/TS codebase; dropping them silently under-reports every analysis."""
    raw = ingest(FIX, "typescript")
    names = {s.name for s in raw.symbols}
    assert "Widget" in names, f"the .tsx symbol was not ingested; got {names}"
    # the call greet('world') inside widget.tsx must surface as a reference to greet
    assert any(
        r.kind == "references" and (r.to_file or "").endswith("lib.ts")
        and (r.from_file or "").endswith("widget.tsx")
        for r in raw.references
    ), f"no reference from widget.tsx -> lib.ts greet; refs={[(r.kind, r.from_file, r.to_file) for r in raw.references]}"
