from lattice.ingest.types import RawIngest, RawSymbol, RawReference
from lattice.graph.builder import build


def test_shebang_entry_file_becomes_an_entrypoint_surface():
    """A file flagged as a program entry (e.g. a #!/usr/bin/env shebang script) must
    become an `entrypoint` surface on its module vertex, so reachability is rooted at
    the real program start — not only at exported public_api functions."""
    raw = RawIngest(language="typescript", root="/x",
                    symbols=[RawSymbol(name="run", kind="function", file="cli.ts",
                                       start_line=2, end_line=4)],
                    references=[], files=["cli.ts"], entry_files={"cli.ts"})
    net = build(raw)
    eps = [s for s in net.surfaces if s.kind == "entrypoint"]
    assert eps, "no entrypoint surface created for the shebang entry file"
    ep_v = next(v for v in net.vertices if v.id == eps[0].vertex_id)
    assert ep_v.file == "cli.ts" and ep_v.kind == "module"


def test_non_entry_files_do_not_get_entrypoint_surfaces():
    """Only flagged entries are roots — a normal module is not an entrypoint."""
    raw = RawIngest(language="typescript", root="/x",
                    symbols=[RawSymbol(name="helper", kind="function", file="util.ts",
                                       start_line=1, end_line=2)],
                    references=[], files=["util.ts"], entry_files=set())
    net = build(raw)
    assert not [s for s in net.surfaces if s.kind == "entrypoint"]


def test_entry_surface_connects_only_the_top_level_main():
    raw = RawIngest(
        language="rust", root="/x", files=["main.rs"], entry_files={"main.rs"},
        symbols=[
            RawSymbol(name="main", kind="function", file="main.rs",
                      start_line=1, end_line=3),
            RawSymbol(name="main", kind="function", file="main.rs",
                      start_line=6, end_line=8, container="nested"),
        ],
    )
    net = build(raw)
    entry_module = next(s.vertex_id for s in net.surfaces if s.kind == "entrypoint")
    main_targets = {e.members[-1] for e in net.hyperedges
                    if e.provenance == "entrypoint" and e.members[0] == entry_module}

    assert main_targets == {"rs-sym:main.rs#main"}
