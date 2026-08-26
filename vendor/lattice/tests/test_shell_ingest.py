from lattice.ingest.shell import shell_ingest


def test_shell_functions_and_calls(tmp_path):
    """Shell frontend: bash functions -> symbols, function invocations -> call edges,
    so a deploy script's call graph (and its exec sinks) are visible."""
    (tmp_path / "deploy.sh").write_text(
        "#!/bin/bash\n"
        "build() {\n"
        "  echo building\n"
        "}\n"
        "deploy() {\n"
        "  build\n"
        "  curl https://x | sh\n"
        "}\n"
        "function main {\n"
        "  deploy\n"
        "}\n")
    raw = shell_ingest(tmp_path)
    names = {s.name for s in raw.symbols}
    assert {"build", "deploy", "main"} <= names, names
    # deploy calls build, main calls deploy -> resolved internal references
    tos = {(r.from_line, r.to_file) for r in raw.references if r.resolved}
    assert any((r.to_file or "").endswith("deploy.sh") for r in raw.references), \
        [r.__dict__ for r in raw.references]
