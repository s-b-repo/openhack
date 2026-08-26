# tests/test_changeset.py
from lattice.changeset import file_manifest, changed_files


def test_manifest_hashes_source_files(tmp_path):
    (tmp_path / "a.ts").write_text("export const x = 1;\n")
    (tmp_path / "b.ts").write_text("export const y = 2;\n")
    (tmp_path / "skip.md").write_text("docs")
    m = file_manifest(tmp_path)
    assert set(m) == {"a.ts", "b.ts"}            # only source files
    assert all(isinstance(h, str) and h for h in m.values())


def test_changed_files_detects_edits_adds_removes(tmp_path):
    (tmp_path / "a.ts").write_text("const x = 1;\n")
    (tmp_path / "b.ts").write_text("const y = 2;\n")
    old = file_manifest(tmp_path)

    (tmp_path / "a.ts").write_text("const x = 99;\n")    # edit
    (tmp_path / "c.ts").write_text("const z = 3;\n")     # add
    (tmp_path / "b.ts").unlink()                          # remove
    new = file_manifest(tmp_path)

    ch = changed_files(old, new)
    assert "a.ts" in ch["modified"]
    assert "c.ts" in ch["added"]
    assert "b.ts" in ch["removed"]
    assert ch["any"] is True


def test_no_changes_is_a_noop(tmp_path):
    (tmp_path / "a.ts").write_text("const x = 1;\n")
    m = file_manifest(tmp_path)
    ch = changed_files(m, file_manifest(tmp_path))
    assert ch["any"] is False
    assert ch["modified"] == [] and ch["added"] == [] and ch["removed"] == []


def test_manifest_includes_native_sources_and_graph_metadata(tmp_path):
    (tmp_path / "main.go").write_text("package main\n")
    (tmp_path / "package.json").write_text('{"main":"dist/index.js"}\n')
    (tmp_path / "tsconfig.build.json").write_text('{"compilerOptions":{}}\n')
    assert {"main.go", "package.json", "tsconfig.build.json"} <= set(file_manifest(tmp_path))


def test_manifest_includes_source_in_frontend_specific_vendor_directory(tmp_path):
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "schema.sql").write_text("CREATE TABLE old_name (id INT);\n")

    assert "vendor/schema.sql" in file_manifest(tmp_path)
