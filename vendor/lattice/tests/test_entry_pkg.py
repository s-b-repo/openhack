import json
from lattice.ingest.lsp_client import _entry_files_from_package_json


def test_main_dist_path_maps_to_src(tmp_path):
    """package.json "main": "./dist/index.js" must map to the existing src/index.ts."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text("export const x = 1\n")
    (tmp_path / "package.json").write_text(json.dumps({"main": "./dist/index.js"}))
    assert _entry_files_from_package_json(tmp_path) == {"src/index.ts"}


def test_bin_dict_maps_each_existing_src(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "cli.tsx").write_text("export const c = 1\n")
    (tmp_path / "package.json").write_text(json.dumps({"bin": {"tool": "./dist/cli.js"}}))
    assert _entry_files_from_package_json(tmp_path) == {"src/cli.tsx"}


def test_javascript_main_maps_to_javascript_source(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.js").write_text("exports.x = 1\n")
    (tmp_path / "main.js").write_text("require('./src')\n")
    (tmp_path / "package.json").write_text(json.dumps({
        "main": "main.js",
        "bin": {"app": "./dist/index.js"},
    }))
    assert _entry_files_from_package_json(tmp_path, "javascript") == {
        "main.js",
        "src/index.js",
    }


def test_missing_or_unmappable_yields_nothing(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"main": "./dist/ghost.js"}))
    assert _entry_files_from_package_json(tmp_path) == set()
    (tmp_path / "nopkg").mkdir()
    assert _entry_files_from_package_json(tmp_path / "nopkg") == set()
