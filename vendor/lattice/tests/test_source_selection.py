import pathlib
from lattice.ingest.lsp_client import _select_source_files


def test_excludes_build_output_and_generated_dts(tmp_path):
    """Build output (dist/build/out) and generated .d.ts (a .ts sibling exists) are NOT
    source — ingesting them inflates dead-code and triplicates findings."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "real.ts").write_text("export const x = 1\n")
    (tmp_path / "src" / "real.d.ts").write_text("export declare const x: number\n")  # generated
    (tmp_path / "src" / "types.d.ts").write_text("export interface T { a: number }\n")  # standalone
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "real.js").write_text("exports.x = 1\n")
    (tmp_path / "dist" / "real.d.ts").write_text("export declare const x: number\n")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "i.ts").write_text("export const y = 2\n")

    picked = {p.relative_to(tmp_path).as_posix() for p in _select_source_files(tmp_path)}
    assert "src/real.ts" in picked
    assert "src/types.d.ts" in picked            # standalone .d.ts (no sibling .ts) -> kept
    assert "src/real.d.ts" not in picked         # generated declaration of real.ts -> dropped
    assert not any(p.startswith("dist/") for p in picked)        # build output -> dropped
    assert not any("node_modules" in p for p in picked)          # deps -> dropped


def test_selects_javascript_sources_when_language_is_javascript(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.js").write_text("function run() {}\n")
    (tmp_path / "src" / "view.jsx").write_text("export function View() { return null }\n")
    (tmp_path / "src" / "module.mjs").write_text("export const f = () => 1\n")
    (tmp_path / "src" / "legacy.cjs").write_text("module.exports = function f() {}\n")
    (tmp_path / "src" / "ignored.ts").write_text("export const ts = 1\n")
    (tmp_path / "src" / "renderer.bundle.js").write_text("function generated() {}\n")
    (tmp_path / "src" / "vendor.min.js").write_text("function minified() {}\n")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("function built() {}\n")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1\n")

    picked = {
        p.relative_to(tmp_path).as_posix()
        for p in _select_source_files(tmp_path, "javascript")
    }
    assert picked == {
        "src/main.js",
        "src/view.jsx",
        "src/module.mjs",
        "src/legacy.cjs",
    }
