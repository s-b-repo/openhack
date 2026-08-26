import pytest
from lattice import sidecar as sc


def _write(proj, name, text):
    (proj / name).write_text(text)


@pytest.mark.integration
def test_developer_mode_catches_a_real_regression(tmp_path):
    """End-to-end prevention: baseline a real project via the LSP pipeline, then DELETE
    an exported function that has a caller. The next sidecar update must surface the
    regression (removed public API + a reference broken by the removal) and flag it —
    'caught at the moment it's created'. This exercises the real ingest→diff path, not
    a hand-built graph."""
    proj = tmp_path / "proj"
    proj.mkdir()
    out = tmp_path / ".footings"
    _write(proj, "util.ts", "export function helper(): number {\n  return 1\n}\n")
    _write(proj, "api.ts",
           "import { helper } from './util'\n"
           "export function handler(): number {\n  return helper()\n}\n")

    base = sc.update(proj, out)                      # baseline (full ingest)
    assert base["updated"] and base["digest"]["public_api"] == 2

    # --- inject a real break: remove the exported helper that api.ts calls ---
    _write(proj, "util.ts", "export function unrelated(): number {\n  return 2\n}\n")
    after = sc.update(proj, out)

    ch = after["changes"]
    assert ch is not None, "second update produced no change report"
    assert ch["verdict"] == "regressed", f"a real break was not flagged: {ch}"
    # completeness: the removed public API and/or the broken reference must surface
    assert ch["removed_public_api"] or ch["broken_by_removal"], \
        f"the break was not surfaced in the change report: {ch}"


@pytest.mark.integration
def test_developer_mode_catches_deleted_internal_function_with_a_caller(tmp_path):
    """The catastrophic case: delete a NON-exported function that a surviving function
    still calls. removed_public_api won't fire (not exported), so prevention depends on
    detecting the orphaned caller. A 'clean' verdict here = a real break the mirror hid."""
    proj = tmp_path / "proj"
    proj.mkdir()
    out = tmp_path / ".footings"
    _write(proj, "app.ts",
           "function helper(): number {\n  return 1\n}\n"
           "export function handler(): number {\n  return helper()\n}\n")
    sc.update(proj, out)
    # delete helper; handler still calls it -> a live call to a now-missing function
    _write(proj, "app.ts", "export function handler(): number {\n  return helper()\n}\n")
    ch = sc.update(proj, out)["changes"]
    assert ch is not None
    assert ch["broken_by_removal"], f"orphaned caller not detected: {ch}"
    assert ch["verdict"] == "regressed", f"a real break was reported clean: {ch}"


@pytest.mark.integration
def test_developer_mode_does_not_cry_wolf_on_a_benign_change(tmp_path):
    """Correctness: adding a comment is not a regression — verdict stays clean."""
    proj = tmp_path / "proj"
    proj.mkdir()
    out = tmp_path / ".footings"
    _write(proj, "util.ts", "export function helper(): number {\n  return 1\n}\n")
    sc.update(proj, out)
    _write(proj, "util.ts", "// a harmless comment\nexport function helper(): number {\n  return 1\n}\n")
    after = sc.update(proj, out)
    if after["changes"] is not None:
        assert after["changes"]["verdict"] == "clean", \
            f"a benign comment edit was flagged as a regression: {after['changes']}"


@pytest.mark.integration
def test_developer_mode_catches_a_new_broken_relative_import(tmp_path):
    """Writing `import { x } from './ghost'` where ghost.ts doesn't exist is a forward-
    reference break — the most common developer mistake. A relative import that can't
    resolve is broken (vs a bare 'lodash' specifier, which is just an external pkg).
    It must surface as unresolved, not be mistaken for an external package."""
    proj = tmp_path / "proj"
    proj.mkdir()
    out = tmp_path / ".footings"
    _write(proj, "app.ts", "export function handler(): number {\n  return 1\n}\n")
    sc.update(proj, out)
    _write(proj, "app.ts",
           "import { x } from './ghost'\n"
           "export function handler(): number {\n  return x\n}\n")
    ch = sc.update(proj, out)["changes"]
    assert ch["new_unresolved_imports"], f"broken relative import not flagged: {ch}"
    assert ch["verdict"] == "regressed", f"broken import reported clean: {ch}"


@pytest.mark.integration
def test_developer_mode_does_not_flag_external_package_imports(tmp_path):
    """Correctness guard: a bare 'lodash'-style specifier is external, NOT a break."""
    proj = tmp_path / "proj"
    proj.mkdir()
    out = tmp_path / ".footings"
    _write(proj, "app.ts", "export function handler(): number {\n  return 1\n}\n")
    sc.update(proj, out)
    _write(proj, "app.ts",
           "import { debounce } from 'lodash'\n"
           "export function handler(): number {\n  return 1\n}\n")
    ch = sc.update(proj, out)["changes"]
    if ch is not None:
        assert not ch["new_unresolved_imports"], f"external pkg wrongly flagged: {ch}"
