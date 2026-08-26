# src/lattice/incremental.py
"""Incremental ingest — re-ingest only the changed neighborhood, provably equal to a
full re-ingest (see test_incremental.py, the no-drift gate).

The insight that makes the splice precise: a `references` edge is created by querying
its TARGET symbol, so it "belongs to" the requery region iff its `to_file` is in it.
An `imports` edge is scanned from its source, so it belongs to the changed set iff its
`from_file` changed. So the splice keeps exactly the edges the change can't have
touched, and replaces the rest with freshly-queried ones.

Requery region (for TS with explicit imports): the changed files plus the files they
import — because a symbol's outbound references only go to files it imports or its own
file. Re-querying that region recreates every edge the change could affect.
"""
from __future__ import annotations
import pathlib
import time
from dataclasses import asdict

from lattice.ingest.types import RawIngest, RawSymbol, RawReference


def raw_to_dict(raw: RawIngest) -> dict:
    """Serialize a RawIngest so the sidecar can persist it for incremental updates."""
    return {
        "language": raw.language,
        "root": raw.root,
        "symbols": [asdict(s) for s in raw.symbols],
        "references": [asdict(r) for r in raw.references],
        "diagnostics": raw.diagnostics,
        "files": raw.files,
        "entry_files": sorted(raw.entry_files),
    }


def raw_from_dict(d: dict) -> RawIngest:
    # Unknown keys are dropped, not fatal — a persisted dict from a newer/older
    # lattice must still load (the sidecar cache outlives code versions).
    sym_fields = RawSymbol.__dataclass_fields__
    ref_fields = RawReference.__dataclass_fields__
    return RawIngest(
        language=d["language"], root=d["root"],
        symbols=[RawSymbol(**{k: v for k, v in s.items() if k in sym_fields})
                 for s in d["symbols"]],
        references=[RawReference(**{k: v for k, v in r.items() if k in ref_fields})
                    for r in d["references"]],
        diagnostics=list(d.get("diagnostics", [])), files=d.get("files", []),
        entry_files=set(d.get("entry_files", [])),
    )


def splice(old_raw: RawIngest, changed_files: set, removed_files: set, requery_files: set,
           fresh_symbols: list, fresh_refs: list, files: list,
           fresh_diagnostics: list | None = None,
           fresh_entry_files: set[str] | None = None) -> RawIngest:
    """Pure merge: old graph data + freshly re-ingested region -> new graph data.
    Provably equal to a full re-ingest of the new state (test_incremental.py)."""
    changed, removed, requery = set(changed_files), set(removed_files), set(requery_files)
    # A changed caller can stop referring to an old target even when its new imports no
    # longer mention that target. Include those old targets in the replacement region so
    # stale A->B facts cannot survive an A import/call change to C.
    requery.update(
        r.to_file for r in old_raw.references
        if r.kind not in {"imports", "dyn_dispatch"}
        and r.from_file in changed and r.to_file and r.to_file not in removed
    )
    drop = changed | removed

    # symbols: changed/removed files' symbols are stale -> replace with fresh
    symbols = [s for s in old_raw.symbols if s.file not in drop]
    symbols += list(fresh_symbols)

    # references: keep only edges the change cannot have touched.
    refs: list = []
    for r in old_raw.references:
        if r.kind == "imports":
            if r.from_file in changed or r.from_file in removed:
                continue                       # changed file's imports -> re-scanned
        elif r.kind == "dyn_dispatch":
            continue                           # all dynamic sites are re-parsed below
        else:
            if r.to_file in requery or r.to_file in removed or r.from_file in removed:
                continue                       # edge into the requery region -> re-queried
        refs.append(r)
    refs += list(fresh_refs)

    def keep_diagnostic(d: dict) -> bool:
        file = d.get("file")
        if file in drop:
            return False                         # changed/removed documents were reparsed
        if file == "<project>":
            return False                         # project lifecycle/source state was rerun
        if d.get("parser") == "babel":
            return False                         # Babel enrichment is rerun project-wide
        if file in requery and d.get("kind") == "reference_error":
            return False                         # only references rerun for unchanged targets
        return True                              # retain schema/parse facts not recomputed

    diagnostics = [d for d in old_raw.diagnostics if keep_diagnostic(d)]
    diagnostics += list(fresh_diagnostics or [])

    # File set = source files + resolved non-source import targets (.json/barrels), so
    # those keep their module vertices — exactly as a full ingest computes it.
    ts_set = set(files)
    extra = {r.to_file for r in refs
             if r.kind == "imports" and r.resolved and r.to_file and r.to_file not in ts_set}
    all_files = sorted(ts_set | extra)

    entry_files = ((set(old_raw.entry_files) - removed)
                   if fresh_entry_files is None else set(fresh_entry_files))

    return RawIngest(language=old_raw.language, root=old_raw.root,
                     symbols=symbols, references=refs, diagnostics=diagnostics,
                     files=all_files, entry_files=entry_files)


# ---- LSP driver: re-ingest only the changed neighborhood, then splice ----

def _project_files(root, language: str = "typescript") -> list[str]:
    """Project source files (relative paths) — the SAME selection as a full ingest
    (lsp_client._select_source_files), so incremental can't drift on .tsx files or
    build-dir exclusions."""
    from lattice.ingest import lsp_client as L
    root = pathlib.Path(root)
    return sorted(p.relative_to(root).as_posix()
                  for p in L._select_source_files(root, language))


def incremental_ingest(old_raw: RawIngest, root, changed: list, removed: list,
                       language: str = "typescript") -> RawIngest:
    """Re-extract symbols for changed files, determine the requery region (changed +
    their imports), re-query references for it, and splice. Falls back to nothing for
    callers to detect (returns None) if the LSP is unavailable."""
    from lattice.ingest import lsp_client as L
    import contextlib
    import shutil
    from multilspy import SyncLanguageServer
    from multilspy.multilspy_config import MultilspyConfig
    from multilspy.multilspy_logger import MultilspyLogger
    import psutil

    root = pathlib.Path(root).resolve()
    changed_set, removed_set = set(changed), set(removed)

    binary = L._LSP_BINARY.get(language)
    if binary and shutil.which(binary) is None:
        return None

    all_files = _project_files(root, language)

    # Entrypoint surfaces are cheap source/package metadata, not LSP results. Recompute
    # them project-wide so a changed shebang can add/remove an entrypoint and an ordinary
    # incremental edit cannot silently drop the package.json-derived entries retained by
    # the previous full ingest.
    fresh_entry_files = L._entry_files_from_package_json(root, language)
    for rel in all_files:
        lines = L._read_lines(root, rel)
        if lines and lines[0].startswith("#!"):
            fresh_entry_files.add(rel)

    cfg = MultilspyConfig.from_dict({"code_language": language})
    lsp = SyncLanguageServer.create(
        cfg, MultilspyLogger(), str(root), timeout=L._LSP_TIMEOUT)
    # Keep the incremental lifecycle identical to full ingest. multilspy launches its
    # bundled server through a shell, so a checkout/venv path containing spaces must be
    # quoted before the first server start (not only after a prior full ingest happened
    # to mutate the shared launch metadata).
    L._quote_lsp_launch_command(lsp)

    fresh_symbols: list = []
    fresh_refs: list = []
    fresh_diagnostics: list[dict] = []
    requery_files = set(changed_set)
    requery_files.update(
        r.to_file for r in old_raw.references
        if r.kind not in {"imports", "dyn_dispatch"}
        and r.from_file in changed_set and r.to_file and r.to_file not in removed_set
    )
    ingest_complete = False

    try:
        with L._started_server(lsp), contextlib.ExitStack() as stack:
            for f in all_files:
                stack.enter_context(lsp.open_file(f))
                if language == "javascript" and L._JS_OPEN_SETTLE:
                    time.sleep(L._JS_OPEN_SETTLE)

            # 1) re-extract symbols + imports for changed files; collect requery targets
            changed_syms: dict = {}     # file -> list of (name,start,end,sel_line0,sel_char0)
            for rel in sorted(changed_set):
                lines = L._read_lines(root, rel)
                raw = lsp.request_document_symbols(rel)
                syms_list = raw[0] if isinstance(raw, tuple) else raw
                flat: list = []
                if isinstance(syms_list, list):
                    L._flatten(syms_list, flat)
                else:
                    fresh_diagnostics.append({
                        "kind": "lsp_schema_error", "language": language, "file": rel,
                        "line": 1, "severity": "error",
                        "message": "document-symbol response was not a list",
                    })
                # Same single source of truth as the full ingest — no drift (this path
                # previously lacked container recovery; the shared helper fixes that).
                file_syms, file_refs = L._symbols_from_flat(flat, rel, lines)
                fresh_symbols.extend(file_syms)
                changed_syms[rel] = [(s, e, sl, sc) for (_r, s, e, sl, sc) in file_refs]

                # imports of the changed file (re-scanned) — mirror ingest's broken-vs-
                # external distinction: a relative import resolving to no file is BROKEN
                # (keep its intended path so it's flagged), a bare specifier is external.
                for i, tgt in L._module_specifiers(lines):
                    resolved_to = L._resolve_import(tgt, rel, root, language)
                    if resolved_to is not None:
                        requery_files.add(resolved_to)
                        to_file, is_res = resolved_to, True
                    elif tgt.startswith("."):
                        to_file = L._intended_rel(tgt, rel, root, language)
                        is_res = False
                    else:
                        to_file, is_res = None, False
                    fresh_refs.append(RawReference(
                        kind="imports", from_file=rel, from_line=i, name=tgt,
                        to_file=to_file, to_line=1, resolved=is_res))

            # Babel-only dynamic dispatch is re-parsed as one project-wide enrichment:
            # a prior bridge failure may have stopped at any file, so refreshing only
            # the changed file could clear the error while retaining an incomplete map.
            L._append_dynamic_dispatch_refs(
                sorted(all_files), root, language, fresh_refs, fresh_diagnostics)

            time.sleep(L._REFERENCE_SETTLE)

            # 2) re-query references for every symbol in the requery region.
            #    Changed files use fresh positions; unchanged requery files use old symbols.
            def query_symbol(rel, start, end, sl, sc):
                locs = L._request_reference_locations(
                    lsp, rel, sl, sc, start, language, fresh_diagnostics)
                sites = [s for s in (L._location_site(loc, root) for loc in locs) if s]
                fresh_refs.extend(L._ref_edges(rel, start, end, sites))

            for rel, kept in changed_syms.items():
                for (start, end, sl, sc) in kept:
                    query_symbol(rel, start, end, sl, sc)
            # unchanged requery files (imports of changed): re-query their old symbols
            for s in old_raw.symbols:
                if (s.file in requery_files and s.file not in changed_set
                        and s.file not in removed_set):
                    if s.kind in L._REFERENCEABLE:
                        # recover the name position (selectionRange) approximately via decl
                        query_symbol(s.file, s.start_line, s.end_line,
                                     s.start_line - 1, _name_col(root, s))
            ingest_complete = True
    except psutil.NoSuchProcess as exc:
        if not ingest_complete:
            fresh_diagnostics.append({
                "kind": "lsp_process_error", "language": language,
                "file": "<project>", "line": 1, "severity": "error",
                "message": f"language server exited before incremental ingest completed: {exc}",
            })
    except TimeoutError as exc:
        raise L.LSPIngestError(
            f"Language server request timed out after {L._LSP_TIMEOUT:g}s during "
            f"incremental {language} ingest at {root}."
        ) from exc

    new_files = [f for f in all_files]
    return splice(old_raw, changed_set, removed_set, requery_files,
                  fresh_symbols, fresh_refs, new_files, fresh_diagnostics,
                  fresh_entry_files)


def _name_col(root, sym) -> int:
    """Best-effort column of a symbol's name on its declaration line."""
    try:
        line = (pathlib.Path(root) / sym.file).read_text(encoding="utf-8",
                                                          errors="ignore").splitlines()[sym.start_line - 1]
        idx = line.find(sym.name)
        return idx if idx >= 0 else 0
    except Exception:
        return 0
