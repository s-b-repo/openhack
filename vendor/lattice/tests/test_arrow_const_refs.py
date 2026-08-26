# tests/test_arrow_const_refs.py
import pytest
from lattice.ingest.lsp_client import _is_function_valued, ingest
from lattice.graph.builder import build
from lattice.graph.query import GraphView


def test_is_function_valued_detects_arrows_and_function_exprs():
    assert _is_function_valued(["export const f = (x) => {", "  body"], 1)
    assert _is_function_valued(["const g = function () {}"], 1)
    assert _is_function_valued(["export const h = async () => {", ""], 1)
    assert _is_function_valued(["const j = x => x + 1"], 1)


def test_is_function_valued_rejects_plain_values():
    assert not _is_function_valued(["const n = 42"], 1)
    assert not _is_function_valued(["const obj = { a: 1, b: 2 }"], 1)
    assert not _is_function_valued(['const s = "hello"'], 1)


@pytest.mark.integration
def test_arrow_const_function_gets_reference_edges(tmp_path):
    (tmp_path / "db.ts").write_text(
        "export const runQuery = (sql: string): void => {\n  doIt(sql);\n};\n")
    (tmp_path / "api.ts").write_text(
        'import { runQuery } from "./db";\n'
        "export function handler(): void {\n  runQuery(\"SELECT 1\");\n}\n")
    net = build(ingest(tmp_path, "typescript"))
    g = GraphView(net)
    rq = [v for v in net.vertices if v.name == "runQuery"][0]
    assert g.fan_in(rq.id, kinds="references") >= 1     # handler -> runQuery edge now exists
