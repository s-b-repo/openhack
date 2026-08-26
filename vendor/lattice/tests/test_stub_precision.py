# tests/test_stub_precision.py
from lattice.ingest.lsp_client import _is_stub


def test_genuine_stubs_detected():
    # explicitly marked unfinished, or a single throw/placeholder body
    assert _is_stub(["function f() {", "  throw new Error('not implemented');", "}"], 1, 3)
    assert _is_stub(["function f() {", "  // TODO: implement", "}"], 1, 3)
    assert _is_stub(["function f() {", "  /* not implemented */", "}"], 1, 3)


def test_silently_empty_function_is_not_a_stub():
    # `noop` and friends are intentionally empty — emptiness is not "unimplemented"
    assert not _is_stub(["function noop() {}"], 1, 1)
    assert not _is_stub(["function onEvent() {", "}"], 1, 2)


def test_real_functions_that_throw_are_not_stubs():
    # the false-positive class that produced 1518 findings on a 22-file repo
    assert not _is_stub(
        ["function parseArgs(a) {", "  if (!a) throw new Error('bad input');",
         "  return parse(a);", "}"], 1, 4)


def test_real_function_with_todo_comment_is_not_a_stub():
    assert not _is_stub(
        ["function main() {", "  run(); // TODO: optimize later", "}"], 1, 3)


def test_multi_statement_body_is_not_a_stub():
    assert not _is_stub(
        ["function go() {", "  const x = 1;", "  return x + 1;", "}"], 1, 4)
