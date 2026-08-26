# tests/test_logic.py
from lattice.logic.engine import atoms, evaluate, truth_table, analyze
from lattice.logic.parse import parse
from lattice.logic.audit import audit_condition

# expr tree: ("atom", s) | ("not", e) | ("and", e1, e2) | ("or", e1, e2)
A = ("atom", "a")
B = ("atom", "b")


# --- engine (exact) ---

def test_atoms_collected():
    assert atoms(("and", A, ("not", B))) == {"a", "b"}


def test_evaluate():
    assert evaluate(("and", A, B), {"a": True, "b": False}) is False
    assert evaluate(("or", A, ("not", B)), {"a": False, "b": False}) is True


def test_truth_table_shape():
    tt = truth_table(("and", A, B))
    assert len(tt) == 4
    trues = [row for row in tt if row[1]]
    assert len(trues) == 1 and trues[0][0] == {"a": True, "b": True}


def test_analyze_contradiction():
    a = analyze(("and", A, ("not", A)))
    assert a["contradiction"] is True and a["satisfiable"] is False


def test_analyze_tautology():
    a = analyze(("or", A, ("not", A)))
    assert a["tautology"] is True


def test_analyze_plain_satisfiable():
    a = analyze(("and", A, B))
    assert a["satisfiable"] is True and not a["contradiction"] and not a["tautology"]


# --- parser (tier-1 propositional) ---

def test_parse_and():
    assert parse("a && b") == ("and", ("atom", "a"), ("atom", "b"))


def test_parse_not_and_or():
    assert parse("a || !b") == ("or", ("atom", "a"), ("not", ("atom", "b")))


def test_parse_does_not_treat_neq_as_not():
    # '!=' is a comparison, not boolean NOT -> the whole thing is one atom
    assert parse("x != y") == ("atom", "x != y")


def test_parse_grouping_and_funcalls():
    # outer grouping stripped; function-call parens stay inside the atom
    assert parse("(isReady(u) && a)") == ("and", ("atom", "isReady(u)"), ("atom", "a"))


# --- audit ---

def test_audit_flags_contradiction():
    f = audit_condition("a && !a", file="x.ts", line=3)
    assert f and f["kind"] == "contradiction" and f["line"] == 3


def test_audit_flags_tautology():
    f = audit_condition("a || !a")
    assert f and f["kind"] == "tautology"


def test_audit_clean_condition_is_none():
    assert audit_condition("a && b") is None


def test_audit_relational_is_tier1_silent():
    # x>5 && x<3 is a real contradiction, but tier-1 treats the comparisons as
    # independent atoms -> reported satisfiable -> no false-positive, no detection.
    assert audit_condition("x > 5 && x < 3") is None
