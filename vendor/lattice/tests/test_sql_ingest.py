from lattice.ingest.sql import sql_ingest
from lattice.complete.gate import check
from lattice.graph.builder import build


def test_sql_tables_procedures_and_calls(tmp_path):
    (tmp_path / "schema.sql").write_text(
        "CREATE TABLE users (id INT, name TEXT);\n"
        "CREATE FUNCTION get_user(uid INT) RETURNS TEXT AS $$\n"
        "  SELECT name FROM users WHERE id = uid;\n"
        "$$ LANGUAGE sql;\n"
        "CREATE PROCEDURE delete_user(uid INT) AS $$\n"
        "BEGIN\n"
        "  CALL get_user(uid);\n"
        "  DELETE FROM users WHERE id = uid;\n"
        "END; $$ LANGUAGE plpgsql;\n")
    raw = sql_ingest(tmp_path)
    names = {s.name for s in raw.symbols}
    assert {"users", "get_user", "delete_user"} <= names, names
    assert next(s for s in raw.symbols if s.name == "users").kind == "class"
    # delete_user CALLs get_user -> a resolved reference
    assert any(r.resolved and (r.to_file or "").endswith("schema.sql")
               for r in raw.references), [r.__dict__ for r in raw.references]


def test_mysql_single_statement_procedure_is_not_rejected_as_postgres_syntax(tmp_path):
    (tmp_path / "procedure.sql").write_text(
        "CREATE PROCEDURE citycount (IN country CHAR(3), OUT cities INT) "
        "SELECT COUNT(*) INTO cities FROM world.city WHERE CountryCode = country;\n"
    )

    raw = sql_ingest(tmp_path)

    assert raw.diagnostics == []
    assert any(symbol.name == "citycount" and symbol.kind == "function"
               for symbol in raw.symbols)
    assert check(build(raw)).verdict == "pass"


def test_sql_server_bracket_identifier_parenthesis_is_lexically_opaque(tmp_path):
    (tmp_path / "schema.sql").write_text("CREATE TABLE [odd(name] ([id] INT);\n")

    raw = sql_ingest(tmp_path)

    assert raw.diagnostics == []
    assert check(build(raw)).verdict == "pass"


def test_mysql_hash_comment_parenthesis_is_lexically_opaque(tmp_path):
    (tmp_path / "schema.sql").write_text(
        "# explain an unmatched ( without parsing it\nCREATE TABLE t (id INT);\n"
    )

    raw = sql_ingest(tmp_path)

    assert raw.diagnostics == []
    assert check(build(raw)).verdict == "pass"
