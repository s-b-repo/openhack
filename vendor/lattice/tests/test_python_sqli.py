"""FIRES / SILENT / toggle triple for Python SQL injection (CWE-89).

New attack class added in the accuracy sweep. Same discipline as
tests/test_python_taint.py: the two files must differ ONLY by whether the query
is parametrized (safe) or composed from a tainted source (vulnerable). The name
"toggle_is_genuine" carries the load-bearing invariant — if the toggle body is
larger than the fix, either the detector has a hidden path-condition or a whole
class of real injections is being masked.
"""
from lattice.ingest.python_taint import python_taint_audit


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return [f for f in python_taint_audit(p) if f["kind"] == "sql_injection"]


# ── the core FIRES / SILENT / toggle triple ───────────────────────────────────

def test_sqli_string_concat_FIRES(tmp_path):
    src = ("def view(request):\n"
           "    uid = request.args['id']\n"
           "    cur.execute('SELECT * FROM u WHERE id = ' + uid)\n")
    findings = _audit(tmp_path, "vuln.py", src)
    assert findings, "concatenated tainted SQL must fire"
    assert findings[0]["cwe"] == "CWE-89"


def test_sqli_parametrized_SILENT(tmp_path):
    src = ("def view(request):\n"
           "    uid = request.args['id']\n"
           "    cur.execute('SELECT * FROM u WHERE id = ?', (uid,))\n")
    assert _audit(tmp_path, "safe.py", src) == [], "parametrized query must not fire"


def test_sqli_toggle_is_genuine(tmp_path):
    vuln = ("def h(request):\n"
            "    x = request.args['x']\n"
            "    cur.execute('SELECT ' + x)\n")
    safe = ("def h(request):\n"
            "    x = request.args['x']\n"
            "    cur.execute('SELECT ?', (x,))\n")
    assert _audit(tmp_path, "v.py", vuln), "vulnerable form must fire"
    assert not _audit(tmp_path, "s.py", safe), "parametrized form must not fire"


# ── additional shapes ────────────────────────────────────────────────────────

def test_sqli_fstring_FIRES(tmp_path):
    src = ("def h(request):\n"
           "    uid = request.args['id']\n"
           "    cur.execute(f'SELECT * FROM u WHERE id = {uid}')\n")
    assert _audit(tmp_path, "v.py", src), "f-string-composed SQL must fire"


def test_sqli_format_FIRES(tmp_path):
    src = ("def h(request):\n"
           "    uid = request.args['id']\n"
           "    cur.execute('SELECT * FROM u WHERE id = {}'.format(uid))\n")
    assert _audit(tmp_path, "v.py", src), ".format-composed SQL must fire"


def test_sqli_executemany_parametrized_SILENT(tmp_path):
    """The parametrized shape (arg0 bare string constant + arg1 list literal) is silent
    even for executemany, because arg0 has no name footprint to taint."""
    src = ("def h(request):\n"
           "    x = request.args['x']\n"
           "    cur.executemany('INSERT INTO u(name) VALUES (?)', [(x,)])\n")
    assert _audit(tmp_path, "safe.py", src) == [], \
        "bare-constant arg0 + list-literal arg1 is the parametrized shape"


def test_sqli_executemany_composed_query_FIRES(tmp_path):
    """A composed table name (concat into arg0) reaches the operator's tainted set even
    with a rows-list arg1. Only the arg0 shape decides parametrization safety."""
    src = ("def h(request):\n"
           "    tbl = request.args['tbl']\n"
           "    cur.executemany('INSERT INTO ' + tbl + ' VALUES (?)', rows)\n")
    assert _audit(tmp_path, "v.py", src), "composed table name in executemany must fire"


def test_sqli_bare_execute_leaf_FIRES(tmp_path):
    """Any `.execute(sql)` receiver — the leaf-name check catches session.execute,
    db.execute, connection.execute, etc., without needing to enumerate every ORM."""
    for recv in ("db.session", "self.conn", "engine.connection"):
        src = (f"def h(request):\n"
               f"    x = request.args['x']\n"
               f"    {recv}.execute('SELECT ' + x)\n")
        assert _audit(tmp_path, "v.py", src), f"leaf `.execute` on {recv} must fire"


def test_sqli_constant_query_SILENT(tmp_path):
    """No taint reaches the sink — constant query is silent even when composed."""
    src = ("def h():\n"
           "    cur.execute('SELECT COUNT(*) FROM u')\n"
           "    cur.execute('DROP TABLE ' + 'temp')\n")
    assert _audit(tmp_path, "safe.py", src) == []


def test_sqli_kwargs_only_untainted_SILENT(tmp_path):
    """A single positional arg with no tainted footprint stays silent."""
    src = ("def h():\n"
           "    q = 'SELECT 1'\n"
           "    cur.execute(q)\n")
    assert _audit(tmp_path, "safe.py", src) == []


def test_sqli_argv_source_FIRES(tmp_path):
    src = ("import sys\n"
           "def h():\n"
           "    n = sys.argv[1]\n"
           "    cur.execute('DROP TABLE ' + n)\n")
    assert _audit(tmp_path, "v.py", src), "sys.argv-sourced SQL composition must fire"


def test_sqli_environ_source_FIRES(tmp_path):
    src = ("import os\n"
           "def h():\n"
           "    t = os.environ['TABLE']\n"
           "    cur.execute('DELETE FROM ' + t)\n")
    assert _audit(tmp_path, "v.py", src), "env-var-sourced SQL composition must fire"


def test_shlex_quote_wrapped_source_is_known_FN_SILENT(tmp_path):
    """KNOWN LIMITATION (honest documentation, not silent). A value wound through
    `shlex.quote(...)` at ASSIGNMENT time is stripped from the deps footprint at
    ingest time (`_value_names` skips sanitizer calls), so it becomes silent even
    against a SQL sink where shlex.quote is a wrong-domain sanitizer. This is a
    genuine FN — noted in the module docstring; closing it requires a per-domain
    sanitizer split in `_build_deps` (a Wave-3+ refactor)."""
    src = ("import shlex\n"
           "def h(request):\n"
           "    x = shlex.quote(request.args['x'])\n"
           "    cur.execute('SELECT ' + x)\n")
    # Current behavior: silent (documented FN).
    assert _audit(tmp_path, "v.py", src) == [], \
        "current model treats shlex.quote as domain-blind; documented FN"


def test_shlex_quote_inline_sql_composition_FIRES(tmp_path):
    """The FN above is only for BOUND assignments through shlex.quote. When the
    tainted source is composed INLINE at the sink call (`'SELECT ' + request.args['x']`),
    the deps stripping doesn't apply — the sink's arg0 name-footprint contains the
    tainted `request`, and the SQLi still fires. This proves the domain-blind bug is
    localized to the deps pass, not the sink pass."""
    src = ("def h(request):\n"
           "    cur.execute('SELECT * WHERE x = ' + request.args['x'])\n")
    assert _audit(tmp_path, "v.py", src), "inline-composed SQL from request must fire"


def test_command_and_sql_both_reported(tmp_path):
    """A scope that has BOTH a shell sink and a SQL sink emits BOTH findings."""
    src = ("import os\n"
           "def h(request):\n"
           "    x = request.args['x']\n"
           "    os.system('ls ' + x)\n"
           "    cur.execute('SELECT ' + x)\n")
    findings = [f for f in python_taint_audit(tmp_path)
                if f["file"] == "" or True]  # dir audit
    p = tmp_path / "v.py"
    p.write_text(src)
    findings = python_taint_audit(p)
    kinds = {f["kind"] for f in findings}
    assert kinds == {"command_injection", "sql_injection"}, kinds
