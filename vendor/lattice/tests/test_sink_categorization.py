from lattice.security import _CALL_SINKS


def _cats(snippet):
    return {cat for rx, cat, _ in _CALL_SINKS if rx.search(snippet)}


def test_database_exec_is_sql_not_command_exec():
    """SQLite/better-sqlite3 `db.exec(sql)` is SQL execution, not a shell command —
    `\\bexec` was matching the `.exec` after the dot, inflating it to critical command_exec."""
    for recv in ("db", "database", "conn", "connection", "this.db", "pool", "sqlite"):
        snip = f"  {recv}.exec(`CREATE TABLE x`)"
        assert "command_exec" not in _cats(snip), f"{recv}.exec mis-flagged: {_cats(snip)}"
        assert "sql_injection" in _cats(snip), f"{recv}.exec not seen as SQL: {_cats(snip)}"


def test_shell_exec_still_command_exec():
    """Genuine shell execution must still be command_exec."""
    assert "command_exec" in _cats("  exec(userCmd)")                 # bare, from child_process
    assert "command_exec" in _cats("  childProcess.exec(cmd)")
    assert "command_exec" in _cats("  child_process.exec(cmd)")
    assert "command_exec" in _cats("  const p = spawn(c, args)")
    assert "command_exec" in _cats("  execSync(cmd)")


# ── Wave 2 additions: FIRES / SILENT per new regex trigger ──


def test_member_spawn_does_not_fire_command_exec():
    """`emitter.spawn(...)` isn't child_process.spawn — the lookbehind must kill it."""
    for recv in ("emitter", "this.emitter", "worker", "cluster"):
        snip = f"  {recv}.spawn(handler)"
        assert "command_exec" not in _cats(snip), f"{recv}.spawn mis-flagged: {_cats(snip)}"


def test_windows_process_family_is_command_exec():
    for name in ("_wsystem", "_system", "_spawnv", "_spawnvp", "_execv", "_execvp"):
        assert "command_exec" in _cats(f"  {name}(cmd)"), name


def test_new_function_and_vm_context_are_code_eval():
    assert "code_eval" in _cats("  const f = new Function('x','return x+1')")
    assert "code_eval" in _cats("  vm.runInNewContext(src, ctx)")
    assert "code_eval" in _cats("  vm.runInContext(src, ctx)")
    assert "code_eval" in _cats("  vm.compileFunction(src, [])")
    assert "code_eval" in _cats("  vm.Script(src)")


def test_extended_deserialization_sinks():
    assert "deserialization" in _cats("  cloudpickle.loads(buf)")
    assert "deserialization" in _cats("  dill.loads(buf)")
    assert "deserialization" in _cats("  jsonpickle.decode(buf)")


def test_extended_sql_sink_verbs():
    for call in ("cur.executemany(sql, rows)",
                 "conn.query_all(sql)",
                 "db.execute_batch(sql)"):
        assert "sql_injection" in _cats(f"  {call}"), call


def test_xss_extended_dom_sinks():
    assert "xss" in _cats("  el.outerHTML = html")
    assert "xss" in _cats("  el.insertAdjacentHTML('beforeend', html)")
    assert "xss" in _cats("  document.write(html)")
    assert "xss" in _cats("  document.writeln(html)")


def test_ssrf_regex_still_fires_baseline():
    """The regex itself still classifies as ssrf; the demotion to ssrf_possible
    happens only at the report layer (_scan_external_sinks). Regex layer stays
    unconditional so the taint layer can override it."""
    for call in ("fetch(url)", "requests.get(url)", "httpx.get(url)",
                 "requests.post(url, data)", "axios(url)"):
        assert "ssrf" in _cats(f"  {call}"), call


def test_ssrf_member_call_does_not_fire():
    """`user.fetch(...)` isn't the global fetch — lookbehind guards against it."""
    for snip in ("  user.fetch(url)", "  this.fetch(url)", "  self.fetch(url)"):
        assert "ssrf" not in _cats(snip), snip
