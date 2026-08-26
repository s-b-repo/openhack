"""Python command-injection must follow taint INTERPROCEDURALLY — a shell sink wrapped in a helper
function (the OWASP PyGoat `mitre.py` shape: `def command_out(command): subprocess.Popen(command,
shell=True)`, called by a handler that builds `command` from `request`) was a silent FN under the
intraprocedural detector. The fix mirrors the Solidity oracle return-taint fixpoint: identify each
function's SINK-PARAMETERS (params that flow to a shell sink), then a caller passing a TAINTED arg into a
sink-param position reaches the sink.
"""
from lattice.ingest.python_taint import python_taint_audit


def _audit(tmp_path, src):
    p = tmp_path / "m.py"
    p.write_text(src)
    return python_taint_audit(p)


def test_interprocedural_helper_sink_FIRES(tmp_path):
    """request -> caller builds command -> helper(command) -> subprocess.Popen(command, shell=True)."""
    src = ("import subprocess\n"
           "def command_out(command):\n"
           "    return subprocess.Popen(command, shell=True)\n"
           "def handler(request):\n"
           "    ip = request.POST.get('ip')\n"
           "    cmd = 'ping ' + ip\n"
           "    command_out(cmd)\n")
    findings = _audit(tmp_path, src)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert "handler" in {f["function"] for f in findings}, "the caller's flow reaches the helper's sink"


def test_interprocedural_safe_helper_SILENT(tmp_path):
    """The same shape but the helper uses the LIST form (no shell) — no sink, must stay silent."""
    src = ("import subprocess\n"
           "def run_args(argv):\n"
           "    return subprocess.run(argv)\n"           # list form, no shell -> not a sink
           "def handler(request):\n"
           "    ip = request.POST.get('ip')\n"
           "    run_args(['ping', ip])\n")
    assert _audit(tmp_path, src) == [], "a list-form helper has no shell sink"


def test_interprocedural_untainted_arg_SILENT(tmp_path):
    """A helper with a shell sink-param called with a CONSTANT arg must not fire (taint-gated)."""
    src = ("import subprocess\n"
           "def command_out(command):\n"
           "    return subprocess.Popen(command, shell=True)\n"
           "def cron():\n"
           "    command_out('backup --now')\n")
    assert _audit(tmp_path, src) == [], "a constant arg to a sink-helper is not injection"


# ── cross-file interprocedural (deep-sweep wk01jvye5) ──
def test_crossfile_interproc_helper_FIRES(tmp_path):
    """The sink-wrapping helper lives in helper.py and the tainted caller in app.py — auditing the
    DIRECTORY must carry taint across the file boundary (the per-file sink-param map was a silent FN)."""
    (tmp_path / "helper.py").write_text(
        "import subprocess\n"
        "def run_cmd(command):\n"
        "    return subprocess.Popen(command, shell=True)\n")
    (tmp_path / "app.py").write_text(
        "from helper import run_cmd\n"
        "def handler(request):\n"
        "    run_cmd('ping ' + request.args['host'])\n")
    findings = python_taint_audit(tmp_path)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert any(f.get("file") == "app.py" for f in findings)


def test_crossfile_safe_helper_SILENT(tmp_path):
    """Cross-file but the helper is the LIST form (no shell) — must stay silent (widening stays gated)."""
    (tmp_path / "h2.py").write_text(
        "import subprocess\n"
        "def run_args(argv):\n"
        "    return subprocess.run(argv)\n")
    (tmp_path / "a2.py").write_text(
        "from h2 import run_args\n"
        "def handler(request):\n"
        "    run_args(['ping', request.args['host']])\n")
    assert python_taint_audit(tmp_path) == []


def test_duplicate_helper_name_does_not_transfer_sink_summary(tmp_path):
    """A dirty helper's bare-name summary must not attach to an unrelated clean definition."""
    (tmp_path / "dirty.py").write_text(
        "import subprocess\n"
        "def run_cmd(command):\n"
        "    return subprocess.Popen(command, shell=True)\n")
    (tmp_path / "clean.py").write_text(
        "def run_cmd(command):\n"
        "    return command\n")
    (tmp_path / "app.py").write_text(
        "from clean import run_cmd\n"
        "def handler(request):\n"
        "    run_cmd(request.args['host'])\n")
    assert python_taint_audit(tmp_path) == []


def test_same_file_helper_survives_unrelated_duplicate_name(tmp_path):
    """A second module's same-named helper cannot suppress an exact same-file call."""
    (tmp_path / "vulnerable.py").write_text(
        "import subprocess\n"
        "def sh(command):\n"
        "    return subprocess.Popen(command, shell=True)\n"
        "def handler(request):\n"
        "    sh(request.args['host'])\n")
    (tmp_path / "unrelated.py").write_text(
        "def sh(command):\n"
        "    return command\n")

    findings = python_taint_audit(tmp_path)
    assert any(f.get("kind") == "command_injection" and f.get("file") == "vulnerable.py"
               for f in findings), findings


def test_duplicate_import_resolves_to_exact_dirty_module(tmp_path):
    """An explicit from-import identifies the dirty definition even when its bare name is duplicated."""
    (tmp_path / "dirty.py").write_text(
        "import subprocess\n"
        "def sh(command):\n"
        "    return subprocess.Popen(command, shell=True)\n")
    (tmp_path / "clean.py").write_text(
        "def sh(command):\n"
        "    return command\n")
    (tmp_path / "app.py").write_text(
        "from dirty import sh\n"
        "def handler(request):\n"
        "    sh(request.args['host'])\n")

    findings = python_taint_audit(tmp_path)
    assert any(f.get("kind") == "command_injection" and f.get("file") == "app.py"
               for f in findings), findings


def test_unresolved_explicit_import_does_not_fall_back_to_local_summary(tmp_path):
    """An external import cannot inherit a unique same-named helper from another module."""
    (tmp_path / "dirty.py").write_text(
        "import subprocess\n"
        "def sh(command):\n"
        "    return subprocess.Popen(command, shell=True)\n")
    (tmp_path / "app.py").write_text(
        "from external_package import sh\n"
        "def handler(request):\n"
        "    sh(request.args['host'])\n")

    assert python_taint_audit(tmp_path) == []


def test_function_local_import_resolves_exact_helper_with_duplicate(tmp_path):
    """A function-local import keeps its exact target despite a duplicate helper elsewhere."""
    (tmp_path / "dirty.py").write_text(
        "import subprocess\n"
        "def sh(command):\n"
        "    return subprocess.Popen(command, shell=True)\n")
    (tmp_path / "other.py").write_text(
        "def sh(command):\n"
        "    return command\n")
    (tmp_path / "app.py").write_text(
        "def handler(request):\n"
        "    from dirty import sh\n"
        "    sh(request.args['host'])\n")

    findings = python_taint_audit(tmp_path)
    assert any(f.get("kind") == "command_injection" and f.get("file") == "app.py"
               for f in findings), findings


def test_function_local_import_does_not_leak_to_sibling_scope(tmp_path):
    """A dirty local import in one function cannot override a sibling's clean module binding."""
    (tmp_path / "dirty.py").write_text(
        "import subprocess\n"
        "def sh(command):\n"
        "    return subprocess.Popen(command, shell=True)\n")
    (tmp_path / "clean.py").write_text(
        "def sh(command):\n"
        "    return command\n")
    (tmp_path / "app.py").write_text(
        "from clean import sh\n"
        "def import_dirty():\n"
        "    from dirty import sh\n"
        "    return sh\n"
        "def handler(request):\n"
        "    sh(request.args['host'])\n")

    assert python_taint_audit(tmp_path) == []


def test_class_qualified_helpers_keep_receiver_identity(tmp_path):
    """``self.sh`` resolves within its class; a clean sibling class does not inherit the summary."""
    src = ("import subprocess\n"
           "class Dirty:\n"
           "    def sh(self, command):\n"
           "        return subprocess.Popen(command, shell=True)\n"
           "    def handler(self, request):\n"
           "        self.sh(request.args['host'])\n"
           "class Clean:\n"
           "    def sh(self, command):\n"
           "        return command\n"
           "    def handler(self, request):\n"
           "        self.sh(request.args['host'])\n")
    findings = _audit(tmp_path, src)
    commands = [f for f in findings if f.get("kind") == "command_injection"]
    assert len(commands) == 1, findings
