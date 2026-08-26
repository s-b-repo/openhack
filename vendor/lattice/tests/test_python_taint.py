"""CROSS-LANGUAGE PROOF — the trust/taint OPERATOR (lattice.taint.trust_obstructions) carries to PYTHON
unchanged; only a new stdlib-`ast` ingest classifies sources/sinks/sanitizers. This is the DVD-equivalent
for Python: a real OS-command-injection idiom (CWE-78) must FIRE; the byte-identical `shlex.quote`-
sanitized version must be SILENT — differing ONLY in the source->sink path.

It validates the workflow design's central claim (operator is language-agnostic, the work is one ingest)
AND the three defects the adversarial verifier found and that this ingest fixes:
  (1) INLINE-SOURCE — `os.system(request.args['h'])` with no intermediate binding still FIRES
      (source-marker names are seeded tainted, exactly the inline-read FN solidity_taint patched).
  (2) DOTTED sink/sanitizer — `pickle.loads` != `json.loads`; `shlex.quote` keyed on the dotted callee.
  (3) SANITIZER-WINS — a value through a sanitizer (bound OR inline) is clean even though its footprint
      still contains the source name.
"""
from lattice.ingest.python_taint import python_taint_audit
from lattice.taint import trust_obstructions  # the operator the ingest calls VERBATIM


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return python_taint_audit(p)


# ---- the load-bearing TOGGLE: bound source -> os.system, shlex.quote is the only difference ----

def test_command_injection_bound_FIRES(tmp_path):
    src = ("import os\n"
           "def handler(request):\n"
           "    cmd = request.args['host']\n"
           "    os.system('ping ' + cmd)\n")
    findings = _audit(tmp_path, "vuln.py", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert "handler" in {f["function"] for f in findings}


def test_command_injection_bound_shlex_SILENT(tmp_path):
    src = ("import os, shlex\n"
           "def handler(request):\n"
           "    cmd = shlex.quote(request.args['host'])\n"
           "    os.system('ping ' + cmd)\n")
    assert _audit(tmp_path, "safe.py", src) == [], "shlex.quote-sanitized command must not fire"


def test_toggle_is_genuine(tmp_path):
    """The two files differ ONLY by the shlex.quote wrap on the source->sink path."""
    vuln = ("import os\n"
            "def h(request):\n"
            "    c = request.args['x']\n"
            "    os.system('ls ' + c)\n")
    safe = ("import os, shlex\n"
            "def h(request):\n"
            "    c = shlex.quote(request.args['x'])\n"
            "    os.system('ls ' + c)\n")
    assert _audit(tmp_path, "v.py", vuln) and not _audit(tmp_path, "s.py", safe)


# ---- defect (1): INLINE source (no intermediate binding) must still fire ----

def test_inline_source_FIRES(tmp_path):
    src = ("import os\n"
           "def handler(request):\n"
           "    os.system('ping ' + request.args['host'])\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "inline.py", src))


def test_inline_shlex_SILENT(tmp_path):
    """Inline sanitizer: request.* is still in the call's arg footprint, but shlex.quote sanitizes it."""
    src = ("import os, shlex\n"
           "def handler(request):\n"
           "    os.system('ping ' + shlex.quote(request.args['host']))\n")
    assert _audit(tmp_path, "inlinesafe.py", src) == []


# ---- subprocess shell=True is a sink; a list-arg (no shell) is not ----

def test_subprocess_shell_true_FIRES(tmp_path):
    src = ("import subprocess\n"
           "def run(request):\n"
           "    subprocess.call('echo ' + request.args['m'], shell=True)\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "sp.py", src))


def test_subprocess_list_no_shell_SILENT(tmp_path):
    """subprocess.run([...]) with no shell=True does not spawn a shell — not a command-injection sink."""
    src = ("import subprocess\n"
           "def run(request):\n"
           "    subprocess.run(['echo', request.args['m']])\n")
    assert _audit(tmp_path, "spsafe.py", src) == []


# ---- CLI source (sys.argv) also taints ----

def test_argv_source_FIRES(tmp_path):
    src = ("import os, sys\n"
           "def main():\n"
           "    target = sys.argv[1]\n"
           "    os.system('nmap ' + target)\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "cli.py", src))


# ---- a constant command (no source) must stay silent ----

def test_constant_command_SILENT(tmp_path):
    src = ("import os\n"
           "def cron():\n"
           "    os.system('backup --now')\n")
    assert _audit(tmp_path, "const.py", src) == []


# ---- the proof of the carry: the ingest calls the SAME operator that validated on Solidity ----

def test_module_level_command_injection_FIRES(tmp_path):
    """Real scripts wire source->sink at MODULE level, not inside a function (the Bandit examples are
    all module-level). A function-only walk misses them — the 'fixtures use functions, real code uses
    module scope' slip. The module body is an implicit scope and must be analyzed."""
    src = ("import os, sys\n"
           "target = sys.argv[1]\n"
           "os.system('ping ' + target)\n")
    findings = _audit(tmp_path, "script.py", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings


def test_module_level_constant_SILENT(tmp_path):
    """A module-level CONSTANT command (the Bandit os_system.py shape) is a sink but not tainted —
    a taint analyzer must stay silent (the sink-linter-vs-taint-analyzer distinction)."""
    src = ("import os\n"
           "os.system('/bin/echo hi')\n")
    assert _audit(tmp_path, "const_mod.py", src) == []


def test_operator_is_reused_verbatim():
    """trust_obstructions is the language-agnostic operator: a tainted dep-dict FIRES, the sanitized
    one is SILENT — identical call shape the Solidity legs use, no Python-specific operator."""
    deps = {"cmd": {"request"}}
    assert trust_obstructions(deps, sources={"request"}, sinks={"cmd"}, sanitizers=set())
    assert not trust_obstructions(deps, sources={"request"}, sinks={"cmd"}, sanitizers={"cmd"})


# ── idiom-sweep fixes (workflow ws6yh6pp7) ──
def test_augassign_command_FIRES(tmp_path):
    """cmd += request.args.get('h') — incremental command building; the AugAssign must carry taint."""
    src = ("import os\ndef h(request):\n    cmd = 'ping '\n    cmd += request.args.get('h')\n    os.system(cmd)\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "aug.py", src))


def test_html_escape_is_NOT_shell_sanitizer_FIRES(tmp_path):
    """html.escape neutralizes HTML, NOT shell metacharacters — treating it as a sanitizer was a SILENT
    FN. A command through html.escape must still FIRE."""
    src = ("import os, html\ndef h(request):\n    x = html.escape(request.args.get('h'))\n    os.system('ping ' + x)\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "he.py", src)), "html.escape is not a shell sanitizer"


def test_shlex_quote_still_sanitizes_SILENT(tmp_path):
    """The genuine shell sanitizer shlex.quote must still silence (no over-correction)."""
    src = ("import os, shlex\ndef h(request):\n    x = shlex.quote(request.args.get('h'))\n    os.system('ping ' + x)\n")
    assert _audit(tmp_path, "sq.py", src) == []


def test_from_import_system_FIRES(tmp_path):
    """`from os import system; system('ping ' + h)` — bare callee, must still be recognized as a sink."""
    src = ("from os import system\ndef h(request):\n    x = request.args.get('h')\n    system('ping ' + x)\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "fi.py", src))


def test_subprocess_getoutput_FIRES(tmp_path):
    """subprocess.getoutput always runs a shell (no shell= param) — must fire."""
    src = ("import subprocess\ndef h(request):\n    x = request.args.get('h')\n    subprocess.getoutput('ping ' + x)\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "go.py", src))
