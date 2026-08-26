"""CROSS-LANGUAGE PROOF (Ruby) — the trust/taint operator carries to Ruby for OS command injection.
Operator verbatim; the ingest builds the dep dict + source/sink sets from the native Ripper AST.
TOGGLE: system("ping #{params[:host]}") FIRES; a constant command is SILENT."""
import shutil
import pytest
from lattice.ingest.ruby_taint import ruby_taint_audit, _BRIDGE


def _ok():
    return _BRIDGE.exists() and shutil.which("ruby") is not None


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return ruby_taint_audit(p)


def test_params_system_interp_FIRES(tmp_path):
    if not _ok():
        pytest.skip("ruby not available")
    src = "def handler\n  host = params[:host]\n  system(\"ping #{host}\")\nend\n"
    f = _audit(tmp_path, "h.rb", src)
    assert any(x["kind"] == "command_injection" for x in f), f
    assert "handler" in {x["function"] for x in f}


def test_constant_SILENT(tmp_path):
    if not _ok():
        pytest.skip("ruby not available")
    src = "def cron\n  system(\"backup --now\")\nend\n"
    assert _audit(tmp_path, "c.rb", src) == []


def test_backtick_interp_FIRES(tmp_path):
    if not _ok():
        pytest.skip("ruby not available")
    src = "def run\n  q = params[:q]\n  out = `grep #{q} log.txt`\nend\n"
    assert any(x["kind"] == "command_injection" for x in _audit(tmp_path, "b.rb", src))


def test_env_source_FIRES(tmp_path):
    if not _ok():
        pytest.skip("ruby not available")
    src = "def run\n  t = ENV[\"TARGET\"]\n  system(\"nmap #{t}\")\nend\n"
    assert any(x["kind"] == "command_injection" for x in _audit(tmp_path, "e.rb", src))


def test_toggle_is_genuine(tmp_path):
    if not _ok():
        pytest.skip("ruby not available")
    vuln = "def h\n  x = params[:x]\n  system(\"echo #{x}\")\nend\n"
    safe = "def h\n  system(\"echo hi\")\nend\n"
    assert _audit(tmp_path, "v.rb", vuln) and not _audit(tmp_path, "s.rb", safe)


def test_operator_is_reused_verbatim():
    from lattice.taint import trust_obstructions
    deps = {"host": {"params"}}
    assert trust_obstructions(deps, sources={"params"}, sinks={"host"}, sanitizers=set())
    assert not trust_obstructions(deps, sources={"params"}, sinks={"host"}, sanitizers={"host"})


def test_class_method_def_self_analyzed(tmp_path):
    """Fastlane-style class methods (`def self.run`) must be analyzed as their own scope, not swept into
    <main> (which conflates all methods and risks cross-method FPs)."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ("class Action\n  def self.run(params)\n    host = params[:host]\n"
           "    system(\"ping #{host}\")\n  end\nend\n")
    f = _audit(tmp_path, "cls.rb", src)
    assert any(x["kind"] == "command_injection" for x in f), f
    assert "run" in {x["function"] for x in f}, f"must attribute to 'run', not <main>: {f}"


def test_shellescape_sanitizes_SILENT(tmp_path):
    """`.shellescape` is Ruby's shell sanitizer — a value passed through it must NOT fire (the fastlane FP)."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ("def h\n  host = params[:host].shellescape\n  system(\"ping #{host}\")\nend\n")
    assert _audit(tmp_path, "se.rb", src) == [], "shellescape-sanitized command must not fire"


# ── idiom-sweep fixes (workflow ws6yh6pp7) ──
def test_opassign_command_FIRES(tmp_path):
    """cmd += params[:host] — Ripper emits :opassign (not :assign); the bridge must carry the taint."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def run(params)\n  cmd = "ping "\n  cmd += params[:host]\n  system(cmd)\nend\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "aug.rb", src))


def test_shovel_append_command_FIRES(tmp_path):
    """cmd << params[:host] — the `<<` string mutation appends taint into cmd; must fire."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def run(params)\n  cmd = "ping "\n  cmd << params[:host]\n  system(cmd)\nend\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "sh.rb", src))


def test_regexp_quote_is_NOT_shell_sanitizer_FIRES(tmp_path):
    """Regexp.quote escapes REGEX metacharacters, leaving `;`/`|`/`$()` intact — it is NOT a shell
    sanitizer. Treating bare `quote` as safe was a SILENT FN; this must FIRE."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def run(params)\n  q = Regexp.quote(params[:host])\n  system("ping #{q}")\nend\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "rq.rb", src)), "Regexp.quote is not a shell sanitizer"


def test_inline_shellescape_SILENT(tmp_path):
    """system("ping #{params[:host].shellescape}") — the genuine shell sanitizer applied INLINE must
    silence (the fastlane-style FP)."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def run(params)\n  system("ping #{params[:host].shellescape}")\nend\n')
    assert _audit(tmp_path, "ise.rb", src) == [], "inline .shellescape sanitizes"


def test_shellescape_assign_still_SILENT(tmp_path):
    """Regression: the bound-sanitizer path (safe = x.shellescape; system(safe)) must remain silent."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def run(params)\n  safe = params[:host].shellescape\n  system("ping #{safe}")\nend\n')
    assert _audit(tmp_path, "ase.rb", src) == []


# ── interprocedural + cross-file (deep-sweep wk01jvye5) ──
def test_intrafile_sink_wrapper_FIRES(tmp_path):
    """A helper wrapping system(cmd) called with a tainted param — Ruby had NO interproc summary (silent FN)."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def sh(cmd)\n  system(cmd)\nend\n'
           'def run(params)\n  sh(params[:host])\nend\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "ip.rb", src))


def test_intrafile_safe_wrapper_SILENT(tmp_path):
    """A helper whose param is shellescaped before the sink must stay silent (taint-gated, sanitizer-aware)."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def sh(cmd)\n  system(cmd.shellescape)\nend\n'
           'def run(params)\n  sh(params[:host])\nend\n')
    assert _audit(tmp_path, "safe.rb", src) == []


def test_crossfile_sink_wrapper_FIRES(tmp_path):
    """Sink-wrapping helper in helper.rb, tainted caller in app.rb — auditing the DIRECTORY must carry taint."""
    if not _ok():
        pytest.skip("ruby not available")
    (tmp_path / "helper.rb").write_text('def sh(cmd)\n  system(cmd)\nend\n')
    (tmp_path / "app.rb").write_text('def run(params)\n  sh(params[:host])\nend\n')
    findings = ruby_taint_audit(tmp_path)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert any(f.get("file") == "app.rb" for f in findings)


def test_same_file_wrapper_survives_unrelated_duplicate_name(tmp_path):
    """An unrelated file's same-named top-level method cannot suppress a lexical local call."""
    if not _ok():
        pytest.skip("ruby not available")
    (tmp_path / "vulnerable.rb").write_text(
        "def sh(cmd)\n  system(cmd)\nend\n"
        "def run(params)\n  sh(params[:host])\nend\n")
    (tmp_path / "unrelated.rb").write_text(
        "def sh(cmd)\n  cmd\nend\n"
        "def run(params)\n  sh(params[:host])\nend\n")

    findings = ruby_taint_audit(tmp_path)
    assert any(f.get("kind") == "command_injection" and f.get("file") == "vulnerable.rb"
               for f in findings), findings
    assert not any(f.get("kind") == "command_injection" and f.get("file") == "unrelated.rb"
                   for f in findings), findings


def test_return_chain_helper_FIRES(tmp_path):
    """A helper that builds a tainted string and returns it (Ruby implicit return), then a caller shells
    the result — `cmd = build(); system(cmd)`. The source is hidden in build's body (was a silent FN)."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def build\n  raw = params[:host]\n  "ping #{raw}"\nend\n'
           'def run\n  cmd = build()\n  system(cmd)\nend\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "rc.rb", src))


def test_return_constant_helper_SILENT(tmp_path):
    """A helper returning a CONSTANT must not taint its callers (return-taint stays gated)."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def build\n  "localhost"\nend\n'
           'def run\n  cmd = build()\n  system("ping #{cmd}")\nend\n')
    assert _audit(tmp_path, "rcs.rb", src) == []


def test_file_qualified_return_source_survives_duplicate_name(tmp_path):
    if not _ok():
        pytest.skip("ruby not available")
    (tmp_path / "dirty.rb").write_text(
        "def build\n  ENV['CMD']\nend\n"
        "def run\n  command = build\n  system(command)\nend\n")
    (tmp_path / "clean.rb").write_text(
        "def build\n  'safe'\nend\n"
        "def run\n  command = build\n  system(command)\nend\n")

    findings = ruby_taint_audit(tmp_path)
    command_files = {f.get("file") for f in findings if f.get("kind") == "command_injection"}
    assert "dirty.rb" in command_files, findings
    assert "clean.rb" not in command_files, findings


def test_duplicate_method_return_source_does_not_taint_clean_receiver(tmp_path):
    """A dirty return summary on Dirty#load must not contaminate Clean#load."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('class Dirty\n  def load\n    ENV["CMD"]\n  end\nend\n'
           'class Clean\n  def load\n    "safe"\n  end\nend\n'
           'def run\n  loader = Clean.new\n  value = loader.load\n  system(value)\nend\n')
    assert _audit(tmp_path, "method_collision.rb", src) == []


def test_duplicate_method_return_source_propagates_for_exact_dirty_receiver(tmp_path):
    """Qualified collision defense retains the positive path for the actual dirty receiver."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('class Dirty\n  def load\n    ENV["CMD"]\n  end\nend\n'
           'class Clean\n  def load\n    "safe"\n  end\nend\n'
           'def run\n  loader = Dirty.new\n  value = loader.load\n  system(value)\nend\n')
    findings = _audit(tmp_path, "method_exact.rb", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings


def test_qualified_open3_sink_still_fires(tmp_path):
    """Qualified call identity must not hide the bare Open3 shell-sink classification."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('require "open3"\n'
           'def run(params)\n  Open3.capture3("ping #{params[:host]}")\nend\n')
    findings = _audit(tmp_path, "open3.rb", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings


def test_duplicate_method_sink_summary_does_not_attach_to_clean_receiver(tmp_path):
    if not _ok():
        pytest.skip("ruby not available")
    src = ('class Dirty\n  def run(cmd)\n    system(cmd)\n  end\nend\n'
           'class Clean\n  def run(cmd)\n    cmd\n  end\nend\n'
           'def handler(params)\n  runner = Clean.new\n  runner.run(params[:host])\nend\n')
    assert _audit(tmp_path, "method_sink_clean.rb", src) == []


def test_duplicate_method_sink_summary_propagates_for_exact_dirty_receiver(tmp_path):
    if not _ok():
        pytest.skip("ruby not available")
    src = ('class Dirty\n  def run(cmd)\n    system(cmd)\n  end\nend\n'
           'class Clean\n  def run(cmd)\n    cmd\n  end\nend\n'
           'def handler(params)\n  runner = Dirty.new\n  runner.run(params[:host])\nend\n')
    findings = _audit(tmp_path, "method_sink_dirty.rb", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings


# ── multiple-assignment (massign) with POSITIONAL pairing (deep-sweep wk01jvye5) ──
def test_massign_basic_FIRES(tmp_path):
    """`host, port = params[:host], params[:port]` — Ripper :massign was unhandled, dropping the binding."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def run(params)\n  host, port = params[:host], params[:port]\n  system("ping #{host}")\nend\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "ma.rb", src))


def test_massign_positional_no_sanitizer_leak_FIRES(tmp_path):
    """LANDMINE: `a, b = params[:x].shellescape, params[:y]` — a is sanitized, b is NOT. Positional pairing
    must keep b tainted; a UNION would leak `shellescape` onto b and SILENCE the real injection (new FN)."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def run(params)\n  a, b = params[:x].shellescape, params[:y]\n  system("ping #{b}")\nend\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "mp.rb", src)), "b must stay tainted"


def test_massign_sanitized_target_SILENT(tmp_path):
    """The sanitized target a (= x.shellescape) used in the sink must stay silent."""
    if not _ok():
        pytest.skip("ruby not available")
    src = ('def run(params)\n  a, b = params[:x].shellescape, params[:y]\n  system("ping #{a}")\nend\n')
    assert _audit(tmp_path, "ms.rb", src) == []
