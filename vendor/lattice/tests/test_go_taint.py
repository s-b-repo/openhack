"""CROSS-LANGUAGE PROOF (Go) — the trust/taint operator carries to Go for OS command injection (CWE-78).
Operator called verbatim; the ingest builds the dep dict + source/sink sets from a native go/parser AST.
The load-bearing TOGGLE: `exec.Command("sh","-c", "ping "+host)` (shell-interpreted, host from the HTTP
request) FIRES; the byte-identical `exec.Command("ping", host)` (argv form, no shell) is SILENT.
"""
import shutil

import pytest

from lattice.ingest.go_taint import go_taint_audit, _BRIDGE


def _go_ok() -> bool:
    return _BRIDGE.exists() and shutil.which("go") is not None


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return go_taint_audit(p)


_HEAD = "package main\nimport (\n\t\"os/exec\"\n\t\"net/http\"\n)\n"


def test_shell_form_request_FIRES(tmp_path):
    if not _go_ok():
        pytest.skip("go bridge not built")
    src = _HEAD + ("func handler(w http.ResponseWriter, r *http.Request) {\n"
                   "\thost := r.FormValue(\"host\")\n"
                   "\texec.Command(\"sh\", \"-c\", \"ping \"+host).Run()\n"
                   "}\n")
    findings = _audit(tmp_path, "h.go", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert "handler" in {f["function"] for f in findings}


def test_argv_form_SILENT(tmp_path):
    """exec.Command("ping", host) — no shell, host is a single literal arg — cannot inject."""
    if not _go_ok():
        pytest.skip("go bridge not built")
    src = _HEAD + ("func handler(w http.ResponseWriter, r *http.Request) {\n"
                   "\thost := r.FormValue(\"host\")\n"
                   "\texec.Command(\"ping\", host).Run()\n"
                   "}\n")
    assert _audit(tmp_path, "s.go", src) == [], "argv form (no shell) cannot inject"


def test_toggle_is_genuine(tmp_path):
    if not _go_ok():
        pytest.skip("go bridge not built")
    vuln = _HEAD + "func h(w http.ResponseWriter, r *http.Request){ x:=r.FormValue(\"x\"); exec.Command(\"bash\",\"-c\",x).Run() }\n"
    safe = _HEAD + "func h(w http.ResponseWriter, r *http.Request){ x:=r.FormValue(\"x\"); exec.Command(\"echo\",x).Run() }\n"
    assert _audit(tmp_path, "v.go", vuln) and not _audit(tmp_path, "s.go", safe)


def test_tainted_program_name_FIRES(tmp_path):
    """exec.Command(userBinary) — the attacker chooses the binary that runs."""
    if not _go_ok():
        pytest.skip("go bridge not built")
    src = _HEAD + ("func handler(w http.ResponseWriter, r *http.Request) {\n"
                   "\tbin := r.FormValue(\"bin\")\n"
                   "\texec.Command(bin).Run()\n"
                   "}\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "p.go", src))


def test_os_args_source_FIRES(tmp_path):
    """CLI source: os.Args into a shell exec."""
    if not _go_ok():
        pytest.skip("go bridge not built")
    src = ("package main\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n"
           "func main() {\n"
           "\ttarget := os.Args[1]\n"
           "\texec.Command(\"sh\", \"-c\", \"nmap \"+target).Run()\n"
           "}\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "cli.go", src))


def test_constant_shell_command_SILENT(tmp_path):
    """A constant shell command (no taint) must stay silent."""
    if not _go_ok():
        pytest.skip("go bridge not built")
    src = _HEAD + ("func cron() {\n"
                   "\texec.Command(\"sh\", \"-c\", \"backup --now\").Run()\n"
                   "}\n")
    assert _audit(tmp_path, "c.go", src) == []


def test_operator_is_reused_verbatim():
    """trust_obstructions is the SAME language-agnostic operator — no Go-specific operator."""
    from lattice.taint import trust_obstructions
    deps = {"cmd": {"FormValue"}}
    assert trust_obstructions(deps, sources={"FormValue"}, sinks={"cmd"}, sanitizers=set())
    assert not trust_obstructions(deps, sources={"FormValue"}, sinks={"cmd"}, sanitizers={"cmd"})


# ── idiom-sweep fixes (workflow ws6yh6pp7) ──
def test_combined_shell_flags_FIRES(tmp_path):
    """exec.Command("bash", "-lc", x) — combined POSIX shell flags (-lc/-ec/-xc) still run a shell; the
    exact `-c` membership test missed them (FN)."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('func h(r *http.Request) {\n'
                   '    x := r.FormValue("c")\n'
                   '    exec.Command("bash", "-lc", "ping "+x)\n}\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "cf.go", src))


def test_interproc_helper_FIRES(tmp_path):
    """A helper wrapping exec.Command("sh","-c",cmd), called with a tainted arg — one-hop sink-param
    summary must carry the taint across the call (FN, the Python/JS fix ported to Go)."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('func sh(cmd string) {\n    exec.Command("sh", "-c", cmd)\n}\n'
                   'func h(r *http.Request) {\n    x := r.FormValue("c")\n    sh(x)\n}\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "ip.go", src))


def test_viper_get_config_SILENT(tmp_path):
    """A value from a TRUSTED config getter (viper.Get) reaching a shell is NOT attacker input — the bare
    `Get` selector collision must not FALSE-fire."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('func h() {\n    host := viper.Get("trusted.host").(string)\n'
                   '    exec.Command("sh", "-c", "ping "+host)\n}\n')
    assert _audit(tmp_path, "vg.go", src) == [], "viper.Get is a config getter, not attacker input"


def test_header_get_still_FIRES(tmp_path):
    """Regression for the FP fix: the genuine `.Get` HTTP source (r.Header.Get) on a non-trusted receiver
    must KEEP firing — the no-silent-FN footing forbids dropping the marker wholesale."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('func h(r *http.Request) {\n    x := r.Header.Get("X-Cmd")\n'
                   '    exec.Command("sh", "-c", "ping "+x)\n}\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "hg.go", src))


# ── cross-file interprocedural (deep-sweep wk01jvye5) ──
def test_crossfile_interproc_helper_FIRES(tmp_path):
    """Sink-wrapping helper in helper.go, tainted caller in main.go — auditing the DIRECTORY must carry
    taint across the file boundary (per-file sink-param map was a silent FN)."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    (tmp_path / "helper.go").write_text(
        'package main\nimport "os/exec"\n'
        'func sh(cmd string) { exec.Command("sh", "-c", cmd) }\n')
    (tmp_path / "main.go").write_text(
        'package main\nimport "net/http"\n'
        'func h(r *http.Request) { sh(r.FormValue("c")) }\n')
    findings = go_taint_audit(tmp_path)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert any(f.get("file") == "main.go" for f in findings)


def test_same_package_helper_survives_duplicate_name_in_other_directory(tmp_path):
    """Two commands may both use ``package main`` without sharing a Go package.

    The unrelated clean ``cmd/b.sh`` must not make the lexically exact ``cmd/a.sh`` summary
    disappear, and the dirty summary must not transfer into ``cmd/b``.
    """
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    command_a = tmp_path / "cmd" / "a"
    command_b = tmp_path / "cmd" / "b"
    command_a.mkdir(parents=True)
    command_b.mkdir(parents=True)
    (command_a / "helper.go").write_text(
        'package main\nimport "os/exec"\n'
        'func sh(cmd string) { exec.Command("sh", "-c", cmd).Run() }\n')
    (command_a / "main.go").write_text(
        'package main\nimport "net/http"\n'
        'func handler(r *http.Request) { sh(r.FormValue("cmd")) }\n')
    (command_b / "helper.go").write_text(
        'package main\nfunc sh(cmd string) { _ = cmd }\n')
    (command_b / "main.go").write_text(
        'package main\nimport "net/http"\n'
        'func handler(r *http.Request) { sh(r.FormValue("cmd")) }\n')

    findings = go_taint_audit(tmp_path)
    command_files = {f.get("file") for f in findings if f.get("kind") == "command_injection"}
    assert "cmd/a/main.go" in command_files, findings
    assert "cmd/b/main.go" not in command_files, findings


def test_qualified_external_call_does_not_use_local_bare_summary(tmp_path):
    """A package-qualified call is not a same-named helper in the current package."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = ('package main\nimport ("net/http"; "os/exec"; clean "example.com/clean")\n'
           'func Run(cmd string) { exec.Command("sh", "-c", cmd).Run() }\n'
           'func handler(r *http.Request) { clean.Run(r.FormValue("cmd")) }\n')
    assert _audit(tmp_path, "external.go", src) == []


# ── return-value taint laundering (deep-sweep wk01jvye5) ──
def test_return_value_source_FIRES(tmp_path):
    """A helper that READS a source internally and RETURNS it, then the caller shells the result —
    `v := get(r); exec.Command("sh","-c",v)`. The source is hidden in get()'s body (was a silent FN)."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('func get(r *http.Request) string { return r.FormValue("c") }\n'
                   'func h(r *http.Request) { v := get(r); exec.Command("sh", "-c", v) }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "rv.go", src))


def test_return_constant_SILENT(tmp_path):
    """A helper that returns a CONSTANT must not mark its callers tainted (return-taint stays gated)."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('func get() string { return "localhost" }\n'
                   'func h() { v := get(); exec.Command("sh", "-c", "ping "+v) }\n')
    assert _audit(tmp_path, "rc.go", src) == []


def test_package_qualified_return_source_survives_other_directory_duplicate(tmp_path):
    """Return-taint summaries use the same package identity as sink-wrapper summaries."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    command_a = tmp_path / "cmd" / "a"
    command_b = tmp_path / "cmd" / "b"
    command_a.mkdir(parents=True)
    command_b.mkdir(parents=True)
    (command_a / "main.go").write_text(
        'package main\nimport ("os"; "os/exec")\n'
        'func load() string { return os.Getenv("CMD") }\n'
        'func main() { value := load(); exec.Command("sh", "-c", value).Run() }\n')
    (command_b / "main.go").write_text(
        'package main\nimport "os/exec"\n'
        'func load() string { return "safe" }\n'
        'func main() { value := load(); exec.Command("sh", "-c", value).Run() }\n')

    findings = go_taint_audit(tmp_path)
    command_files = {f.get("file") for f in findings if f.get("kind") == "command_injection"}
    assert "cmd/a/main.go" in command_files, findings
    assert "cmd/b/main.go" not in command_files, findings


def test_duplicate_method_return_source_does_not_taint_clean_receiver(tmp_path):
    """A dirty method summary belongs to its receiver type, not every method with that bare name."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = ('package main\nimport ("os"; "os/exec")\n'
           'type Dirty struct{}\nfunc (Dirty) Load() string { return os.Getenv("CMD") }\n'
           'type Clean struct{}\nfunc (Clean) Load() string { return "safe" }\n'
           'func main() { c := Clean{}; v := c.Load(); '
           'exec.Command("sh", "-c", v).Run() }\n')
    assert _audit(tmp_path, "method_collision.go", src) == []


def test_duplicate_method_return_source_propagates_for_exact_dirty_receiver(tmp_path):
    """Collision suppression must retain the positive path when the receiver type is provable."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = ('package main\nimport ("os"; "os/exec")\n'
           'type Dirty struct{}\nfunc (Dirty) Load() string { return os.Getenv("CMD") }\n'
           'type Clean struct{}\nfunc (Clean) Load() string { return "safe" }\n'
           'func main() { d := Dirty{}; v := d.Load(); '
           'exec.Command("sh", "-c", v).Run() }\n')
    findings = _audit(tmp_path, "method_exact.go", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings


def test_duplicate_method_sink_summary_does_not_attach_to_clean_receiver(tmp_path):
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = (_HEAD +
           'type Dirty struct{}\nfunc (Dirty) Run(cmd string) { exec.Command("sh", "-c", cmd) }\n'
           'type Clean struct{}\nfunc (Clean) Run(cmd string) { _ = cmd }\n'
           'func handler(r *http.Request) { x := r.FormValue("cmd"); c := Clean{}; c.Run(x) }\n')
    assert _audit(tmp_path, "method_sink_clean.go", src) == []


def test_duplicate_method_sink_summary_propagates_for_exact_dirty_receiver(tmp_path):
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = (_HEAD +
           'type Dirty struct{}\nfunc (Dirty) Run(cmd string) { exec.Command("sh", "-c", cmd) }\n'
           'type Clean struct{}\nfunc (Clean) Run(cmd string) { _ = cmd }\n'
           'func handler(r *http.Request) { x := r.FormValue("cmd"); d := Dirty{}; d.Run(x) }\n')
    findings = _audit(tmp_path, "method_sink_dirty.go", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings


# ── launcher-prefix shell (deep-sweep wk01jvye5) ──
def test_launcher_prefix_shell_FIRES(tmp_path):
    """A launcher wrapper (sudo/env/timeout) before the real shell still runs a shell command —
    `exec.Command("sudo","sh","-c","ping "+x)` (was a silent FN)."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('func h(r *http.Request) { x := r.FormValue("c"); '
                   'exec.Command("sudo", "sh", "-c", "ping "+x) }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "lp.go", src))


def test_ping_count_flag_SILENT(tmp_path):
    """`exec.Command("ping","-c","4",host)` — ping's -c is COUNT, not a shell flag; no shell program is
    present, so this argv form must stay SILENT (the -c gate requires a shell to be present)."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('func h(r *http.Request) { host := r.FormValue("h"); '
                   'exec.Command("ping", "-c", "4", host) }\n')
    assert _audit(tmp_path, "pc.go", src) == []


# ── container/field write taint (deep-sweep wk01jvye5) ──
def test_map_write_taint_FIRES(tmp_path):
    """`m["c"] = r.FormValue("c")` — a map index write taints the container (IndexExpr LHS was dropped)."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('func h(r *http.Request) { m := map[string]string{}; '
                   'm["c"] = r.FormValue("c"); exec.Command("sh", "-c", m["c"]) }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "mw.go", src))


def test_struct_field_write_taint_FIRES(tmp_path):
    """`q.Cmd = r.FormValue("c")` — a struct-field write taints the struct (SelectorExpr LHS was dropped)."""
    if not _go_ok():
        pytest.skip("go bridge unavailable")
    src = _HEAD + ('type Q struct{ Cmd string }\n'
                   'func h(r *http.Request) { var q Q; q.Cmd = r.FormValue("c"); exec.Command("sh", "-c", q.Cmd) }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "sw.go", src))
