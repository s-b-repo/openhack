"""CROSS-LANGUAGE PROOF (Rust) — the trust/taint operator carries to Rust for OS command injection.
Operator called verbatim; the ingest builds the dep dict + source/sink sets from a native `syn` AST.
TOGGLE: `Command::new("sh").arg("-c").arg(format!("ping {}", env::args()...))` FIRES; the byte-identical
argv form `Command::new("ping").arg(target)` is SILENT.
"""
import shutil

import pytest

from lattice.ingest.rust_taint import rust_taint_audit, _BRIDGE


def _rust_ok() -> bool:
    return _BRIDGE.exists() and shutil.which("cargo") is not None


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return rust_taint_audit(p)


def test_rust_bridge_missing_source_is_an_explicit_failure(tmp_path):
    if not _rust_ok():
        pytest.skip("rust bridge unavailable")
    from lattice.bridge_runtime import BridgeRuntimeError
    from lattice.ingest.rust_taint import _parse

    with pytest.raises(BridgeRuntimeError, match="READ_ERROR"):
        _parse(tmp_path / "missing.rs")


def test_shell_form_env_args_FIRES(tmp_path):
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ("use std::process::Command;\nuse std::env;\n"
           "fn run() {\n"
           "    let target = env::args().nth(1).unwrap();\n"
           "    Command::new(\"sh\").arg(\"-c\").arg(format!(\"ping {}\", target)).output().unwrap();\n"
           "}\n")
    findings = _audit(tmp_path, "r.rs", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert "run" in {f["function"] for f in findings}


def test_argv_form_SILENT(tmp_path):
    """Command::new("ping").arg(target) — no shell, target is a single arg — cannot inject."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ("use std::process::Command;\nuse std::env;\n"
           "fn run() {\n"
           "    let target = env::args().nth(1).unwrap();\n"
           "    Command::new(\"ping\").arg(target).output().unwrap();\n"
           "}\n")
    assert _audit(tmp_path, "s.rs", src) == [], "argv form (no shell) cannot inject"


def test_toggle_is_genuine(tmp_path):
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    vuln = ("use std::process::Command;\nuse std::env;\n"
            "fn h(){ let x = env::var(\"X\").unwrap(); Command::new(\"bash\").arg(\"-c\").arg(x).output().unwrap(); }\n")
    safe = ("use std::process::Command;\nuse std::env;\n"
            "fn h(){ let x = env::var(\"X\").unwrap(); Command::new(\"echo\").arg(x).output().unwrap(); }\n")
    assert _audit(tmp_path, "v.rs", vuln) and not _audit(tmp_path, "sf.rs", safe)


def test_tainted_program_name_FIRES(tmp_path):
    """Command::new(user_bin) — the attacker chooses the binary."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ("use std::process::Command;\nuse std::env;\n"
           "fn run() {\n"
           "    let bin = env::args().nth(1).unwrap();\n"
           "    Command::new(bin).output().unwrap();\n"
           "}\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "p.rs", src))


def test_constant_shell_SILENT(tmp_path):
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ("use std::process::Command;\n"
           "fn cron(){ Command::new(\"sh\").arg(\"-c\").arg(\"backup --now\").output().unwrap(); }\n")
    assert _audit(tmp_path, "c.rs", src) == []


def test_operator_is_reused_verbatim():
    from lattice.taint import trust_obstructions
    deps = {"target": {"args"}}
    assert trust_obstructions(deps, sources={"args"}, sinks={"target"}, sanitizers=set())
    assert not trust_obstructions(deps, sources={"args"}, sinks={"target"}, sanitizers={"target"})


# ── idiom-sweep fixes (workflow ws6yh6pp7) ──
def test_interproc_helper_FIRES(tmp_path):
    """A helper wrapping Command::new("sh").arg("-c").arg(cmd), called with a tainted arg — one-hop
    sink-param summary must carry the taint across the call (was a silent FN)."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn sh(cmd: &str) { Command::new("sh").arg("-c").arg(cmd); }\n'
           'fn h() { let x = std::env::var("Q").unwrap(); sh(&x); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "ip.rs", src))


def test_combined_shell_flags_FIRES(tmp_path):
    """Guard: `bash -lc` (combined POSIX flags) already fires in Rust because shell_mode keys on the
    program being a shell, independent of the exact flag literal — lock that in."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn h() { let x = std::env::var("Q").unwrap(); '
           'Command::new("bash").arg("-lc").arg(format!("ping {}", x)); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "cf.rs", src))


def test_launcher_env_prefix_FIRES(tmp_path):
    """A launcher prefix smuggles the shell into the arg list: Command::new("env").arg("sh").arg("-c")
    .arg(format!("ping {}", x)). The program literal is 'env' (not a shell) so the old shell_mode missed
    the tainted arg — a silent FN. shell_mode must also trigger on a shell literal + a shell-flag literal
    appearing in the arg list."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\nuse std::env;\n'
           'fn run() {\n'
           '    let x = env::args().nth(1).unwrap();\n'
           '    Command::new("env").arg("sh").arg("-c").arg(format!("ping {}", x)).output().unwrap();\n'
           '}\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "le.rs", src))


def test_launcher_env_prefix_constant_SILENT(tmp_path):
    """The same launcher prefix with a CONSTANT command (no tainted name) stays SILENT — the gate is the
    taint, not shell_mode alone."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn cron(){ Command::new("env").arg("sh").arg("-c").arg("backup --now").output().unwrap(); }\n')
    assert _audit(tmp_path, "lec.rs", src) == []


def test_launcher_env_no_shell_flag_SILENT(tmp_path):
    """`env MYVAR=1 ping x` — launcher with a tainted arg but NO shell name + NO -c flag — stays SILENT
    (the program ultimately exec'd is `ping`, argv form, no shell interpretation)."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\nuse std::env;\n'
           'fn run(){ let x = env::args().nth(1).unwrap(); '
           'Command::new("env").arg("MYVAR=1").arg("ping").arg(x).output().unwrap(); }\n')
    assert _audit(tmp_path, "lenf.rs", src) == []


# ── cross-file interprocedural (deep-sweep wk01jvye5) ──
def test_crossfile_interproc_helper_FIRES(tmp_path):
    """Sink-wrapping helper in helper.rs, tainted caller in main.rs — auditing the DIRECTORY must carry
    taint across the file boundary (per-file sink-param map was a silent FN)."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    (tmp_path / "helper.rs").write_text(
        'use std::process::Command;\n'
        'fn sh(cmd: &str) { Command::new("sh").arg("-c").arg(cmd); }\n')
    (tmp_path / "main.rs").write_text(
        'fn h() { let x = std::env::var("Q").unwrap(); crate::sh(&x); }\n')
    findings = rust_taint_audit(tmp_path)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert any(f.get("file") == "main.rs" for f in findings)


# ── variable-held shell + argv-count guard (deep-sweep wk01jvye5) ──
def test_shell_in_var_FIRES(tmp_path):
    """Shell program held in a variable — `let sh="/bin/sh"; Command::new(sh).arg("-c").arg(...)`. The
    `-c` flag is the discriminator when the program literal is unknown (was a silent FN)."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn h() { let x = std::env::var("Q").unwrap(); let sh = "/bin/sh"; '
           'Command::new(sh).arg("-c").arg(format!("ping {}", x)); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "sv.rs", src))


def test_argv_count_flag_SILENT(tmp_path):
    """`Command::new("ping").arg("-c").arg("4").arg(host)` — ping's -c is COUNT, no shell present, argv
    form, must stay SILENT (the -c gate requires a shell or a variable program)."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn h() { let host = std::env::var("H").unwrap(); '
           'Command::new("ping").arg("-c").arg("4").arg(host); }\n')
    assert _audit(tmp_path, "ac.rs", src) == []


# ── string-builder, destructuring, real sanitizer (deep-sweep wk01jvye5) ──
def test_string_builder_push_FIRES(tmp_path):
    """`let mut c=String::from("ping "); c.push_str(&x)` — the push_str mutation must accumulate taint into
    the receiver (was a silent FN: a mutating method was only a Call, never an assign)."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn h() { let x = std::env::var("Q").unwrap(); let mut c = String::from("ping "); '
           'c.push_str(&x); Command::new("sh").arg("-c").arg(c); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "sb.rs", src))


def test_tuple_unpack_FIRES(tmp_path):
    """`let (cmd, _f) = (env::var("C").unwrap(), 1)` — a tuple-destructuring let must bind cmd (Pat::Tuple
    was dropped entirely)."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn h() { let (cmd, _f) = (std::env::var("C").unwrap(), 1); '
           'Command::new("sh").arg("-c").arg(cmd); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "tu.rs", src))


def test_real_shell_sanitizer_SILENT(tmp_path):
    """`let safe = shell_escape::escape(raw.into())` genuinely neutralizes the shell — must stay silent."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn h() { let raw = std::env::var("Q").unwrap(); '
           'let safe = shell_escape::escape(raw.into()); Command::new("sh").arg("-c").arg(safe.to_string()); }\n')
    assert _audit(tmp_path, "rss.rs", src) == []


def test_interproc_two_hop_FIRES(tmp_path):
    """Transitive interproc: h -> mid -> sh(sink). The one-hop summary missed the middle hop (silent FN);
    a fixpoint makes mid a sink-wrapper too."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn sh(c: &str) { Command::new("sh").arg("-c").arg(c); }\n'
           'fn mid(c: &str) { sh(c); }\n'
           'fn h() { let x = std::env::var("Q").unwrap(); mid(&x); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "2h.rs", src))


# ── return-value taint laundering (parity with go/ruby/c — deep-sweep wk01jvye5) ──
def test_return_value_source_implicit_FIRES(tmp_path):
    """A helper that reads a source and returns it via the IMPLICIT trailing expression — THE Rust
    idiom — then the caller shells the result. The source is hidden in get()'s body (was a silent FN:
    the rust bridge emitted no `returns`, so rust_taint had no return-taint summary at all)."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn get() -> String { std::env::var("C").unwrap() }\n'
           'fn h() { let v = get(); Command::new("sh").arg("-c").arg(v); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "rv.rs", src))


def test_return_value_source_explicit_FIRES(tmp_path):
    """Same laundering through an EXPLICIT `return` statement — both return forms must carry."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn get() -> String { return std::env::var("C").unwrap(); }\n'
           'fn h() { let v = get(); Command::new("sh").arg("-c").arg(v); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "rve.rs", src))


def test_return_constant_SILENT(tmp_path):
    """A helper that returns a CONSTANT must not mark its callers tainted (return-taint stays gated)."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'fn get() -> String { "localhost".to_string() }\n'
           'fn h() { let v = get(); Command::new("sh").arg("-c").arg(format!("ping {}", v)); }\n')
    assert _audit(tmp_path, "rc.rs", src) == []


# ── impl-block methods ──
def test_impl_method_FIRES(tmp_path):
    """A method INSIDE an impl block — `impl S { fn run(&self){ …Command::new("sh")… } }` — was entirely
    invisible to the bridge (only free ItemFns were emitted): a silent FN for the dominant Rust
    code-organization idiom."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'struct S;\n'
           'impl S {\n'
           '    fn run(&self) { let x = std::env::var("Q").unwrap(); '
           'Command::new("sh").arg("-c").arg(format!("ping {}", x)); }\n'
           '}\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "im.rs", src))


def test_impl_method_return_source_FIRES(tmp_path):
    """Return-taint laundering through a METHOD: `impl S { fn get(&self) -> String { env::var(..) } }`
    feeding a free caller — the method must both be emitted AND join the return-source set."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'struct S;\n'
           'impl S {\n'
           '    fn get(&self) -> String { std::env::var("C").unwrap() }\n'
           '}\n'
           'fn h(s: &S) { let v = s.get(); Command::new("sh").arg("-c").arg(v); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "imr.rs", src))


def test_duplicate_impl_return_names_do_not_cross_contaminate(tmp_path):
    """A tainted ``Dirty::load`` summary must not make the unrelated clean ``Clean::load`` a source."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'struct Dirty; struct Clean;\n'
           'impl Dirty { fn load() -> String { std::env::var("C").unwrap() } }\n'
           'impl Clean { fn load() -> String { "localhost".to_string() } }\n'
           'fn h() { let v = Clean::load(); Command::new("sh").arg("-c").arg(v); }\n')
    assert _audit(tmp_path, "collision.rs", src) == []


def test_qualified_duplicate_impl_return_source_still_fires(tmp_path):
    """Collision safety preserves a statically-qualified call to the genuinely tainted method."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'struct Dirty; struct Clean;\n'
           'impl Dirty { fn load() -> String { std::env::var("C").unwrap() } }\n'
           'impl Clean { fn load() -> String { "localhost".to_string() } }\n'
           'fn h() { let v = Dirty::load(); Command::new("sh").arg("-c").arg(v); }\n')
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "qualified.rs", src))


def test_duplicate_inline_module_helper_does_not_hide_qualified_sink(tmp_path):
    """An unrelated same-named helper in another module must not suppress ``a::sh``."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    src = ('use std::process::Command;\n'
           'mod a { use super::Command; pub fn sh(cmd: &str) { '
           'Command::new("sh").arg("-c").arg(cmd); } }\n'
           'mod b { pub fn sh(cmd: &str) { println!("{}", cmd); } }\n'
           'fn main() { let x = std::env::var("Q").unwrap(); a::sh(&x); }\n')

    findings = _audit(tmp_path, "inline_modules.rs", src)

    assert any(f["kind"] == "command_injection" and f["function"] == "main"
               for f in findings), findings


def test_duplicate_helpers_in_separate_modules_do_not_hide_qualified_sink(tmp_path):
    """File-module identity keeps ``a::sh`` usable when ``b::sh`` is unrelated."""
    if not _rust_ok():
        pytest.skip("rust bridge not built")
    (tmp_path / "a.rs").write_text(
        'use std::process::Command;\n'
        'pub fn sh(cmd: &str) { Command::new("sh").arg("-c").arg(cmd); }\n')
    (tmp_path / "b.rs").write_text(
        'pub fn sh(cmd: &str) { println!("{}", cmd); }\n')
    (tmp_path / "main.rs").write_text(
        'fn main() { let x = std::env::var("Q").unwrap(); crate::a::sh(&x); }\n')

    findings = rust_taint_audit(tmp_path)

    assert any(f["kind"] == "command_injection" and f["function"] == "main"
               for f in findings), findings


def test_duplicate_helpers_in_workspace_crates_do_not_hide_qualified_sink(tmp_path):
    """Each workspace member's crate root remains distinct under a directory-wide audit."""
    for crate in ("crate_a", "crate_b"):
        (tmp_path / crate / "src").mkdir(parents=True)
        (tmp_path / crate / "Cargo.toml").write_text(
            f'[package]\nname = "{crate}"\nversion = "0.1.0"\nedition = "2021"\n')
    (tmp_path / "crate_a" / "src" / "lib.rs").write_text(
        'use std::process::Command;\n'
        'pub fn sh(cmd: &str) { Command::new("sh").arg("-c").arg(cmd); }\n'
        'pub fn run() { let x = std::env::var("Q").unwrap(); crate::sh(&x); }\n')
    (tmp_path / "crate_b" / "src" / "lib.rs").write_text(
        'pub fn sh(cmd: &str) { println!("{}", cmd); }\n')

    findings = rust_taint_audit(tmp_path)

    assert any(f["kind"] == "command_injection" and f["function"] == "crate_a::run"
               for f in findings), findings
