"""CROSS-LANGUAGE PROOF (C / C++) — the trust/taint operator carries to C/C++ for OS command injection.
Operator called verbatim; the ingest builds the dep dict + source/sink sets from the NATIVE Clang AST.
The TOGGLE: `host = getenv(...); sprintf(cmd, "ping %s", host); system(cmd)` FIRES; the same with a
CONSTANT command is SILENT. The string-builder (sprintf/strcpy) must carry taint from host into cmd.
"""
import shutil

import pytest

from lattice.ingest.c_taint import c_taint_audit


def _clang_ok() -> bool:
    return shutil.which("clang") is not None


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return c_taint_audit(p)


def test_getenv_sprintf_system_FIRES(tmp_path):
    if not _clang_ok():
        pytest.skip("clang not available")
    src = ("#include <stdlib.h>\n#include <stdio.h>\n"
           "void handler(void) {\n"
           "    char *host = getenv(\"HOST\");\n"
           "    char cmd[256];\n"
           "    sprintf(cmd, \"ping %s\", host);\n"
           "    system(cmd);\n"
           "}\n")
    findings = _audit(tmp_path, "h.c", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert "handler" in {f["function"] for f in findings}


def test_constant_command_SILENT(tmp_path):
    if not _clang_ok():
        pytest.skip("clang not available")
    src = ("#include <stdlib.h>\n"
           "void cron(void) {\n"
           "    system(\"backup --now\");\n"
           "}\n")
    assert _audit(tmp_path, "c.c", src) == [], "a constant command is not injection"


def test_toggle_is_genuine(tmp_path):
    if not _clang_ok():
        pytest.skip("clang not available")
    vuln = ("#include <stdlib.h>\n#include <stdio.h>\n"
            "void h(void){ char *x=getenv(\"X\"); char b[128]; strcpy(b,\"echo \"); strcat(b,x); system(b); }\n")
    safe = ("#include <stdlib.h>\n#include <stdio.h>\n"
            "void h(void){ char b[128]; strcpy(b,\"echo hi\"); system(b); }\n")
    assert _audit(tmp_path, "v.c", vuln) and not _audit(tmp_path, "s.c", safe)


def test_popen_FIRES(tmp_path):
    if not _clang_ok():
        pytest.skip("clang not available")
    src = ("#include <stdlib.h>\n#include <stdio.h>\n#include <string.h>\n"
           "void run(void) {\n"
           "    char *q = getenv(\"QUERY_STRING\");\n"
           "    char cmd[256];\n"
           "    snprintf(cmd, sizeof(cmd), \"grep %s log\", q);\n"
           "    FILE *p = popen(cmd, \"r\");\n"
           "}\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "p.c", src))


def test_cpp_string_concat_system_FIRES(tmp_path):
    """C++: std::string command built by concatenation from getenv, into std::system."""
    if shutil.which("clang++") is None:
        pytest.skip("clang++ not available")
    src = ("#include <cstdlib>\n#include <string>\n"
           "void handler() {\n"
           "    std::string host = std::getenv(\"HOST\");\n"
           "    std::string cmd = \"ping \" + host;\n"
           "    std::system(cmd.c_str());\n"
           "}\n")
    findings = _audit(tmp_path, "h.cpp", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings


def test_operator_is_reused_verbatim():
    from lattice.taint import trust_obstructions
    deps = {"cmd": {"host"}, "host": {"getenv"}}
    assert trust_obstructions(deps, sources={"getenv"}, sinks={"cmd"}, sanitizers=set())
    assert not trust_obstructions(deps, sources={"getenv"}, sinks={"cmd"}, sanitizers={"host"})


def test_partial_parse_emits_blindspot(tmp_path):
    """A missing project header -> clang gives a PARTIAL AST -> the file must surface a 'parse_incomplete'
    blind-spot, not be silently reported clean (SILENCE != proof)."""
    if not _clang_ok():
        pytest.skip("clang not available")
    src = ("#include \"no_such_header_zzz.h\"\n"
           "void f(void) { int x = 1; }\n")
    findings = _audit(tmp_path, "partial.c", src)
    assert any(f.get("kind") == "parse_incomplete" for f in findings), \
        f"partial parse must escalate a blind-spot, got {findings}"


def test_sibling_header_resolves_no_blindspot(tmp_path):
    """A header in the file's OWN directory must resolve (the -I<file_dir> heuristic, redis's layout) — the
    file parses fully (no blind-spot) and the command-injection is still found."""
    if not _clang_ok():
        pytest.skip("clang not available")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "util.h").write_text("#ifndef UTIL_H\n#define UTIL_H\nint helper(void);\n#endif\n")
    (proj / "app.c").write_text(
        "#include <stdlib.h>\n#include <stdio.h>\n#include \"util.h\"\n"
        "void handler(void){ char *h=getenv(\"H\"); char c[128]; sprintf(c,\"ping %s\",h); system(c); }\n")
    findings = c_taint_audit(proj)
    assert not any(f.get("kind") == "parse_incomplete" for f in findings), \
        f"sibling header should resolve (no blind-spot): {findings}"
    assert any(f.get("kind") == "command_injection" for f in findings), findings


# ── idiom-sweep fixes (workflow ws6yh6pp7) ──
def test_interproc_helper_FIRES(tmp_path):
    """A helper wrapping system(c), called with a tainted arg — one-hop sink-param summary must carry the
    taint across the call (was a silent FN; the Python/Go/Rust fix ported to C)."""
    if not _clang_ok():
        pytest.skip("clang not available")
    src = ("#include <stdlib.h>\n#include <unistd.h>\n"
           "void sh(char *c) { system(c); }\n"
           "void handler(void) { char *x = getenv(\"Q\"); sh(x); }\n")
    findings = _audit(tmp_path, "ip.c", src)
    assert any(f["kind"] == "command_injection" for f in findings), findings


# ── cross-file interprocedural (deep-sweep wk01jvye5) ──
def test_crossfile_interproc_helper_FIRES(tmp_path):
    """Sink-wrapping helper in helper.c, tainted caller in main.c — auditing the DIRECTORY must carry
    taint across the file boundary (per-file sink-param map was a silent FN)."""
    if not _clang_ok():
        pytest.skip("clang not available")
    (tmp_path / "helper.c").write_text(
        "#include <stdlib.h>\nvoid sh(char *c) { system(c); }\n")
    (tmp_path / "main.c").write_text(
        "#include <stdlib.h>\nvoid sh(char *c);\n"
        "void handler(void) { char *x = getenv(\"Q\"); sh(x); }\n")
    findings = c_taint_audit(tmp_path)
    assert any(f["kind"] == "command_injection" for f in findings), findings
    assert any(f.get("file") == "main.c" for f in findings)


def test_same_translation_unit_helper_survives_unrelated_static_duplicate(tmp_path):
    """A static helper in another translation unit cannot suppress or receive a local summary."""
    if not _clang_ok():
        pytest.skip("clang not available")
    (tmp_path / "vulnerable.c").write_text(
        "#include <stdlib.h>\n"
        "static void sh(char *cmd) { system(cmd); }\n"
        "void handler(void) { char *cmd = getenv(\"CMD\"); sh(cmd); }\n")
    (tmp_path / "clean.c").write_text(
        "#include <stdlib.h>\n"
        "static void sh(char *cmd) { (void)cmd; }\n"
        "void other(void) { char *cmd = getenv(\"CMD\"); sh(cmd); }\n")

    findings = c_taint_audit(tmp_path)
    command_files = {f.get("file") for f in findings if f.get("kind") == "command_injection"}
    assert "vulnerable.c" in command_files, findings
    assert "clean.c" not in command_files, findings


# ── out-parameter sources + return-taint (deep-sweep wk01jvye5) ──
def test_recv_outparam_source_FIRES(tmp_path):
    """recv() WRITES attacker bytes into a buffer ARGUMENT (it does not return them) — the buffer must be
    tainted. These network/stdin out-param sources were dead (silent FN on a whole input class)."""
    if not _clang_ok():
        pytest.skip("clang not available")
    src = ("#include <stdlib.h>\n#include <stdio.h>\n#include <sys/socket.h>\n"
           "void h(int sock) {\n"
           "    char buf[256];\n"
           "    recv(sock, buf, 255, 0);\n"
           "    char cmd[512];\n"
           "    sprintf(cmd, \"ping %s\", buf);\n"
           "    system(cmd);\n}\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "rv.c", src))


def test_fgets_outparam_source_FIRES(tmp_path):
    """fgets(buf, n, stdin) writes into buf (arg 0) — buf is attacker-controlled."""
    if not _clang_ok():
        pytest.skip("clang not available")
    src = ("#include <stdio.h>\n#include <stdlib.h>\n"
           "void h(void) {\n"
           "    char buf[256];\n"
           "    fgets(buf, 255, stdin);\n"
           "    system(buf);\n}\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "fg.c", src))


def test_return_source_helper_FIRES(tmp_path):
    """A helper that returns an attacker source — `char* get_host(){ return getenv(\"H\"); }` — taints its
    caller's result (return-taint summary)."""
    if not _clang_ok():
        pytest.skip("clang not available")
    src = ("#include <stdlib.h>\n#include <stdio.h>\n#include <string.h>\n"
           "char* get_host(void) { return getenv(\"HOST\"); }\n"
           "void h(void) {\n"
           "    char *host = get_host();\n"
           "    char cmd[512];\n"
           "    sprintf(cmd, \"ping %s\", host);\n"
           "    system(cmd);\n}\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "rs.c", src))


def test_duplicate_static_return_source_does_not_taint_clean_file(tmp_path):
    """A file-local dirty `load` must not taint another translation unit's clean `load`."""
    if not _clang_ok():
        pytest.skip("clang not available")
    (tmp_path / "dirty.c").write_text(
        '#include <stdlib.h>\n'
        'static char *load(void) { return getenv("CMD"); }\n')
    (tmp_path / "clean.c").write_text(
        '#include <stdlib.h>\n'
        'static char *load(void) { return "safe"; }\n'
        'void handler(void) { char *value = load(); system(value); }\n')
    assert c_taint_audit(tmp_path) == []


def test_same_translation_unit_return_source_survives_static_duplicate(tmp_path):
    if not _clang_ok():
        pytest.skip("clang not available")
    (tmp_path / "dirty.c").write_text(
        '#include <stdlib.h>\n'
        'static char *load(void) { return getenv("CMD"); }\n'
        'void handler(void) { char *value = load(); system(value); }\n')
    (tmp_path / "clean.c").write_text(
        '#include <stdlib.h>\n'
        'static char *load(void) { return "safe"; }\n'
        'void other(void) { char *value = load(); system(value); }\n')

    findings = c_taint_audit(tmp_path)
    command_files = {f.get("file") for f in findings if f.get("kind") == "command_injection"}
    assert "dirty.c" in command_files, findings
    assert "clean.c" not in command_files, findings


def test_interproc_two_hop_FIRES(tmp_path):
    """Transitive interproc: handler -> mid -> sh(system). The one-hop summary missed the middle hop."""
    if not _clang_ok():
        pytest.skip("clang not available")
    src = ("#include <stdlib.h>\n#include <unistd.h>\n"
           "void sh(char *c) { system(c); }\n"
           "void mid(char *c) { sh(c); }\n"
           "void handler(void) { char *x = getenv(\"Q\"); mid(x); }\n")
    assert any(f["kind"] == "command_injection" for f in _audit(tmp_path, "2h.c", src))
