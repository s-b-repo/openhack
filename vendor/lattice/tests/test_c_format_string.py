"""FIRES / SILENT / toggle triple for C CWE-134 uncontrolled format string.

New attack class in the accuracy sweep — mirrors tests/test_c_taint.py. Toggle:
the two files differ ONLY by whether the format arg is a string literal (safe)
or a tainted variable (vulnerable). The `_is_string_literal` shape check is what
distinguishes them, so the toggle depth is exactly `%s` vs `<var>`.
"""
import shutil

import pytest

from lattice.ingest.c_taint import c_taint_audit


pytestmark = pytest.mark.skipif(shutil.which("clang") is None,
                                reason="clang not installed")


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return [f for f in c_taint_audit(p) if f["kind"] == "format_string"]


# ── the core FIRES / SILENT / toggle triple ───────────────────────────────────

def test_printf_tainted_format_FIRES(tmp_path):
    src = ("#include <stdio.h>\n"
           "#include <stdlib.h>\n"
           "int main(void){\n"
           "    char *n = getenv(\"NAME\");\n"
           "    printf(n);\n"
           "    return 0;\n"
           "}\n")
    findings = _audit(tmp_path, "vuln.c", src)
    assert findings, "printf(tainted) must fire CWE-134"
    assert findings[0]["cwe"] == "CWE-134"


def test_printf_literal_format_SILENT(tmp_path):
    src = ("#include <stdio.h>\n"
           "#include <stdlib.h>\n"
           "int main(void){\n"
           "    char *n = getenv(\"NAME\");\n"
           "    printf(\"%s\", n);\n"
           "    return 0;\n"
           "}\n")
    assert _audit(tmp_path, "safe.c", src) == [], "printf(\"%s\", var) is safe"


def test_toggle_is_genuine(tmp_path):
    vuln = ("#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "int main(void){\n"
            "    char *n = getenv(\"X\");\n"
            "    fprintf(stderr, n);\n"
            "    return 0;\n"
            "}\n")
    safe = ("#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "int main(void){\n"
            "    char *n = getenv(\"X\");\n"
            "    fprintf(stderr, \"%s\", n);\n"
            "    return 0;\n"
            "}\n")
    assert _audit(tmp_path, "v.c", vuln)
    assert not _audit(tmp_path, "s.c", safe)


# ── additional printf-family shapes ──────────────────────────────────────────

def test_fprintf_tainted_format_FIRES(tmp_path):
    src = ("#include <stdio.h>\n"
           "#include <stdlib.h>\n"
           "int main(void){\n"
           "    char *n = getenv(\"X\");\n"
           "    fprintf(stderr, n);\n"
           "    return 0;\n"
           "}\n")
    assert _audit(tmp_path, "v.c", src)


def test_snprintf_tainted_format_FIRES(tmp_path):
    src = ("#include <stdio.h>\n"
           "#include <stdlib.h>\n"
           "int main(void){\n"
           "    char buf[64];\n"
           "    char *n = getenv(\"X\");\n"
           "    snprintf(buf, sizeof(buf), n);\n"
           "    return 0;\n"
           "}\n")
    assert _audit(tmp_path, "v.c", src), "snprintf tainted format must fire"


def test_snprintf_literal_format_SILENT(tmp_path):
    src = ("#include <stdio.h>\n"
           "#include <stdlib.h>\n"
           "int main(void){\n"
           "    char buf[64];\n"
           "    char *n = getenv(\"X\");\n"
           "    snprintf(buf, sizeof(buf), \"%s\", n);\n"
           "    return 0;\n"
           "}\n")
    assert _audit(tmp_path, "safe.c", src) == []


def test_syslog_tainted_format_FIRES(tmp_path):
    src = ("#include <syslog.h>\n"
           "#include <stdlib.h>\n"
           "int main(void){\n"
           "    char *n = getenv(\"X\");\n"
           "    syslog(0, n);\n"
           "    return 0;\n"
           "}\n")
    assert _audit(tmp_path, "v.c", src), "syslog tainted format must fire"


def test_untainted_variable_format_SILENT(tmp_path):
    """A non-literal format that isn't reachable from a source is not CWE-134 —
    zero-taint stays silent even when the operator sees a non-literal shape."""
    src = ("#include <stdio.h>\n"
           "int main(void){\n"
           "    const char *fmt = \"hello %s\";\n"
           "    printf(fmt, \"world\");\n"
           "    return 0;\n"
           "}\n")
    assert _audit(tmp_path, "safe.c", src) == []


def test_recv_source_printf_FIRES(tmp_path):
    """Network-sourced format string — recv() is an out-param source that taints buf."""
    src = ("#include <stdio.h>\n"
           "#include <sys/socket.h>\n"
           "void h(int s){\n"
           "    char buf[128];\n"
           "    recv(s, buf, 128, 0);\n"
           "    printf(buf);\n"
           "}\n")
    assert _audit(tmp_path, "v.c", src)


def test_command_and_format_both_reported(tmp_path):
    src = ("#include <stdio.h>\n"
           "#include <stdlib.h>\n"
           "int main(void){\n"
           "    char *n = getenv(\"X\");\n"
           "    char cmd[128];\n"
           "    sprintf(cmd, \"ping %s\", n);\n"
           "    printf(n);\n"
           "    system(cmd);\n"
           "    return 0;\n"
           "}\n")
    p = tmp_path / "both.c"
    p.write_text(src)
    kinds = {f["kind"] for f in c_taint_audit(p)}
    assert "command_injection" in kinds
    assert "format_string" in kinds
