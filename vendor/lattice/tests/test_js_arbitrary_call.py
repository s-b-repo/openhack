"""CROSS-LANGUAGE PROOF (JS/TS) — the arbitrary-call detector ported from solidity_arbitrary_call.py.
Same trust/taint OPERATOR (lattice.taint.trust_obstructions) called VERBATIM; only the ingest is new
(a Babel AST via the tools/jsast bridge instead of the solc AST). This is the JS analog of DVD `truster`:
the call TARGET derives from untrusted input, so the attacker chooses what runs.

SOLIDITY -> JS mapping (the port):
  address-parameter source        -> request object (req/request/ctx/event) + argv
  X.call/.delegatecall(...) sink   -> dynamic-dispatch `obj[KEY](...)`, `eval/require/Function/import(X)`
  fixed state-var target SILENT    -> constant key `handlers['delete']` SILENT
  (sanitizer)                      -> a validate()/allowlist wrap on the key SILENT

The load-bearing TOGGLE: `handlers[req.body.op]()` FIRES; the byte-identical `handlers['delete']()`
(constant key) and `handlers[validate(req.body.op)]()` (sanitized key) are SILENT — differing ONLY in
the source->target path, exactly the Solidity discipline.
"""
import shutil

import pytest

from lattice.ingest.js_arbitrary_call import js_arbitrary_call_audit
from lattice.taint import trust_obstructions  # the operator the ingest calls VERBATIM


def _node_ok() -> bool:
    return shutil.which("node") is not None


def _audit(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return js_arbitrary_call_audit(p)


# ---------------------------------------------------------------- the load-bearing TOGGLE

def test_dynamic_dispatch_tainted_key_FIRES(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    src = ("function route(req, res) {\n"
           "  handlers[req.body.op]();\n"
           "}\n")
    findings = _audit(tmp_path, "vuln.js", src)
    assert "arbitrary_call" in [f["kind"] for f in findings], findings
    assert "route" in {f["function"] for f in findings}


def test_constant_key_SILENT(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    src = ("function route(req, res) {\n"
           "  handlers['delete']();\n"
           "}\n")
    assert _audit(tmp_path, "const.js", src) == [], "a constant dispatch key is not attacker-chosen"


def test_validated_key_SILENT(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    src = ("function route(req, res) {\n"
           "  handlers[validate(req.body.op)]();\n"
           "}\n")
    assert _audit(tmp_path, "valid.js", src) == [], "a validate()-sanitized key must not fire"


def test_toggle_is_genuine(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    vuln = "function r(req){ handlers[req.body.op](); }\n"
    safe = "function r(req){ handlers['delete'](); }\n"
    assert _audit(tmp_path, "v.js", vuln) and not _audit(tmp_path, "s.js", safe)


# ---------------------------------------------------------------- the code-exec sinks

def test_require_tainted_FIRES(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    src = "function load(req){ const m = require(req.query.plugin); return m; }\n"
    assert any(f["kind"] == "arbitrary_call" for f in _audit(tmp_path, "req.js", src))


def test_new_Function_tainted_FIRES(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    src = "function build(req){ const f = new Function(req.body.code); return f; }\n"
    findings = _audit(tmp_path, "fn.js", src)
    assert any(f["kind"] == "arbitrary_call" for f in findings)
    assert any(f["severity"] == "critical" for f in findings)   # code-construction is critical


def test_eval_tainted_FIRES(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    src = "function run(req){ eval(req.body.x); }\n"
    assert any(f["kind"] == "arbitrary_call" for f in _audit(tmp_path, "eval.js", src))


def test_constant_require_SILENT(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    src = "function load(){ const fs = require('fs'); return fs; }\n"
    assert _audit(tmp_path, "constreq.js", src) == [], "require of a string literal is not arbitrary"


# ---------------------------------------------------------------- taint laundering + scope

def test_laundered_key_FIRES(tmp_path):
    """The key is bound to a local first (the most common real shape) — must still fire."""
    if not _node_ok():
        pytest.skip("node not available")
    src = ("function route(req){\n"
           "  const op = req.body.op;\n"
           "  handlers[op]();\n"
           "}\n")
    assert any(f["kind"] == "arbitrary_call" for f in _audit(tmp_path, "laundered.js", src))


def test_argv_dispatch_FIRES(tmp_path):
    """CLI source: process.argv chosen command, module-level (no function) — fires at <module>."""
    if not _node_ok():
        pytest.skip("node not available")
    src = ("const cmd = process.argv[2];\n"
           "commands[cmd]();\n")
    assert any(f["kind"] == "arbitrary_call" for f in _audit(tmp_path, "cli.js", src))


def test_request_but_no_dynamic_call_SILENT(tmp_path):
    """A handler that reads req but makes no dynamic call must stay silent (no FP on every handler)."""
    if not _node_ok():
        pytest.skip("node not available")
    src = "function route(req, res){ const x = req.body.op; res.send(x); }\n"
    assert _audit(tmp_path, "noop.js", src) == []


# ---------------------------------------------------------------- TypeScript parses too

def test_typescript_dispatch_FIRES(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    src = ("function route(req: Request, res: Response): void {\n"
           "  const op: string = req.body.op;\n"
           "  handlers[op]();\n"
           "}\n")
    assert any(f["kind"] == "arbitrary_call" for f in _audit(tmp_path, "vuln.ts", src))


# ---------------------------------------------------------------- the operator carry

def test_arrow_assigned_to_member_recovers_name(tmp_path):
    """Real Node/Express code assigns arrow handlers to a member (the OWASP NodeGoat shape:
    `this.handleUpdate = (req, res) => {...}`), not named `function` declarations. The finding must
    recover the binding name, not report '<anonymous>' (triage needs the function name)."""
    if not _node_ok():
        pytest.skip("node not available")
    src = ("module.exports = function(){\n"
           "  this.handleUpdate = (req, res) => { eval(req.body.x); };\n"
           "};\n")
    findings = _audit(tmp_path, "handler.js", src)
    assert any(f["kind"] == "arbitrary_call" for f in findings), findings
    assert "handleUpdate" in {f["function"] for f in findings}, findings


def test_const_arrow_recovers_name(tmp_path):
    """`const route = (req) => handlers[req.body.op]()` -> name 'route', not '<anonymous>'."""
    if not _node_ok():
        pytest.skip("node not available")
    src = "const route = (req) => { handlers[req.body.op](); };\n"
    assert "route" in {f["function"] for f in _audit(tmp_path, "ca.js", src)}


# ── adversarial-verification fixes (workflow w2iuqm74n) ──

def test_child_process_exec_FIRES(tmp_path):
    """The canonical Node RCE: req.body.* into child_process.exec/spawn — must fire."""
    if not _node_ok():
        pytest.skip("node not available")
    src = ("const cp = require('child_process');\n"
           "function run(req){ cp.exec('git ' + req.body.subcommand); }\n")
    f = _audit(tmp_path, "cp.js", src)
    assert any(x["kind"] == "arbitrary_call" and x["severity"] == "critical" for x in f), f


def test_child_process_destructured_spawn_FIRES(tmp_path):
    if not _node_ok():
        pytest.skip("node not available")
    src = ("const { spawn } = require('child_process');\n"
           "function run(req){ spawn(req.body.bin, req.body.args); }\n")
    assert any(x["kind"] == "arbitrary_call" for x in _audit(tmp_path, "spawn.js", src))


def test_abbreviated_request_param_FIRES(tmp_path):
    """Real handlers abbreviate the request param (r, ctx, httpReq) — usage (`.body`) makes it a source,
    not the exact spelling 'req'."""
    if not _node_ok():
        pytest.skip("node not available")
    for src in ("function route(r, res){ eval(r.body.code); }\n",
                "const h = (ctx) => { handlers[ctx.params.op](); };\n",
                "function route(httpReq, res){ require(httpReq.query.plugin); }\n"):
        assert _audit(tmp_path, "a.js", src), f"abbreviated request param should fire: {src!r}"


def test_shadowing_source_name_SILENT(tmp_path):
    """FP fix: a local merely NAMED like a source but bound to a non-request value must not fire."""
    if not _node_ok():
        pytest.skip("node not available")
    src = "function tick(){ let request = 0; callbacks[request](); }\n"
    assert _audit(tmp_path, "shadow.js", src) == [], "a shadowing local named 'request' must not fire"


def test_loopvar_named_req_SILENT(tmp_path):
    """FP fix: a callback param named 'req' that is NOT a request (no .body/.query access) is silent."""
    if not _node_ok():
        pytest.skip("node not available")
    src = "function go(){ records.forEach(function(req){ table[req.id](); }); }\n"
    assert _audit(tmp_path, "loop.js", src) == [], "a non-request var named 'req' must not fire"


def test_iterator_callback_taint_FIRES(tmp_path):
    """One hop across a callback boundary: elements of a tainted array reach the dispatch key."""
    if not _node_ok():
        pytest.skip("node not available")
    src = "function route(req){ req.body.ops.forEach(op => handlers[op]()); }\n"
    assert any(x["kind"] == "arbitrary_call" for x in _audit(tmp_path, "iter.js", src))


def test_fake_sanitizer_escape_FIRES(tmp_path):
    """escape()/encodeURIComponent()/lookup() do NOT sanitize a code-exec sink — must still fire."""
    if not _node_ok():
        pytest.skip("node not available")
    for src in ("function r(req){ eval(escape(req.body.code)); }\n",
                "function r(req){ require(encodeURIComponent(req.query.p)); }\n",
                "function r(req){ handlers[lookup(req.body.op)](); }\n"):
        assert _audit(tmp_path, "fk.js", src), f"fake sanitizer must not silence: {src!r}"


def test_real_sanitizer_still_SILENT(tmp_path):
    """A genuine allow-list/validation sanitizer must still silence (the toggle stays honest)."""
    if not _node_ok():
        pytest.skip("node not available")
    src = "function r(req){ handlers[validate(req.body.op)](); }\n"
    assert _audit(tmp_path, "rs.js", src) == []


def test_vm_Script_construction_FIRES(tmp_path):
    """new vm.Script(req.body.code) compiles attacker code — must fire critical."""
    if not _node_ok():
        pytest.skip("node not available")
    src = ("const vm = require('vm');\n"
           "function run(req){ const s = new vm.Script(req.body.code); s.runInThisContext(); }\n")
    assert any(x["severity"] == "critical" for x in _audit(tmp_path, "vm.js", src))


def test_interprocedural_helper_sink_FIRES(tmp_path):
    """req -> caller -> helper(arg) -> eval(arg): the sink is wrapped in a helper (the same interprocedural
    gap Python had). Sink-parameter propagation closes it."""
    if not _node_ok():
        pytest.skip("node not available")
    got = _audit(tmp_path, "ip.js",
                 "function run(cmd){ eval(cmd); }\n"
                 "function handler(req, res){ const code = req.body.code; run(code); }")
    assert any(f["kind"] == "arbitrary_call" for f in got), got
    assert "handler" in {f["function"] for f in got}


def test_interprocedural_untainted_helper_SILENT(tmp_path):
    """A sink-helper called with a CONSTANT arg must not fire (taint-gated)."""
    if not _node_ok():
        pytest.skip("node not available")
    got = _audit(tmp_path, "ips.js",
                 "function run(cmd){ eval(cmd); }\n"
                 "function boot(){ run('init()'); }")
    assert "boot" not in {f["function"] for f in got}


def test_operator_is_reused_verbatim():
    """trust_obstructions is the SAME operator the Solidity legs use — no JS-specific operator."""
    deps = {"op": {"req"}}
    assert trust_obstructions(deps, sources={"req"}, sinks={"op"}, sanitizers=set())
    assert not trust_obstructions(deps, sources={"req"}, sinks={"op"}, sanitizers={"op"})


# ── cross-file interprocedural (deep-sweep wk01jvye5) ──
def test_crossfile_interproc_helper_FIRES(tmp_path):
    """Sink-wrapping helper in helper.js, tainted caller in route.js — auditing the DIRECTORY must carry
    taint across the file boundary (per-file sink-param map was a silent FN)."""
    if not _node_ok():
        pytest.skip("node unavailable")
    (tmp_path / "helper.js").write_text(
        "const cp = require('child_process');\n"
        "function run(cmd) { return cp.execSync(cmd); }\n"
        "module.exports = { run };\n")
    (tmp_path / "route.js").write_text(
        "const { run } = require('./helper');\n"
        "function handler(req, res) { run(req.body.cmd); }\n")
    findings = js_arbitrary_call_audit(tmp_path)
    assert any(f["kind"] == "arbitrary_call" for f in findings), findings
    assert any(f.get("file") == "route.js" for f in findings)


# ── deep-sweep wk01jvye5: setTimeout, return-taint, field-taint guards ──
def test_settimeout_string_FIRES(tmp_path):
    """setTimeout/setInterval with a STRING first arg is an implicit eval (CWE-95) — must fire."""
    if not _node_ok():
        pytest.skip("node unavailable")
    assert any(f["kind"] == "arbitrary_call" for f in _audit(tmp_path, "st.js",
        "function h(req){ setTimeout(req.body.code, 100); }\n"))


def test_settimeout_function_arg_SILENT(tmp_path):
    """The safe form setTimeout(()=>..., 100) / setTimeout(fn, 100) must stay silent (no string eval)."""
    if not _node_ok():
        pytest.skip("node unavailable")
    assert _audit(tmp_path, "stf.js", "function h(req){ setTimeout(()=>doit(req.body.x), 100); }\n") == []


def test_return_taint_2hop_FIRES(tmp_path):
    """Taint laundered through a value-returning helper — `const x = get(req); eval(x)` where get returns
    req.body.x. The source is hidden in get's body (was a silent FN)."""
    if not _node_ok():
        pytest.skip("node unavailable")
    src = ("function get(req){ return req.body.x; }\n"
           "function h(req){ const x = get(req); eval(x); }\n")
    assert any(f["kind"] == "arbitrary_call" for f in _audit(tmp_path, "rt.js", src))


def test_return_constant_helper_SILENT(tmp_path):
    """A helper returning a constant must not taint its callers (return-taint stays gated)."""
    if not _node_ok():
        pytest.skip("node unavailable")
    src = ("function get(){ return 'safe'; }\n"
           "function h(){ const x = get(); eval(x); }\n")
    assert _audit(tmp_path, "rcs.js", src) == []


def test_obj_field_write_taint_FIRES(tmp_path):
    """Guard: `o.cmd = req.body.cmd; cp.exec(o.cmd)` — member-write LHS harvested into the dep graph."""
    if not _node_ok():
        pytest.skip("node unavailable")
    src = ("const cp = require('child_process');\n"
           "function h(req){ const o = {}; o.cmd = req.body.cmd; cp.exec(o.cmd); }\n")
    assert any(f["kind"] == "arbitrary_call" for f in _audit(tmp_path, "of.js", src))


def test_interproc_two_hop_FIRES(tmp_path):
    """Transitive interproc: h -> mid -> sh(cp.exec). The one-hop summary missed the middle hop."""
    if not _node_ok():
        pytest.skip("node unavailable")
    src = ("const cp = require('child_process');\n"
           "function sh(c){ cp.exec(c); }\n"
           "function mid(c){ sh(c); }\n"
           "function h(req){ mid(req.body.cmd); }\n")
    assert any(f["kind"] == "arbitrary_call" for f in _audit(tmp_path, "2h.js", src))


def test_dynamic_dispatch_refs_detects_computed_member_call(tmp_path):
    # obj[<dynamic>]() -> a dyn_dispatch ref naming the base object (feeds builder Pass 9);
    # static member access (o.cmd(), o["lit"]()) must NOT produce one.
    if not _node_ok():
        pytest.skip("node not available")
    from lattice.ingest.js_arbitrary_call import dynamic_dispatch_refs
    (tmp_path / "log.ts").write_text(
        "const formatters = { cmd() { return 1 }, stdout() { return 2 } }\n"
        "function printLog(entry) {\n"
        "  return formatters[entry.kind](entry)\n"
        "}\n"
        "function staticCall(o) { return o.cmd() }\n"
        "function litKey(o) { return o['cmd']() }\n"
    )
    dyn = [r for r in dynamic_dispatch_refs(["log.ts"], tmp_path) if r.kind == "dyn_dispatch"]
    assert any(r.name == "formatters" for r in dyn), dyn
    assert all(r.name != "o" for r in dyn)   # static o.cmd() and o['cmd']() excluded
