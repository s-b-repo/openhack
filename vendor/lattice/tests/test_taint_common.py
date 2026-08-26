"""Tests for the SHARED structural helpers behind the bridge-JSON taint frontends
(`lattice.ingest.taint_common`). The per-language frontends (go/rust/ruby + the C fixpoint) delegate
their byte-identical pieces here; these tests pin the shared semantics — dep-map construction, the
interprocedural sink-param lookup, and the transitive fixpoint — so the thin adapters stay honest."""
import sys

from lattice.ingest.taint_common import (
    deps_from_assigns,
    func_params,
    interproc_sink_names,
    module_sink_params_fixpoint,
    return_source_funcs,
    run_json_bridge,
    sink_params,
)


def _go_keys(callee: str) -> tuple:
    """Go-style summary lookup: the bare name after the last dot (pkg.fn / recv.fn -> fn)."""
    return (callee.split(".")[-1],)


def _rust_keys(callee: str) -> tuple:
    """Rust-style summary lookup: the exact path first, then the last ::-segment."""
    return (callee, callee.split("::")[-1])


def _toy_sink_names(func: dict) -> set:
    """A minimal per-language sink detector: names of every arg of a call to `danger`."""
    out: set = set()
    for c in func.get("calls") or []:
        if c.get("callee") == "danger":
            for a in c.get("args") or []:
                out |= set(a.get("names") or [])
    return out


# ---- deps_from_assigns ---------------------------------------------------------------------------

def test_deps_merges_rhs_footprints_for_repeated_lhs():
    func = {"assigns": [
        {"lhs": ["cmd"], "rhs": ["prefix", "user"]},
        {"lhs": ["cmd"], "rhs": ["suffix"]},
        {"lhs": ["a", "b"], "rhs": ["x"]},
    ]}
    assert deps_from_assigns(func) == {
        "cmd": {"prefix", "user", "suffix"},
        "a": {"x"},
        "b": {"x"},
    }


def test_deps_tolerates_missing_fields():
    assert deps_from_assigns({}) == {}
    assert deps_from_assigns({"assigns": [{"lhs": None, "rhs": None}]}) == {}


# ---- interproc_sink_names ------------------------------------------------------------------------

def test_interproc_collects_arg_names_in_sink_param_positions():
    func = {"calls": [{"callee": "pkg.sh", "args": [
        {"names": ["benign"]}, {"names": ["tainted", "other"]}]}]}
    assert interproc_sink_names(func, {"sh": {1}}, _go_keys) == {"tainted", "other"}


def test_interproc_exact_key_tried_before_path_tail():
    func = {"calls": [{"callee": "util::sh", "args": [{"names": ["a"]}, {"names": ["b"]}]}]}
    # rust-style resolution: the EXACT callee key wins over the ::-tail fallback...
    assert interproc_sink_names(func, {"util::sh": {0}, "sh": {1}}, _rust_keys) == {"a"}
    # ...and the tail is the fallback when the exact key is absent.
    assert interproc_sink_names(func, {"sh": {1}}, _rust_keys) == {"b"}


def test_interproc_empty_map_short_circuits():
    func = {"calls": [{"callee": "sh", "args": [{"names": ["x"]}]}]}
    assert interproc_sink_names(func, {}, _go_keys) == set()


# ---- sink_params ---------------------------------------------------------------------------------

def test_sink_params_via_body_sink():
    # fn sh(cmd, quiet): full <- cmd; danger(full)  -> cmd reaches the sink through the assign chain.
    sh = {"name": "sh", "params": ["cmd", "quiet"],
          "assigns": [{"lhs": ["full"], "rhs": ["cmd"]}],
          "calls": [{"callee": "danger", "args": [{"names": ["full"]}]}]}
    assert sink_params(sh, None, _toy_sink_names, _go_keys) == {"cmd"}


def test_sink_params_via_helper_summary_map():
    # fn mid(c): sh(c)  -> with sh's param 0 a known sink-param, mid's own param counts (the middle hop);
    # without the map, mid has no sink of its own.
    mid = {"name": "mid", "params": ["c"],
           "calls": [{"callee": "sh", "args": [{"names": ["c"]}]}]}
    assert sink_params(mid, {"sh": {0}}, _toy_sink_names, _go_keys) == {"c"}
    assert sink_params(mid, None, _toy_sink_names, _go_keys) == set()


# ---- module_sink_params_fixpoint -----------------------------------------------------------------

def test_fixpoint_makes_summary_transitive():
    # h -> mid -> sh: only sh touches a sink DIRECTLY. The fixpoint must mark all three (N-hop);
    # callers listed BEFORE callees forces the extra rounds a single pass would miss.
    sh = {"name": "sh", "params": ["cmd"],
          "calls": [{"callee": "danger", "args": [{"names": ["cmd"]}]}]}
    mid = {"name": "mid", "params": ["c"],
           "calls": [{"callee": "sh", "args": [{"names": ["c"]}]}]}
    h = {"name": "h", "params": ["x", "y"],
         "calls": [{"callee": "mid", "args": [{"names": ["y"]}]}]}

    def _sp(func, summary):
        return sink_params(func, summary, _toy_sink_names, _go_keys)

    assert module_sink_params_fixpoint([h, mid, sh], func_params, _sp) == {
        "sh": {0}, "mid": {0}, "h": {1}}


# ---- return_source_funcs ---------------------------------------------------------------------------

def test_return_sources_fixpoint_for_chains():
    # get returns a source-tainted value; wrap returns get()'s result (the callee name lands in v's
    # footprint). Listing wrap BEFORE get forces the second round a single pass would miss.
    get = {"name": "get", "assigns": [{"lhs": ["raw"], "rhs": ["FormValue"]}], "returns": [["raw"]]}
    wrap = {"name": "wrap", "assigns": [{"lhs": ["v"], "rhs": ["get"]}], "returns": [["v"]]}
    assert return_source_funcs([wrap, get], {"FormValue"}) == {"get", "wrap"}


def test_return_sources_skip_untainted_returnless_and_nameless():
    clean = {"name": "clean", "assigns": [{"lhs": ["x"], "rhs": ["lit"]}], "returns": [["x"]]}
    noret = {"name": "noret", "assigns": [{"lhs": ["y"], "rhs": ["FormValue"]}]}
    anon = {"returns": [["FormValue"]]}                      # tainted return but NO name -> never added
    assert return_source_funcs([clean, noret, anon], {"FormValue"}) == set()


def test_return_sources_respect_sanitizer_callable():
    # ruby-style seam: `safe = params.shellescape; safe` — the binding through a shell sanitizer breaks
    # the flow, so the SAME function is a return-source without the callable and silent with it.
    fn = {"name": "build",
          "assigns": [{"lhs": ["safe"], "rhs": ["params", "shellescape"]}],
          "returns": [["safe"]]}
    assert return_source_funcs([fn], {"params"}) == {"build"}
    assert return_source_funcs([fn], {"params"}, sanitized_of=lambda f: {"safe"}) == set()


def test_return_sources_take_shape_accessors():
    # clang-style seam: returns/deps live behind accessors, not bridge-JSON keys — and the return
    # footprints are SETS (C), which set(r or []) must normalize just like go/ruby's lists.
    fn = {"name": "get_host", "c_rets": [{"host"}], "c_deps": {"host": {"getenv"}}}
    out = return_source_funcs([fn], {"getenv"},
                              returns_of=lambda f: f["c_rets"],
                              deps_of=lambda f: f["c_deps"])
    assert out == {"get_host"}


# ---- run_json_bridge -------------------------------------------------------------------------------

def test_bridge_returns_parsed_json():
    out = run_json_bridge([sys.executable, "-c", "print('[{\"name\": \"f\"}]')"])
    assert out == [{"name": "f"}]


def test_bridge_none_on_nonzero_exit():
    assert run_json_bridge([sys.executable, "-c", "import sys; sys.exit(3)"]) is None


def test_bridge_none_on_garbage_stdout():
    assert run_json_bridge([sys.executable, "-c", "print('not json')"]) is None


def test_bridge_none_on_empty_stdout():
    assert run_json_bridge([sys.executable, "-c", "pass"]) is None


def test_bridge_none_on_missing_binary():
    assert run_json_bridge(["/nonexistent/lattice-bridge"]) is None
