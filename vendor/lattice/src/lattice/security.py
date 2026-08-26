# src/lattice/security.py
"""Structural security audit — attack surface + source-to-sink reachability.

Maps public entrypoints (sources) to dangerous sinks (by name heuristic) and reports
which entrypoints can REACH which sinks, with the path. Honest by construction: this
is *call-reachability*, not proven data-flow taint. The report says so explicitly —
it tells you where a vulnerability *could* live (surface + reachability) so you can
review it, not that attacker input provably flows to the sink.

Sink classification is name-based (tier-1, heuristic): false positives and negatives
are expected; patterns are configurable.
"""
from __future__ import annotations
import pathlib
import re
from dataclasses import dataclass, field, asdict

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView
from lattice.guard import guarded_reachability
from lattice.taxonomy import classify_touchpoints, gate_vertices, is_test_file

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Tier-2: dangerous library CALL sites (caught even when the callee isn't a defined symbol).
# NOTE: the SSRF pattern (last row) starts as "ssrf_possible" (low). It is PROMOTED to
# "ssrf" (medium) inside _scan_external_sinks when interprocedural taint says the URL
# argument carries user input — same demotion pattern as `sql_injection_possible`.
# `spawn` is lookbehind-guarded to avoid `EventEmitter.spawn` and similar member calls
# that are unrelated to child_process.spawn.
_CALL_SINKS = [
    (re.compile(r"(?<![.\w])(?:execSync|execFile|execFileSync|spawn|spawnSync|spawnFileSync|fork)\s*\("),
     "command_exec", "critical"),
    # SHELL exec only: a bare `exec(` (imported from child_process) or `childProcess.exec`.
    # A database receiver's `.exec()` (sqlite/better-sqlite3) is SQL, not a shell command —
    # `\bexec` used to match the `.exec` after the dot and inflate db.exec() to critical.
    (re.compile(r"(?<![.\w])exec\s*\(|(?:child_?[Pp]rocess|cp)\.exec\s*\("),
     "command_exec", "critical"),
    (re.compile(r"\b(?:system|popen)\s*\("), "command_exec", "critical"),
    # Windows CRT process family (kept separate from the POSIX row so C/Ruby coverage
    # doesn't hide inside the shell family and can be tuned independently).
    (re.compile(r"\b_(?:wsystem|system|spawnv|spawnvp|spawnve|execv|execvp)\s*\("),
     "command_exec", "critical"),
    (re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|"
                r"\bvm\.(?:runInNewContext|runInContext|runInThisContext|Script|compileFunction)\s*\("),
     "code_eval", "critical"),
    (re.compile(r"(?:pickle\.loads|yaml\.load|unserialize|marshal\.loads|"
                r"cloudpickle\.loads|dill\.loads|jsonpickle\.decode|"
                r"ObjectInputStream|XMLDecoder|XStream\.fromXML)\s*\("),
     "deserialization", "high"),
    (re.compile(r"\.(?:query|execute|executemany|raw|query_all|execute_batch)\s*\(|"
                r"\b(?:db|database|conn|connection|pool|sqlite|knex|prisma|stmt|client)\.exec\s*\("),
     "sql_injection", "high"),
    (re.compile(r"(?:innerHTML|outerHTML|dangerouslySetInnerHTML)|"
                r"\.insertAdjacentHTML\s*\(|"
                r"\bdocument\.write(?:ln)?\s*\("),
     "xss", "high"),
    # Raw SSRF-shaped call (medium-severity ceiling; demoted to `ssrf_possible` low
    # unless taint reaches the URL argument — see _scan_external_sinks).
    (re.compile(r"(?<![.\w])(?:fetch|urlopen)\s*\(|"
                r"requests\.(?:get|post|put|delete|patch|head)\s*\(|"
                r"\bhttpx\.(?:get|post|put|delete|patch|head)\s*\(|"
                r"\baxios\s*\("),
     "ssrf", "medium"),
]

# Request-OBJECT identifiers that carry attacker input regardless of context. Kept
# deliberately narrow: these are framework request handles, not property names —
# tainting by name (`data`, `query`, `input`) caused false positives, so a value is
# tainted by PROVENANCE (entrypoint param, request-object access, or propagation),
# not by what it happens to be named.
_TAINT_SOURCES = {"req", "request", "ctx", "event"}

# Functions that DETOXIFY their input — a value derived through one of these is clean.
_SANITIZERS = {"sanitize", "escape", "escapehtml", "escapestring", "clean", "encode",
               "quote", "validate", "parameterize", "htmlescape", "sqlescape"}

@dataclass
class SecurityFinding:
    kind: str
    severity: str
    source: str
    sink: str
    path: list
    detail: str
    taint: str = "reachable"        # "reachable" | "argument_flow" (input flows into the sink)

    def to_dict(self) -> dict:
        return asdict(self)


def _capture_args(text: str, idx: int) -> str:
    """Balanced-paren capture of a call's arguments starting at the '(' index."""
    if idx >= len(text) or text[idx] != "(":
        return ""
    depth = 0
    for i in range(idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[idx + 1:i]
    return text[idx + 1:]


def _params_of(vertex, text: str) -> list[str]:
    """Ordered parameter names of a function from its declaration line(s)."""
    lines = text.splitlines()
    decl = " ".join(lines[vertex.start_line - 1: vertex.start_line + 1])
    m = re.search(r"\(([^)]*)\)", decl)
    if not m:
        return []
    out = []
    for tok in m.group(1).split(","):
        name = tok.split(":")[0].strip().strip("{}").strip()
        name = re.split(r"[=\s]", name)[0]
        if name.isidentifier():
            out.append(name)
    return out


def _split_args(s: str) -> list[str]:
    """Top-level positional split of an argument string (respects nesting)."""
    args, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{":
            depth += 1
            cur += ch
        elif ch in ")]}":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            args.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        args.append(cur)
    return [a.strip() for a in args]


def _call_sites(body: str, name: str) -> list[str]:
    """Argument strings of each call to `name` within `body`."""
    return [_capture_args(body, m.end() - 1)
            for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", body)]


_ASSIGN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(.+)")
_RETURN = re.compile(r"\breturn\s+(.+)")


# Precompiled once — recompiling these per call (millions of times in the taint
# fixpoint) was a 7-minute hot path.
_SANITIZER_PATS = {s: re.compile(r"\b" + re.escape(s) + r"\s*\(") for s in _SANITIZERS}


def _strip_sanitized(text: str, sanitizers: set[str]) -> str:
    """Remove `sanitizer(...)` spans (balanced) — values passing through a sanitizer
    are detoxified, so the taint inside its arguments must not leak out."""
    if "(" not in text:
        return text                               # no calls -> nothing to strip
    low = text.lower()
    if not any(s in low for s in sanitizers):
        return text                               # no sanitizer present -> fast path
    out = text
    for sname in sanitizers:
        pat = _SANITIZER_PATS.get(sname) or re.compile(r"\b" + re.escape(sname) + r"\s*\(")
        while True:
            m = pat.search(out)
            if not m:
                break
            idx, depth, end = m.end() - 1, 0, None
            for i in range(idx, len(out)):
                if out[i] == "(":
                    depth += 1
                elif out[i] == ")":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            out = (out[:m.start()] + " " + out[end + 1:]) if end is not None else out[:m.start()]
    return out


def _called(text: str) -> set[str]:
    return {n.lower() for n in re.findall(r"\b([A-Za-z_]\w*)\s*\(", text)}


def _has_taint(expr: str, tainted: set[str], sanitizers: set[str], tainted_returns: set[str]) -> bool:
    """Does an expression carry taint? After stripping sanitizer-wrapped spans, it is
    tainted if it references a tainted name OR calls a function whose return is tainted."""
    stripped = _strip_sanitized(expr, sanitizers)
    words = {w.lower() for w in re.findall(r"[A-Za-z_]\w*", stripped)}
    if words & tainted:
        return True
    return bool(_called(stripped) & tainted_returns)


def _tainted_names(body: str, seed, sanitizers: set[str], tainted_returns: set[str]) -> set[str]:
    """Tainted identifiers in a function: seed (tainted params) + request objects +
    locals assigned from a tainted expression (sanitizer- and return-aware fixpoint)."""
    tainted = {s.lower() for s in seed} | set(_TAINT_SOURCES)
    for _ in range(8):
        changed = False
        for m in _ASSIGN.finditer(body):
            lhs = m.group(1).lower()
            if lhs not in tainted and _has_taint(m.group(2), tainted, sanitizers, tainted_returns):
                tainted.add(lhs)
                changed = True
        if not changed:
            break
    return tainted


def _returns_tainted(body: str, tainted: set[str], sanitizers: set[str], tainted_returns: set[str]) -> bool:
    return any(_has_taint(m.group(1), tainted, sanitizers, tainted_returns)
               for m in _RETURN.finditer(body))


def _interprocedural_taint(net, source_root) -> dict[str, set[str]]:
    """Worklist fixpoint over the call graph. Entrypoint parameters are external input
    (tainted); every other function's parameters are tainted ONLY if a caller passes a
    tainted argument into that position. Returns the full tainted-name set per function
    (params + request sources + locals), propagated across call edges until stable."""
    root = pathlib.Path(source_root)
    funcs = {v.id: v for v in net.vertices if v.kind in ("function", "method")}
    entry_ids = {s.vertex_id for s in net.surfaces if s.kind in ("public_api", "entrypoint")}

    _ft: dict = {}

    def ftext(f):
        if f not in _ft:
            try:
                _ft[f] = (root / f).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                _ft[f] = ""
        return _ft[f]

    body, params = {}, {}
    for vid, v in funcs.items():
        t = ftext(v.file)
        body[vid] = "\n".join(t.splitlines()[v.start_line - 1: v.end_line])
        params[vid] = _params_of(v, t)

    # seed: entrypoint params are external; others only if conventionally request-named
    tparams = {}
    for vid in funcs:
        if vid in entry_ids:
            tparams[vid] = {p.lower() for p in params[vid]}
        else:
            tparams[vid] = {p.lower() for p in params[vid] if p.lower() in _TAINT_SOURCES}

    calls = [(e.members[0], e.members[-1]) for e in net.hyperedges
             if len(e.members) >= 2 and e.members[0] in funcs
             and e.members[-1] in funcs and e.members[0] != e.members[-1]]

    san = _SANITIZERS
    # Call-site argument lists are STATIC (source is fixed) — compute once, not per
    # fixpoint iteration. This and the per-call positional args were the inner hot loop.
    call_arglists: dict = {}
    for caller, callee in calls:
        sites = _call_sites(body[caller], funcs[callee].name)
        if sites:
            call_arglists[(caller, callee)] = [_split_args(s) for s in sites]

    tainted_returns: set[str] = set()
    tset: dict = {vid: _tainted_names(body[vid], tparams[vid], san, tainted_returns)
                  for vid in funcs}
    dirty = set(funcs)                        # functions whose tset needs (re)computing
    for _ in range(50):                       # monotone fixpoint over params + returns
        for vid in dirty:                     # only recompute what changed
            tset[vid] = _tainted_names(body[vid], tparams[vid], san, tainted_returns)
        new_returns = {funcs[vid].name.lower() for vid in funcs
                       if funcs[vid].name.lower() not in san
                       and _returns_tainted(body[vid], tset[vid], san, tainted_returns)}
        returns_changed = new_returns != tainted_returns
        tainted_returns = new_returns
        dirty = set()
        for (caller, callee), arglists in call_arglists.items():
            cpar = params[callee]
            for args in arglists:
                for i, arg in enumerate(args):
                    if i >= len(cpar):
                        break
                    if _has_taint(arg, tset[caller], san, tainted_returns):
                        pl = cpar[i].lower()
                        if pl not in tparams[callee]:
                            tparams[callee].add(pl)
                            dirty.add(callee)
        if returns_changed:                   # return-taint affects every function's tset
            dirty = set(funcs)
        if not dirty:
            break
    return tset, tainted_returns


@dataclass
class SecurityReport:
    findings: list = field(default_factory=list)
    attack_surface: dict = field(default_factory=dict)
    sinks: list = field(default_factory=list)
    verified: list = field(default_factory=lambda: ["call_reachability", "attack_surface"])
    not_verified: list = field(default_factory=lambda:
                               ["data_flow", "exploitability", "input_validation"])
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _scan_external_sinks(net, g, source_root, sources, tset, tainted_returns) -> list[SecurityFinding]:
    """Tier-2: scan source for dangerous library CALL sites, map to the enclosing
    function, and report those reachable from a public entrypoint — with a taint
    check (does input flow into the call's arguments? — propagated across call
    edges by _interprocedural_taint)."""
    root = pathlib.Path(source_root)
    src_set = set(sources)

    byfile: dict = {}
    for v in net.vertices:
        if v.kind not in ("module", "external"):
            byfile.setdefault(v.file, []).append(v)
    for lst in byfile.values():
        lst.sort(key=lambda v: (v.end_line - v.start_line))   # tightest enclosing first

    def enclosing(file, line):
        for v in byfile.get(file, []):
            if v.start_line <= line <= v.end_line:
                return v
        return None

    # One BFS per source, ONCE — origin maps each reached vertex to the first source
    # that reaches it (same attribution as scanning sources in order, without
    # re-running reachable_from per finding).
    public_reach: set = set(sources)
    origin: dict = {}
    for s in sources:
        for vid in g.reachable_from(s):
            public_reach.add(vid)
            origin.setdefault(vid, s)

    def source_of(vid):
        if vid in src_set:
            return vid
        return origin.get(vid, "(reachable)")

    findings: list[SecurityFinding] = []
    seen: set = set()
    for fname in byfile:
        if is_test_file(fname):          # test files aren't shipped attack surface
            continue
        try:
            text = (root / fname).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rx, cat, sev in _CALL_SINKS:
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                key = (fname, line, cat)
                if key in seen:
                    continue
                seen.add(key)
                enc = enclosing(fname, line)
                args = _capture_args(text, m.end() - 1)
                # The sink's EXISTENCE is a fact (grep-verifiable); its REACHABILITY is
                # an inference over a call graph with known holes (JSX <Component/> and
                # dynamic dispatch create no edge). Never drop the fact when the inference
                # fails — report it, honestly marked, so consumers can rank but not miss it.
                reachable = enc is not None and enc.id in public_reach
                if reachable:
                    tnames = tset.get(enc.id, set())
                    taint = ("argument_flow"
                             if _has_taint(args, tnames, _SANITIZERS, tainted_returns)
                             else "reachable")
                    src = source_of(enc.id)
                    detail = (f"library {cat} call reachable from a public entrypoint"
                              + (" with input flowing into its arguments" if taint == "argument_flow"
                                 else " (constant args — reachable, no visible input flow)"))
                else:
                    taint = "unverified_reach"
                    src = enc.id if enc is not None else "(top-level)"
                    detail = (f"library {cat} call present but NOT provably reachable from a "
                              f"detected entrypoint — its enclosing function isn't on a path from "
                              f"any public_api/entrypoint surface (may be dead code, or reachable "
                              f"via an entry the surface scan didn't mark); verify manually")
                # SSRF-shape call sites are demoted to `ssrf_possible` (low) unless
                # taint provably reaches the URL argument. Same demotion-under-doubt
                # rule as `sql_injection_possible` — the fact is still reported (FIRE =
                # lead), just at low severity so `fetch(constURL)` doesn't dominate
                # rankings against genuine attacker-controlled URLs.
                out_kind, out_sev = cat, sev
                if cat == "ssrf" and taint != "argument_flow":
                    out_kind, out_sev = "ssrf_possible", "low"
                findings.append(SecurityFinding(
                    kind=out_kind, severity=out_sev, source=src,
                    sink=f"{fname}:{line}", path=[src, f"{fname}:{line}"],
                    detail=detail, taint=taint))
    return findings


def audit(net: Hypernetwork, source_root=None) -> SecurityReport:
    g = GraphView(net)
    sources = [s.vertex_id for s in net.surfaces if s.kind in ("public_api", "entrypoint")]

    # Control-flow layer: one guarded_reachability call over the taxonomy yields BOTH
    # touchpoint findings (sink reachable) and missing-gate findings (sink reachable
    # WITHOUT crossing a required gate — broken access control). Same engine, the
    # whole taxonomy is config in taxonomy.py.
    touchpoints = classify_touchpoints(net)
    gates = gate_vertices(net)
    num_sinks = sum(len(vids) for vids, _ in touchpoints.values())

    # Sinks classified only by a generic-word fallback ("*_possible" categories) are
    # name-only evidence — a bypassed gate on one is low-priority review, not a
    # high-severity finding.
    weak_sinks: set = set()
    for cat, (vids, _sev) in touchpoints.items():
        if cat.endswith("_possible"):
            weak_sinks |= vids

    findings: list[SecurityFinding] = []
    for gf in guarded_reachability(net, sources, touchpoints, gates):
        if gf.kind.startswith("missing_"):
            gate = gf.gate.replace("_", " ")
            weak = gf.sink in weak_sinks
            findings.append(SecurityFinding(
                kind=gf.kind, severity="low" if weak else "high",
                source=gf.source, sink=gf.sink, path=gf.path,
                detail=f"reachable from a public entrypoint WITHOUT crossing a {gate} "
                       f"gate (possible {gate} bypass)"
                       + (" — sink is a name-only match, verify it is sensitive" if weak
                          else "")))
        else:
            findings.append(SecurityFinding(
                kind=gf.kind, severity=gf.severity, source=gf.source, sink=gf.sink, path=gf.path,
                detail=f"public entrypoint reaches a {gf.kind} sink (reachability, not proven taint)"))

    # incomplete handlers on the attack surface
    public_reach: set = set(sources)
    for src in sources:
        public_reach |= g.reachable_from(src)
    for v in net.vertices:
        if v.stub and v.id in public_reach:
            findings.append(SecurityFinding(
                kind="incomplete_handler", severity="medium", source="(public)",
                sink=v.id, path=[v.id],
                detail="unimplemented code reachable from a public entrypoint"))

    # Tier-2: external library-call sinks + intraprocedural taint (needs source).
    verified = ["call_reachability", "attack_surface"]
    not_verified = ["data_flow", "exploitability", "input_validation"]
    if source_root is not None:
        tset, tainted_returns = _interprocedural_taint(net, source_root)
        findings.extend(_scan_external_sinks(net, g, source_root, sources, tset, tainted_returns))
        if any(f.taint == "argument_flow" for f in findings):
            verified.append("interprocedural_taint")
        not_verified = ["exploitability", "input_validation"]

    findings.sort(key=lambda f: (_SEV[f.severity], f.sink))

    surface = {k: sum(1 for s in net.surfaces if s.kind == k)
               for k in ("public_api", "entrypoint", "external_call", "trust_boundary")}
    by = {s: sum(1 for f in findings if f.severity == s) for s in _SEV}
    summary = {
        "verdict": "review" if findings else "clean",
        "findings": len(findings),
        "critical": by["critical"], "high": by["high"],
        "medium": by["medium"], "low": by["low"],
        "attack_surface": sum(surface.values()),
        "sinks": num_sinks,
    }
    return SecurityReport(findings=findings, attack_surface=surface,
                          sinks=sorted(vid for vids, _ in touchpoints.values() for vid in vids),
                          verified=verified,
                          not_verified=not_verified, summary=summary)
