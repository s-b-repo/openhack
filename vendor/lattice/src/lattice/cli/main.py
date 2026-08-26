from __future__ import annotations
import argparse, json, pathlib, sys
from lattice.graph.builder import build
from lattice.complete.gate import check
from lattice.complete.verify import verify_against_ref
from lattice.cache import GraphIngestError, SourceIngestError, load_network
from lattice.graph.models import Hypernetwork
from lattice.sidecar import digest, changes, render
from lattice.diagnose import diagnose
from lattice.impact import impact, resolve_targets, follow
from lattice.plan import plan
from lattice.hunt import hunt, Bug
from lattice.security import audit as security_audit
from lattice.triage import triage
from lattice.optimize import optimize
from lattice.logic.scan import scan_paradoxes
from lattice.memory.recall_sink import persist

_LANG = {"ts": "typescript", "js": "javascript", "py": "python", "sol": "solidity",
         "go": "go", "rs": "rust", "rb": "ruby",
         "cpp": "cpp", "cu": "cpp", "c": "c", "sh": "shell", "sql": "sql", "iac": "iac",
         "docker": "iac", "auto": "auto"}


def _cmd_ingest(args) -> int:
    from lattice.cache import ingest_source, build_auto
    language = _LANG[args.lang]
    root = pathlib.Path(args.path).resolve()
    if language == "auto":
        net, handled = build_auto(root)
        print(f"[lattice] auto-detected and handled: {', '.join(handled) or 'no source found'}")
    else:
        net = build(ingest_source(root, language))
    report = check(net)

    out = pathlib.Path(args.out)
    out.write_text(json.dumps(net.to_dict(), indent=2))
    (out.parent / "hypernetwork-report.json").write_text(json.dumps(report.to_dict(), indent=2))
    cov = report.coverage
    print(
        f"[lattice] vertices={net.stats['vertices']} hyperedges={net.stats['hyperedges']} "
        f"verdict={report.verdict} resolution={report.resolution:.3f} "
        f"coverage={cov.get('ratio', 1.0):.2f} "
        f"({cov.get('functions_with_inbound_refs', 0)}/{cov.get('functions_total', 0)} fns referenced)"
    )
    print("[lattice] note: resolution = edges-that-exist resolve; coverage = recall indicator "
          "(NOT a completeness guarantee)")

    if report.verdict == "fail" and not args.allow_partial:
        print(f"[lattice] FAIL: {report.failing_checks}", file=sys.stderr)
        return 1
    if args.db:
        try:
            persist(net, report, db_path=args.db, project=args.project)
            print(f"[lattice] persisted to recall db {args.db}")
        except Exception as e:
            print(
                f"[lattice] WARNING: recall persistence failed: {e}; "
                f"hypernetwork.json kept at {out}",
                file=sys.stderr,
            )
            return 2
    return 0


def _cmd_verify(args) -> int:
    """Differential gate: did the working tree regress the structure vs a git ref?"""
    language = _LANG[args.lang]
    repo = pathlib.Path(args.path).resolve()
    report = verify_against_ref(repo, ref=args.against, language=language)

    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(report.to_dict(), indent=2))
    print(
        f"[lattice] verify vs {args.against}: verdict={report.verdict} "
        f"regressions={report.regressions or 'none'} "
        f"(+{len(report.added_vertices)}/-{len(report.removed_vertices)} vertices)"
    )
    if report.verdict == "unverifiable":
        print("[lattice] UNVERIFIABLE: ingest errors prevent structural verification",
              file=sys.stderr)
        if report.baseline_error_diagnostics:
            print(f"  baseline_error_diagnostics: {report.baseline_error_diagnostics}",
                  file=sys.stderr)
        print(f"  error_diagnostics: {report.error_diagnostics}", file=sys.stderr)
        return 2
    if report.verdict == "regressed" and not args.allow_regression:
        print(f"[lattice] REGRESSED: {report.regressions}", file=sys.stderr)
        if report.broken_by_removal:
            print(f"  broken_by_removal: {report.broken_by_removal}", file=sys.stderr)
        if report.new_unresolved_imports:
            print(f"  new_unresolved_imports: {report.new_unresolved_imports}", file=sys.stderr)
        if report.new_error_diagnostics:
            print(f"  new_error_diagnostics: {report.new_error_diagnostics}", file=sys.stderr)
        if report.removed_public_api:
            print(f"  removed_public_api: {report.removed_public_api}", file=sys.stderr)
        return 1
    return 0


def _cmd_diagnose(args) -> int:
    """Structural diagnostics — the Footings microscope."""
    language = _LANG[args.lang]
    net, _ = load_network(args.path, language)
    d = diagnose(net)
    s = d.summary

    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(d.to_dict(), indent=2))

    print(
        f"[lattice] {s['verdict'].upper()} — vertices={s['vertices']} b1={s['b1']} "
        f"obstructions={s['obstructions']} cycles={s['cycles']} dead_code={s['dead_code']} "
        f"stubs={s['stubs']} dangling={s['dangling_edges']} "
        f"unresolved_imports={s['unresolved_imports']} "
        f"reconcile_candidates={s['reconciliation_candidates']}"
    )
    if d.obstructions:
        for w in d.obstructions[:5]:
            print(f"  obstruction[{w['kind']}]: broken {w['broken_edge']} "
                  f"in cycle {w['cycle']} (energy {w['energy']:.2f})")
    if d.cycles:
        print(f"  cycles: {d.cycles[:5]}")
    if d.dead_code:
        print(f"  dead_code: {d.dead_code[:10]}")
    if d.stubs:
        print(f"  stubs: {d.stubs[:10]}")
    if d.hotspots:
        top = ", ".join(f"{h['id']}(in{h['fan_in']}/out{h['fan_out']})" for h in d.hotspots[:5])
        print(f"  hotspots: {top}")

    if args.fail_on_issues and s["verdict"] == "issues":
        return 1
    return 0


def _cmd_paradox(args) -> int:
    """Logic paradox audit — dead branches (contradictions) and redundant guards (tautologies)."""
    root = pathlib.Path(args.path).resolve()
    findings = scan_paradoxes(root)
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(findings, indent=2))

    contradictions = [f for f in findings if f["kind"] == "contradiction"]
    tautologies = [f for f in findings if f["kind"] == "tautology"]
    print(f"[lattice] paradox audit: {len(contradictions)} contradiction(s), "
          f"{len(tautologies)} tautology(ies)")
    for f in findings:
        loc = f"{f['file']}:{f['line']}" if f.get("file") else "?"
        print(f"  {f['kind']:13} {loc}  `{f['condition']}`  — {f['detail']}")

    if args.fail_on_paradox and findings:
        return 1
    return 0


def _cmd_impact(args) -> int:
    """Change blast radius — everything that transitively depends on a symbol."""
    language = _LANG[args.lang]
    net, _ = load_network(args.path, language)

    targets = resolve_targets(net, args.symbol)
    if not targets:
        print(f"[lattice] no symbol matched '{args.symbol}'", file=sys.stderr)
        return 1

    reports = [impact(net, t) for t in targets]
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps([r.to_dict() for r in reports], indent=2))

    for r in reports:
        print(f"[lattice] impact of {r.target}: blast_radius={r.blast_radius} "
              f"(direct={len(r.direct_dependents)}, files={len(r.affected_files)}, "
              f"public_api={len(r.affected_public_api)})")
        if r.affected_public_api:
            print(f"  reaches public API: {r.affected_public_api}")
        if r.direct_dependents:
            print(f"  direct dependents: {r.direct_dependents[:10]}")
        if r.affected_files:
            print(f"  affected files: {r.affected_files[:10]}")
    return 0


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _cmd_hunt(args) -> int:
    """Bug hunter — ranked structural bugs, merged with the logic paradox audit."""
    language = _LANG[args.lang]
    net, source_root = load_network(args.path, language)
    bugs = hunt(net)

    # fold in logic paradoxes (dead branches / redundant guards are bugs too)
    for p in scan_paradoxes(source_root):
        loc = f"{p['file']}:{p['line']}"
        if p["kind"] == "contradiction":
            bugs.append(Bug("dead_branch", "medium", loc,
                            f"branch can never execute: `{p['condition']}`", p))
        else:
            bugs.append(Bug("redundant_guard", "low", loc,
                            f"guard is always true: `{p['condition']}`", p))
    bugs.sort(key=lambda b: (_SEV_ORDER[b.severity], b.symbol))

    if args.out:
        pathlib.Path(args.out).write_text(json.dumps([b.to_dict() for b in bugs], indent=2))

    by = {s: sum(1 for b in bugs if b.severity == s) for s in _SEV_ORDER}
    print(f"[lattice] bug hunt: {len(bugs)} finding(s) — "
          f"critical={by['critical']} high={by['high']} medium={by['medium']} low={by['low']}")
    for b in bugs:
        print(f"  [{b.severity:8}] {b.kind:20} {b.symbol}  — {b.detail}")

    serious = [b for b in bugs if b.severity in ("critical", "high")]
    if args.fail_on_bugs and serious:
        return 1
    return 0


def _cmd_secaudit(args) -> int:
    """Structural security audit — attack surface + source-to-sink reachability."""
    language = _LANG[args.lang]
    net, source_root = load_network(args.path, language)
    r = security_audit(net, source_root=source_root)
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(r.to_dict(), indent=2))
    s = r.summary
    print(f"[lattice] security audit: {s['verdict'].upper()} — {s['findings']} finding(s) "
          f"(critical={s['critical']} high={s['high']} medium={s['medium']}) "
          f"attack_surface={s['attack_surface']} sinks={s['sinks']}")
    print(f"  verified: {r.verified}  |  NOT verified: {r.not_verified}")
    # Rank by confidence: input flows into the sink > reachable from entrypoint >
    # present-but-reachability-unproven. The last group is recall (real sinks the call
    # graph can't trace, e.g. JSX-rendered) — shown, but never drowning the proven ones.
    _ORDER = {"argument_flow": 0, "reachable": 1, "unverified_reach": 2}
    _FLAG = {"argument_flow": "⚠ TAINTED", "reachable": "reachable",
             "unverified_reach": "? unproven"}
    n_unproven = sum(1 for f in r.findings if getattr(f, "taint", "") == "unverified_reach")
    if n_unproven:
        print(f"  confidence: {len(r.findings) - n_unproven} reachable/tainted (proven path)  ·  "
              f"{n_unproven} present but reachability-unproven (enclosing not reached from a "
              f"detected entrypoint — may be dead, or rooted on an entry the surface scan missed)")
    for f in sorted(r.findings, key=lambda f: (_ORDER.get(getattr(f, "taint", "reachable"), 1),
                                               f.severity)):
        taint = getattr(f, "taint", "reachable")
        flag = _FLAG.get(taint, "reachable")
        loc = f"{f.source} → {f.sink}" if f.path and len(f.path) > 1 else f.sink
        print(f"  [{f.severity:8}] {f.kind:18} {flag:11} {loc}")
    if args.fail_on_findings and r.findings:
        return 1
    return 0


def _cmd_link(args) -> int:
    """Auto-link a host to its dependency graphs from a name@version registry, then report
    what joined, what's a trace loss, and any broken links across the joins."""
    from lattice.registry import GraphRegistry, link_auto
    from lattice.compose import broken_links
    language = _LANG[args.lang]
    host, source_root = load_network(args.path, language)
    reg = GraphRegistry(args.registry)
    composed, report = link_auto(host, source_root, reg)
    joins = sum(1 for e in composed.hyperedges if e.kind == "links")
    print(f"[lattice] link: {len(report.linked)} dependency graph(s) joined "
          f"({joins} join edge(s)) · {len(report.missing)} installed but not in registry "
          f"(trace loss) · {len(report.unresolved)} version unresolved")
    for name, ver in report.linked:
        print(f"  ✓ linked  {name}@{ver}")
    for name, ver in report.missing:
        print(f"  ↗ trace loss  {name}@{ver}  (add to registry to follow through)")
    # verify the joins that DID form — broken-link findings across the registry graphs
    bl = broken_links(host, source_root, _linked_graphs(host, source_root, reg))
    if bl:
        print(f"\n  ⚠ {len(bl)} broken link(s) across joins:")
        for b in bl[:12]:
            print(f"      {b.location}  {b.reason}: {b.detail}")
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(composed.to_dict()))
        print(f"\n  composed graph -> {args.out}")
    return 0


def _linked_graphs(host, source_root, reg) -> dict:
    """{import_specifier: library_graph} for the libraries the host uses that the registry
    has — the same join set link_auto builds, reused for broken-link verification."""
    from lattice.exposure import library_exposure
    from lattice.registry import _package_of, installed_version
    out: dict = {}
    for spec in {e.library for e in library_exposure(host, source_root)}:
        pkg = _package_of(spec)
        if pkg is None:
            continue
        ver = installed_version(source_root, pkg)
        if ver is None:
            continue
        g = reg.get(pkg, ver, host.language)
        if g is not None:
            out[spec] = g
    return out


def _cmd_registry_add_all(args) -> int:
    """Auto-populate the registry from installed selected-language dependencies."""
    from lattice.registry import GraphRegistry, populate_from_project
    language = _LANG[args.lang]
    rep = populate_from_project(args.path, GraphRegistry(args.registry), language,
                                include_dev=args.include_dev)
    added = [a for a in rep["added"] if a[2] != "cached"]
    print(f"[lattice] registry-add-all: {len(added)} indexed · "
          f"{len(rep['skipped_no_source'])} skipped (no selected-language source) · "
          f"{len(rep['failed'])} failed")
    for name, ver, n in rep["added"]:
        print(f"  ✓ {name}@{ver}  ({n} vertices)" if n != "cached" else f"  · {name}@{ver} (cached)")
    if rep["skipped_no_source"]:
        print(f"  skipped (no ingestable source — stay trace losses): "
              f"{', '.join(rep['skipped_no_source'][:20])}")
    for name, why in rep["failed"]:
        print(f"  ✗ {name}: {why}")
    return 1 if rep["failed"] else 0


def _cmd_registry_add(args) -> int:
    """Ingest a library and store its graph by name@version@language."""
    import json as _json
    from lattice.cache import build_source
    from lattice.registry import GraphRegistry, gate_failure_reason
    language = _LANG[args.lang]
    libdir = pathlib.Path(args.path)
    name, version = args.name, args.version
    if name is None or version is None:
        try:
            pj = _json.loads((libdir / "package.json").read_text())
            name = name or pj.get("name")
            version = version or pj.get("version")
        except OSError:
            pass
    if not name or not version:
        print("[lattice] need --name and --version (no package.json found)", file=sys.stderr)
        return 1
    net = build_source(libdir, language)
    failure = gate_failure_reason(net)
    if failure is not None:
        print(f"[lattice] registry-add refused {name}@{version}: {failure}",
              file=sys.stderr)
        return 1
    GraphRegistry(args.registry).put(name, version, net, language)
    print(f"[lattice] registry-add: stored {name}@{version} "
          f"({len(net.vertices)} vertices) in {args.registry}")
    return 0


def _cmd_intake(args) -> int:
    """Emit the complete, labeled intake the triage agent decides over."""
    from lattice.intake import agent_intake
    language = _LANG[args.lang]
    payload = agent_intake(args.path, language)
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(payload, indent=2))
    s = payload["summary"]
    print(f"[lattice] agent intake: {s['total']} finding(s) "
          f"({', '.join(f'{k}={v}' for k, v in s['by_disposition'].items())}) "
          f"· {s['blind_spots']} blind spot(s)")
    print("  → hand to the footings-triage agent: it decides act/review/suppress per finding "
          "and escalate/accept per blind spot (suppressions logged, never silent).")
    for f in payload["findings"][:8]:
        print(f"    [{f['severity']:8}] {f['disposition']:18} {f['kind']} — {f['subject']} ({f['location']})")
    return 0


def _cmd_typed(args) -> int:
    """Typed-constraint-algebra audit — the three obstruction legs (homology / typed-collision /
    conservation) over the typed storage-cell complex. Finds obstructions, not just paths."""
    from lattice.ingest.solidity_typed import typed_audit
    _, source_root = load_network(args.path, "solidity")
    findings = typed_audit(source_root)
    from collections import Counter
    by = Counter(f["leg"] for f in findings)
    print(f"[lattice] typed audit: {len(findings)} obstruction(s) — "
          f"homology={by['homology']} (reentrancy/stale-state) · "
          f"typed_collision={by['typed_collision']} (delegatecall slot-aliasing) · "
          f"conservation={by['conservation']} (value leaks) · blindspot={by['blindspot']}")
    print("  (structural obstructions = the GATE/precondition, not a confirmed exploit — triage downstream)")
    order = {"homology": 0, "typed_collision": 1, "conservation": 2, "blindspot": 3}
    for f in sorted(findings, key=lambda x: order.get(x["leg"], 9))[:50]:
        print(f"  [{f['leg']:15}] {f.get('contract','')}.{f.get('function','')} "
              f"({f['file']}:{f.get('line','?')}) — {f['detail']}")
    return 0


def _cmd_solaudit(args) -> int:
    """Solidity vulnerability audit — all structural detectors, with honest parse coverage."""
    import pathlib as _pl
    from lattice.ingest.solidity import solidity_audit, _solc_ast, _SKIP_DIRS
    net, source_root = load_network(args.path, "solidity")
    root = _pl.Path(source_root)
    sol = [p for p in root.rglob("*.sol") if not (_SKIP_DIRS & set(p.relative_to(root).parts))]
    blind = [p.relative_to(root).as_posix() for p in sol if _solc_ast(p) is None]
    findings = solidity_audit(source_root)
    sev = {"critical": 0, "high": 1, "medium": 2}
    findings.sort(key=lambda f: sev.get(f["severity"], 3))
    from collections import Counter
    by = Counter(f["severity"] for f in findings)
    print(f"[lattice] solidity audit: {len(findings)} finding(s) "
          f"(critical={by['critical']} high={by['high']} medium={by['medium']}) "
          f"across {len(sol) - len(blind)}/{len(sol)} parseable file(s)")
    if blind:
        print(f"  ⚠ BLIND SPOT: {len(blind)} file(s) could not be parsed (version/syntax) — "
              f"NOT audited: {', '.join(blind[:6])}")
    for f in findings[:50]:
        print(f"  [{f['severity']:8}] {f['kind']:24} {f['contract']}.{f['function']} "
              f"({f['file']}:{f['line']}) — {f['detail']}")
    return 0


def _cmd_reentrancy(args) -> int:
    """Solidity reentrancy — external call before a state write (CEI violation)."""
    from lattice.ingest.solidity import reentrancy_findings
    net, source_root = load_network(args.path, "solidity")
    findings = reentrancy_findings(source_root)
    print(f"[lattice] reentrancy: {len(findings)} CEI-violation(s) "
          f"(external call before a state write)")
    for x in findings:
        print(f"  ⚠ {x['contract']}.{x['function']}  ({x['file']})  "
              f"ext-call L{x['call_line']} → state-write L{x['write_line']}")
    return 0


def _cmd_fix(args) -> int:
    """Minimal fix — the math->solver pipeline. Homology finds the obstruction cycles; the
    solver returns the fewest edges to cut so every one is broken (verified before reporting)."""
    from lattice.topology import minimal_fix
    net, _ = load_network(args.path, _LANG[args.lang])
    fix = minimal_fix(net)
    n = fix["obstructions_before"]
    if n == 0:
        print("[lattice] minimal fix: 0 obstruction cycles — graph is already obstruction-free")
        return 0
    print(f"[lattice] minimal fix: cut {len(fix['cut'])} edge(s) to break all {n} "
          f"obstruction cycle(s) → {fix['obstructions_after']} remain  [{fix['provenance']}]")
    for u, v in fix["cut"]:
        print(f"  ✂ {str(u).split('#')[-1]} → {str(v).split('#')[-1]}")
    if fix["obstructions_after"] != 0:
        print(f"  (residual {fix['obstructions_after']} — cut is a lower bound; escalate the remainder)")
    return 0


def _cmd_cuda(args) -> int:
    """CUDA host/device data crossings — what data moves to/from the GPU."""
    from lattice.cuda import cuda_crossings
    net, source_root = load_network(args.path, _LANG[args.lang])
    cr = cuda_crossings(source_root)
    h2d = sum(1 for c in cr if c.direction == "host_to_device")
    print(f"[lattice] cuda crossings: {len(cr)} ({h2d} host->device) across the GPU boundary")
    for c in cr[:40]:
        print(f"  {c.file}:{c.line}  [{c.direction}]  {c.detail}")
    return 0


def _cmd_barriers(args) -> int:
    """Minimum gate placement — the fewest functions to guard to cover every attack path."""
    from lattice.barriers import min_barrier_set
    from lattice.taxonomy import classify_touchpoints
    net, _ = load_network(args.path, _LANG[args.lang])
    sources = [s.vertex_id for s in net.surfaces if s.kind in ("public_api", "entrypoint")]
    sinks = [vid for vids, _ in classify_touchpoints(net).values() for vid in vids]
    res = min_barrier_set(net, sources, sinks)
    print(f"[lattice] minimum barrier set: gate {len(res.barriers)} function(s) to cover "
          f"{res.paths_covered}/{res.paths_total} attack path(s)  [{res.method}]")
    for b in res.barriers:
        print(f"  ⚑ {b.split('#')[-1]}  ({b.split('#')[0].replace('ts-sym:', '')})")
    return 0


def _cmd_blindspots(args) -> int:
    """The keystone — honestly enumerate where the map goes dark, by category."""
    from lattice.blindspots import blindspots
    language = _LANG[args.lang]
    net, source_root = load_network(args.path, language)
    b = blindspots(net, source_root)
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(b.to_dict(), indent=2))
    s = b.summary
    print(f"[lattice] blindspots: {s['total_dark']} place(s) the map goes dark — "
          f"{s['leaves_to_unmapped']} leave to unmapped code · {s['unresolved']} point at "
          f"nothing · {s['unreached']} unreached by any followed path")
    print("  (this is the honest known-unknowns: trust the map elsewhere, look here yourself)")
    if b.leaves_to_unmapped:
        print(f"\n  ↗ leaves to unmapped code ({len(b.leaves_to_unmapped)}) — handoffs; map the "
              f"other side to follow through:")
        for x in b.leaves_to_unmapped[:12]:
            print(f"      {x}")
    if b.unresolved:
        print(f"\n  ✗ points at nothing ({len(b.unresolved)}) — broken/dangling references:")
        for x in b.unresolved[:12]:
            print(f"      {x}")
    if b.unreached:
        print(f"\n  ? unreached by any followed path ({len(b.unreached)}) — dead, OR reached via "
              f"a path type not yet followed (dynamic dispatch / JSX / reflection):")
        for x in b.unreached[:12]:
            print(f"      {x.split('#')[-1]}  ({x.split('#')[0].replace('ts-sym:', '')})")
    return 0


def _cmd_inbound(args) -> int:
    """Inbound boundary — what each entrypoint asks for and whether it's bounded here."""
    from lattice.inbound import entrypoint_surface
    language = _LANG[args.lang]
    net, source_root = load_network(args.path, language)
    eps = entrypoint_surface(net, source_root)
    # a hole = accepts input but has no guard at the point
    holes = [e for e in eps if e.asks_for and not e.bounded]
    shown = holes if args.unbounded_only else eps
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps([e.to_dict() for e in shown], indent=2))
    declared = sum(1 for e in eps if e.kind == "entrypoint")
    print(f"[lattice] inbound surface: {len(eps)} exported callable(s) "
          f"({declared} declared program entrypoint(s)) — {len(holes)} accept input with NO "
          f"explicit bound at the point")
    print("  note: 'exported' != 'external entry' — these are facts (takes input, no guard "
          "here); the agent identifies which are true request entrypoints vs internal/UI.")
    for e in sorted(shown, key=lambda e: (e.bounded, -len(e.asks_for))):
        asks = ", ".join(e.asks_for) if e.asks_for else "—"
        if e.bounded:
            tag = f"bounded [{', '.join(e.gates_at_point)}]"
        else:
            tag = "⚠ UNBOUNDED at the point" if e.asks_for else "no input"
        print(f"  {e.location}  {e.symbol.split('#')[-1]}( {asks} )  {tag}")
    return 0


def _cmd_exposure(args) -> int:
    """Outbound boundary — for each library handoff, what's accessible to that library."""
    from lattice.exposure import library_exposure
    language = _LANG[args.lang]
    net, source_root = load_network(args.path, language)
    exp = library_exposure(net, source_root)
    if args.tainted_only:
        exp = [e for e in exp if e.tainted]
    if args.out:
        pathlib.Path(args.out).write_text(
            json.dumps([e.to_dict() for e in exp], indent=2))
    # group by library — the boundary is per-dependency
    by_lib: dict = {}
    for e in exp:
        by_lib.setdefault(e.library, []).append(e)
    tainted_total = sum(1 for e in exp if e.tainted)
    print(f"[lattice] library exposure: {len(exp)} handoff(s) across {len(by_lib)} "
          f"librar{'y' if len(by_lib) == 1 else 'ies'} — {tainted_total} carry untrusted input")
    for lib in sorted(by_lib, key=lambda l: -len(by_lib[l])):
        items = by_lib[lib]
        flag = "  ⚠ untrusted input crosses" if any(e.tainted for e in items) else ""
        print(f"  {lib}  ({len(items)} handoff(s)){flag}")
        for e in items[:8]:
            acc = ", ".join(e.accessible)
            mark = f"  ⚠ tainted: {', '.join(e.tainted)}" if e.tainted else ""
            print(f"    {e.location}  {e.callee}( {acc} ){mark}")
    return 0


def _cmd_follow(args) -> int:
    """Trace impact chains — how a change to a symbol ripples outward."""
    language = _LANG[args.lang]
    net, _ = load_network(args.path, language)
    targets = resolve_targets(net, args.symbol)
    if not targets:
        print(f"[lattice] no symbol matched '{args.symbol}'", file=sys.stderr)
        return 1
    for t in targets:
        chains = follow(net, t)
        print(f"[lattice] impact chains from {t}: {len(chains)}")
        for ch in chains[:20]:
            print("  " + " → ".join(ch))
    return 0


def _cmd_plan(args) -> int:
    """Ordered plan to land a change reliably (RRT backward planning)."""
    language = _LANG[args.lang]
    net, _ = load_network(args.path, language)
    targets = resolve_targets(net, args.symbol)
    if not targets:
        print(f"[lattice] no symbol matched '{args.symbol}'", file=sys.stderr)
        return 1
    p = plan(net, targets[0], kind=args.kind)
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(p.to_dict(), indent=2))
    print(f"[lattice] plan to {p.goal} — {len(p.steps)} step(s)"
          f"{'  ⚠ crosses public API' if p.crosses_public_api else ''}"
          f"{'  ⚠ cycle risk' if p.has_cycle_risk else ''}")
    for s in p.steps:
        print(f"  {s.order:>2}. [{s.action:9}] {s.target}  — {s.detail}")
    return 0


def _cmd_triage(args) -> int:
    """Prioritized worklist — bugs ranked by severity x blast radius."""
    language = _LANG[args.lang]
    net, _ = load_network(args.path, language)
    items = triage(net)
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps([t.to_dict() for t in items], indent=2))
    prov = items[0].provenance if items else "local"
    print(f"[lattice] triage: {len(items)} item(s), ranked by priority [{prov}]")
    for t in items:
        print(f"  P={t.priority:>4} [{t.severity:8}] {t.kind:20} {t.symbol}  (blast {t.blast_radius})")
    return 0


def _cmd_optimize(args) -> int:
    """Structural optimization suggestions — break cycles, reduce coupling."""
    language = _LANG[args.lang]
    net, _ = load_network(args.path, language)
    sugg = optimize(net, hotspot_threshold=args.hotspot_threshold)
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps([o.to_dict() for o in sugg], indent=2))
    print(f"[lattice] optimize: {len(sugg)} suggestion(s)")
    for o in sugg:
        print(f"  [{o.kind:15} score={o.score:>5.1f} {o.provenance:14}] {o.action}  — {o.rationale}")
    return 0


def _sidecar_out(args) -> pathlib.Path:
    src = pathlib.Path(args.path)
    return pathlib.Path(args.out) if args.out else src / ".footings"


def _print_update(out, r) -> None:
    if not r["updated"]:
        verdict = r["digest"]["health"]["verdict"]
        print(f"[lattice] sidecar at {out}/ — no source changes, verdict={verdict}")
        return
    dg, ch = r["digest"], r["changes"]
    cov = dg["coverage"].get("ratio", 1.0)
    chs = ", ".join(r["changed_files"][:5]) if r["changed_files"] else "initial"
    tail = (f" | changed [{chs}]: +{ch['added_vertices']}/-{ch['removed_vertices']} ({ch['verdict']})"
            if ch else " (first snapshot)")
    print(f"[lattice] sidecar at {out}/ [{r['mode']}] — verdict={dg['health']['verdict']} "
          f"coverage={cov:.2f} bugs={dg['bugs']['total']}{tail}")


def _cmd_sidecar(args) -> int:
    """Update the living sidecar once — a self-maintaining reflection of the codebase."""
    from lattice import sidecar as sc
    src = pathlib.Path(args.path)
    if not src.is_dir():
        print("[lattice] sidecar requires a source directory", file=sys.stderr)
        return 1
    out = _sidecar_out(args)
    r = sc.update(src, out, _LANG[args.lang], force=args.force)
    _print_update(out, r)
    return 1 if r["digest"]["health"]["verdict"] == "fail" else 0


def _cmd_watch(args) -> int:
    """Self-maintaining loop: poll for changes and update the sidecar automatically."""
    import time
    from lattice import sidecar as sc
    src = pathlib.Path(args.path)
    if not src.is_dir():
        print("[lattice] watch requires a source directory", file=sys.stderr)
        return 1
    out = _sidecar_out(args)
    print(f"[lattice] watching {src}/ → {out}/ (every {args.interval}s; Ctrl-C to stop)")
    i = 0
    gate_failed = False
    try:
        while args.iterations == 0 or i < args.iterations:
            r = sc.update(src, out, _LANG[args.lang])
            failed = r["digest"]["health"]["verdict"] == "fail"
            # Exit status reflects the latest snapshot. A transient failed ingest that
            # later rebuilds cleanly is a recovered watch, not a permanently failed one.
            gate_failed = failed
            if r["updated"] or failed:
                _print_update(out, r)
            i += 1
            if args.iterations == 0 or i < args.iterations:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[lattice] watch stopped")
    return 1 if gate_failed else 0


def _cmd_exchange_status(args) -> int:
    """Machine-readable status payload for Exchange/Deck."""
    from lattice.exchange_status import build_exchange_status

    language = _LANG[args.lang]
    net, _ = load_network(args.path, language)
    payload = build_exchange_status(net, source_path=str(pathlib.Path(args.path).resolve()))
    text = json.dumps(payload, indent=2 if args.pretty else None, sort_keys=args.pretty)
    if args.out:
        pathlib.Path(args.out).write_text(text + "\n")
    print(text)
    return 0


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="lattice")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ing = sub.add_parser("ingest")
    ing.add_argument("path")
    ing.add_argument("--lang", default="ts", choices=list(_LANG))
    ing.add_argument("--project", default="lattice")
    ing.add_argument("--db", default=None, help="explicit recall DB path")
    ing.add_argument("--allow-partial", action="store_true")
    ing.add_argument("--out", default="hypernetwork.json")

    ver = sub.add_parser("verify", help="differential structural check vs a git ref")
    ver.add_argument("path")
    ver.add_argument("--against", default="HEAD", help="git ref to use as baseline")
    ver.add_argument("--lang", default="ts", choices=list(_LANG))
    ver.add_argument("--allow-regression", action="store_true")
    ver.add_argument("--out", default=None, help="write diff report JSON here")

    dia = sub.add_parser("diagnose", help="structural diagnostics: cycles, dead code, stubs, hotspots")
    dia.add_argument("path")
    dia.add_argument("--lang", default="ts", choices=list(_LANG))
    dia.add_argument("--fail-on-issues", action="store_true",
                     help="exit non-zero when any issue is found (for CI gating)")
    dia.add_argument("--out", default=None, help="write full diagnostics JSON here")

    par = sub.add_parser("paradox", help="logic audit: dead branches & redundant guards")
    par.add_argument("path")
    par.add_argument("--fail-on-paradox", action="store_true",
                     help="exit non-zero when any paradox is found")
    par.add_argument("--out", default=None, help="write findings JSON here")

    imp = sub.add_parser("impact", help="change blast radius for a symbol")
    imp.add_argument("path")
    imp.add_argument("symbol", help="symbol name or vertex id to analyze")
    imp.add_argument("--lang", default="ts", choices=list(_LANG))
    imp.add_argument("--out", default=None, help="write impact report JSON here")

    fol = sub.add_parser("follow", help="trace impact chains from a symbol")
    fol.add_argument("path")
    fol.add_argument("symbol")
    fol.add_argument("--lang", default="ts", choices=list(_LANG))

    pln = sub.add_parser("plan", help="ordered plan to land a change reliably")
    pln.add_argument("path")
    pln.add_argument("symbol")
    pln.add_argument("--kind", default="modify", help="change kind (modify|rename|delete|...)")
    pln.add_argument("--lang", default="ts", choices=list(_LANG))
    pln.add_argument("--out", default=None, help="write plan JSON here")

    sec = sub.add_parser("secaudit", help="structural security audit (surface + reachability)")
    sec.add_argument("path")
    sec.add_argument("--lang", default="ts", choices=list(_LANG))
    sec.add_argument("--fail-on-findings", action="store_true",
                     help="exit non-zero on any finding")
    sec.add_argument("--out", default=None, help="write security report JSON here")

    lnk = sub.add_parser("link",
                         help="auto-link a host to its dependency graphs via a name@version registry")
    lnk.add_argument("path")
    lnk.add_argument("--registry", required=True, help="registry directory of library graphs")
    lnk.add_argument("--lang", default="ts", choices=list(_LANG))
    lnk.add_argument("--out", default=None, help="write the composed graph JSON here")

    rgall = sub.add_parser("registry-add-all",
                           help="auto-populate the registry from a project's installed dependencies")
    rgall.add_argument("path", help="project directory (with package.json + node_modules)")
    rgall.add_argument("--registry", required=True, help="registry directory")
    rgall.add_argument("--include-dev", action="store_true", help="also index devDependencies")
    rgall.add_argument("--lang", default="ts", choices=list(_LANG))

    rga = sub.add_parser("registry-add",
                         help="ingest a library and store its graph in the registry by name@version")
    rga.add_argument("path", help="library source directory (with a package.json)")
    rga.add_argument("--registry", required=True, help="registry directory")
    rga.add_argument("--name", default=None, help="override package name (else from package.json)")
    rga.add_argument("--version", default=None, help="override version (else from package.json)")
    rga.add_argument("--lang", default="ts", choices=list(_LANG))

    ree = sub.add_parser("reentrancy",
                         help="Solidity CEI-violation reentrancy (external call before state write)")
    ree.add_argument("path")
    ree.add_argument("--lang", default="sol", choices=list(_LANG))

    sla = sub.add_parser("solaudit",
                         help="Solidity vulnerability audit (reentrancy, tx.origin, unprotected sinks, ...)")
    sla.add_argument("path")
    sla.add_argument("--lang", default="sol", choices=list(_LANG))

    typ = sub.add_parser("typed",
                         help="typed-constraint-algebra audit (homology/collision/conservation obstructions)")
    typ.add_argument("path")
    typ.add_argument("--lang", default="sol", choices=list(_LANG))

    itk = sub.add_parser("intake",
                         help="complete, labeled findings+blindspots payload for the triage agent")
    itk.add_argument("path")
    itk.add_argument("--lang", default="ts", choices=list(_LANG))
    itk.add_argument("--out", default=None, help="write intake JSON here")

    fix = sub.add_parser("fix",
                         help="minimal fix: fewest edges to cut to break all obstruction cycles (math->solver)")
    fix.add_argument("path")
    fix.add_argument("--lang", default="auto", choices=list(_LANG))

    cud = sub.add_parser("cuda", help="CUDA host/device data crossings (the GPU boundary)")
    cud.add_argument("path")
    cud.add_argument("--lang", default="cpp", choices=list(_LANG))

    bar = sub.add_parser("barriers",
                         help="minimum gate placement covering every entrypoint->sink path")
    bar.add_argument("path")
    bar.add_argument("--lang", default="ts", choices=list(_LANG))

    bsp = sub.add_parser("blindspots",
                         help="where path-following goes dark — the map's honest known-unknowns")
    bsp.add_argument("path")
    bsp.add_argument("--lang", default="ts", choices=list(_LANG))
    bsp.add_argument("--out", default=None, help="write blindspots report JSON here")

    inb = sub.add_parser("inbound",
                         help="inbound boundary: what each entrypoint asks for + is it bounded")
    inb.add_argument("path")
    inb.add_argument("--lang", default="ts", choices=list(_LANG))
    inb.add_argument("--unbounded-only", action="store_true",
                     help="only entries that accept input with no guard at the point")
    inb.add_argument("--out", default=None, help="write inbound report JSON here")

    exp = sub.add_parser("exposure",
                         help="outbound boundary: what's accessible to each external library")
    exp.add_argument("path")
    exp.add_argument("--lang", default="ts", choices=list(_LANG))
    exp.add_argument("--tainted-only", action="store_true",
                     help="only handoffs where untrusted input crosses the boundary")
    exp.add_argument("--out", default=None, help="write exposure report JSON here")

    hnt = sub.add_parser("hunt", help="prioritized structural bug hunt")
    hnt.add_argument("path")
    hnt.add_argument("--lang", default="ts", choices=list(_LANG))
    hnt.add_argument("--fail-on-bugs", action="store_true",
                     help="exit non-zero on any critical/high finding")
    hnt.add_argument("--out", default=None, help="write bug findings JSON here")

    tri = sub.add_parser("triage", help="rank bugs by severity x blast radius")
    tri.add_argument("path")
    tri.add_argument("--lang", default="ts", choices=list(_LANG))
    tri.add_argument("--out", default=None, help="write triage JSON here")

    opt = sub.add_parser("optimize", help="structural optimization suggestions")
    opt.add_argument("path")
    opt.add_argument("--lang", default="ts", choices=list(_LANG))
    opt.add_argument("--hotspot-threshold", type=int, default=8,
                     help="min fan_in+fan_out to flag a coupling hotspot")
    opt.add_argument("--out", default=None, help="write suggestions JSON here")

    sc = sub.add_parser("sidecar", help="update the living sidecar (reflection + change log)")
    sc.add_argument("path")
    sc.add_argument("--lang", default="ts", choices=list(_LANG))
    sc.add_argument("--out", default=None, help="sidecar dir (default <path>/.footings)")
    sc.add_argument("--force", action="store_true", help="rebuild even if no source changed")

    wat = sub.add_parser("watch", help="auto-update the sidecar as files change")
    wat.add_argument("path")
    wat.add_argument("--lang", default="ts", choices=list(_LANG))
    wat.add_argument("--out", default=None, help="sidecar dir (default <path>/.footings)")
    wat.add_argument("--interval", type=float, default=2.0, help="poll interval seconds")
    wat.add_argument("--iterations", type=int, default=0, help="stop after N polls (0 = forever)")

    exs = sub.add_parser("exchange-status", help="emit authority-neutral status for Exchange/Deck")
    exs.add_argument("path")
    exs.add_argument("--lang", default="auto", choices=list(_LANG))
    exs.add_argument("--out", default=None, help="write status JSON here")
    exs.add_argument("--pretty", action="store_true", help="pretty-print JSON")

    args = ap.parse_args(argv)
    if args.cmd == "exchange-status":
        return _cmd_exchange_status(args)
    if args.cmd == "sidecar":
        return _cmd_sidecar(args)
    if args.cmd == "watch":
        return _cmd_watch(args)
    if args.cmd == "follow":
        return _cmd_follow(args)
    if args.cmd == "plan":
        return _cmd_plan(args)
    if args.cmd == "secaudit":
        return _cmd_secaudit(args)
    if args.cmd == "exposure":
        return _cmd_exposure(args)
    if args.cmd == "inbound":
        return _cmd_inbound(args)
    if args.cmd == "reentrancy":
        return _cmd_reentrancy(args)
    if args.cmd == "solaudit":
        return _cmd_solaudit(args)
    if args.cmd == "typed":
        return _cmd_typed(args)
    if args.cmd == "intake":
        return _cmd_intake(args)
    if args.cmd == "fix":
        return _cmd_fix(args)
    if args.cmd == "cuda":
        return _cmd_cuda(args)
    if args.cmd == "barriers":
        return _cmd_barriers(args)
    if args.cmd == "blindspots":
        return _cmd_blindspots(args)
    if args.cmd == "link":
        return _cmd_link(args)
    if args.cmd == "registry-add":
        return _cmd_registry_add(args)
    if args.cmd == "registry-add-all":
        return _cmd_registry_add_all(args)
    if args.cmd == "triage":
        return _cmd_triage(args)
    if args.cmd == "optimize":
        return _cmd_optimize(args)
    if args.cmd == "verify":
        return _cmd_verify(args)
    if args.cmd == "diagnose":
        return _cmd_diagnose(args)
    if args.cmd == "paradox":
        return _cmd_paradox(args)
    if args.cmd == "impact":
        return _cmd_impact(args)
    if args.cmd == "hunt":
        return _cmd_hunt(args)
    if args.cmd == "ingest":
        return _cmd_ingest(args)
    raise AssertionError(f"unhandled cmd: {args.cmd!r}")   # loud, not a silent fallthrough


def main(argv: list[str] | None = None) -> int:
    """CLI boundary: frontend-error graphs never reach analysis commands as clean."""
    try:
        return _main(argv)
    except GraphIngestError as exc:
        print(f"[lattice] ERROR: {exc}", file=sys.stderr)
        if exc.report.failing_checks:
            print(f"  failing_checks: {exc.report.failing_checks}", file=sys.stderr)
        # Preserve every diagnostic (including warnings adjacent to the fatal error) so
        # the public failure is actionable rather than a filtered summary.
        for diagnostic in exc.report.diagnostics:
            print(f"  diagnostic: {diagnostic}", file=sys.stderr)
        return 2
    except SourceIngestError as exc:
        # Expected environment/lifecycle failures (missing server, bounded timeout,
        # direct-file misuse) are concise CLI errors. Unexpected exceptions still
        # propagate with their traceback for debugging.
        print(f"[lattice] ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
