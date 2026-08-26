# src/lattice/ingest/solidity.py
"""Solidity ingest backend — contracts as a graph of paths, via solc's AST.

The path model maps onto Solidity unusually cleanly: public/external functions are the
inbound boundary (where untrusted txns enter), external calls (`.call`/`.transfer`/a
call on another contract) are the outbound boundary — and reentrancy is literally a path
that crosses OUT and comes back before a state effect. Inheritance (`is Base`) gives the
inherits/dispatch edges; modifiers are gates.

We use `solc --stop-after parsing --ast-compact-json`: it yields the full structural AST
even for contracts that don't type-check against the installed compiler version (the
corpus is full of old patterns), which is exactly the fact-grade structure we need. The
output feeds the SAME RawIngest -> builder pipeline as TypeScript, so every analysis —
impact, blindspots, inheritance/dispatch, the boundary commands — works unchanged.
"""
from __future__ import annotations
import bisect
import json
import os
import pathlib
import posixpath
import re
import subprocess

from lattice.ingest.types import RawIngest, RawSymbol, RawReference

_SKIP_DIRS = {"node_modules", "out", "cache", "lib", ".git", "artifacts"}  # deps / build output


# Directories / filename conventions that mark NON-PRODUCTION code (mocks, tests, foundry scripts) —
# findings there are noise for a production audit (Fei MockTokemak* / forge-std Test.sol). A single such
# file passed EXPLICITLY is still analyzed; the skip applies only to directory globbing.
_TEST_MOCK_DIRS = {"test", "tests", "mock", "mocks", "__mocks__", "testdata"}


def _is_test_or_mock(path, root) -> bool:
    rel = path.relative_to(root)
    if any(part.lower() in _TEST_MOCK_DIRS for part in rel.parts[:-1]):   # a test/mock DIRECTORY
        return True
    low = path.name.lower()
    if low.endswith(".t.sol") or low.endswith(".s.sol"):                  # foundry test / script
        return True
    stem = path.name[:-4] if path.name.endswith(".sol") else path.name
    if stem.startswith("Mock") or stem.endswith("Mock") or stem.endswith("Mocks") or stem == "Test":
        return True
    return False


def _sol_files(root) -> list:
    """The .sol files to audit under `root`: a single file when `root` IS one (analyzed even if it is a
    mock — explicit intent), else every PRODUCTION .sol in the tree minus dependency/build dirs and
    mock/test files. Handles a FILE path so an audit of one file does not silently return empty (rglob on
    a file yields nothing — a no-error 'no findings' that reads as 'no bugs')."""
    root = pathlib.Path(root)
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*.sol")
                  if not (_SKIP_DIRS & set(p.relative_to(root).parts))
                  and not _is_test_or_mock(p, root))


def _audit_rel(path, root) -> str:
    """Display path of `path` relative to the audit `root` — just the filename when `root` is a file."""
    root = pathlib.Path(root)
    return path.name if root.is_file() else path.relative_to(root).as_posix()


# Substrings marking an ACCESS-CONTROL modifier (onlyOwner/onlyGovernor/onlyRole/hasRole/...). A finding
# inside such a function is only reachable by a PRIVILEGED caller — lower exploitability, so it is
# DOWNGRADED (not suppressed: the gate may be bypassable/misconfigured, so a permissionless-equivalent bug
# must still surface). `nonReentrant`/`whenNotPaused` are NOT here — they are not authorization.
_ACCESS_MARKS = ("owner", "admin", "auth", "role", "governance", "gov", "restricted",
                 "operator", "manager", "guardian", "keeper", "permission", "onlyself",
                 "beneficiary", "minter", "controller", "pauser", "burner")


def _cond_checks_sender(cond) -> bool:
    """`require(msg.sender == X)` is a trust boundary ONLY when X is an ADMIN-like name (owner/governor/
    admin/...) — NOT a user role (`msg.sender == partyA` / depositor / channel party), where the attacker
    can simply BE that party (the SpankChain reentrancy: only `partyA` can call, but partyA is the
    attacker). So a sender-equality gate downgrades only if the other operand is privileged-named."""
    for b in _iter(cond, "BinaryOperation"):
        if b.get("operator") not in ("==", "!="):
            continue
        names = set()
        for ma in _iter(b, "MemberAccess"):
            if ma.get("memberName"):
                names.add(ma["memberName"].lower())
        for idn in _iter(b, "Identifier"):
            if idn.get("name"):
                names.add(idn["name"].lower())
        if "sender" in names and any(a in n for n in names if n != "sender" for a in _ACCESS_MARKS):
            return True
    return False


def _access_controlled(fn_node) -> str | None:
    """The access-control gate on a function — a modifier name matching `_ACCESS_MARKS`, or a body-level
    `require(msg.sender == X)` — else None. Used to DOWNGRADE (not hide) findings whose function is only
    reachable by a privileged caller."""
    for m in (fn_node.get("modifiers") or []):
        mn = (m.get("modifierName") or {}).get("name") or ""
        if any(a in mn.lower() for a in _ACCESS_MARKS):
            return mn
    body = fn_node.get("body")
    if body:
        for fc in _iter(body, "FunctionCall"):
            callee = fc.get("expression") or {}
            if callee.get("nodeType") == "Identifier" and callee.get("name") in ("require", "assert"):
                args = fc.get("arguments") or []
                if args and _cond_checks_sender(args[0]):
                    return "msg.sender check"
    return None


def _internal_callees(fn_node) -> set:
    """Names of OWN-contract functions this function calls: a bare `f(...)` (Identifier callee) or
    `this.f(...)`. Non-function callees (require/keccak256/external) are filtered by the caller against
    the contract's function set."""
    out: set = set()
    for fc in _iter(fn_node.get("body") or {}, "FunctionCall"):
        callee = fc.get("expression") or {}
        if callee.get("nodeType") == "Identifier":
            out.add(callee.get("name"))
        elif callee.get("nodeType") == "MemberAccess":
            obj = callee.get("expression") or {}
            if obj.get("nodeType") == "Identifier" and obj.get("name") == "this":
                out.add(callee.get("memberName"))
    return out


def _effectively_ac_names(contract) -> set:
    """INTERPROCEDURAL access control: the names of INTERNAL/PRIVATE functions that are NOT reachable
    from any PERMISSIONLESS external/public entry — so an attacker cannot trigger them without a
    privileged caller (the Fei CollateralizationOracle._addDeposit residual: internal, reached only via
    onlyGovernorOrAdmin entries). RECALL-SAFE by scope: only internal/private functions are added (an
    external/public function is its own entry, handled directly); a missed call edge can only FAIL to
    downgrade (stay HIGH), never wrongly downgrade a permissionless-reachable bug."""
    fns = {f.get("name"): f for f in contract.get("nodes", [])
           if f.get("nodeType") == "FunctionDefinition" and f.get("name")}
    if not fns:
        return set()
    edges = {name: (_internal_callees(fn) & set(fns)) for name, fn in fns.items()}
    # permissionless entries: external/public, not a constructor, with NO direct access control
    entries = [name for name, fn in fns.items()
               if fn.get("visibility") in ("external", "public") and fn.get("kind") != "constructor"
               and _access_controlled(fn) is None]
    reachable: set = set()
    stack = list(entries)
    while stack:
        n = stack.pop()
        if n in reachable:
            continue
        reachable.add(n)
        stack.extend(edges.get(n, ()))
    return {name for name, fn in fns.items()
            if fn.get("visibility") in ("internal", "private") and name not in reachable}
_LOW_LEVEL = {"call", "delegatecall", "staticcall", "transfer", "send"}     # external/value calls
# Only gas-forwarding calls enable REENTRANCY. `.transfer`/`.send` forward a fixed 2300-gas
# stipend (the callee cannot make another call or write storage); `.staticcall` is read-only.
# So the reentrancy boundary is narrower than the general low-level-call set.
_REENTRANT_CALLS = {"call", "delegatecall"}


_PRAGMA = re.compile(r"pragma\s+solidity[^;]*;")
_PRAGMA_VER = re.compile(r"pragma\s+solidity\s+([^;]+);")
_VER = re.compile(r"([\^>=<~]*)\s*(\d+)\.(\d+)(?:\.(\d+))?")
_ARTIFACTS = pathlib.Path.home() / ".solc-select" / "artifacts"


def _installed_solc() -> dict:
    """version (maj,min,patch) -> binary path, from solc-select's cached artifacts. Lets us invoke
    a SPECIFIC compiler per file's pragma without mutating solc-select's global version."""
    out: dict = {}
    if _ARTIFACTS.is_dir():
        for d in _ARTIFACTS.iterdir():
            m = re.match(r"solc-(\d+)\.(\d+)\.(\d+)$", d.name)
            if m:
                b = d / d.name
                if b.exists():
                    out[tuple(int(x) for x in m.groups())] = str(b)
    return out


def _pragma_constraint(src: str):
    """(op, maj, min, patch) of the first solidity pragma — ('^',0,8,0), ('',0,8,30) — or None."""
    m = _PRAGMA_VER.search(src)
    if not m:
        return None
    vm = _VER.search(m.group(1))
    if not vm:
        return None
    return (vm.group(1) or "", int(vm.group(2)), int(vm.group(3)), int(vm.group(4) or 0))


def _select_solc(src: str):
    """(binary_path, version) for the best INSTALLED solc satisfying the pragma, or None to use the
    default `solc`. ^x.y.z -> highest installed x.y.*; exact -> that version; >= -> highest >=."""
    c = _pragma_constraint(src)
    if not c:
        return None
    op, maj, mi, pa = c
    installed = _installed_solc()
    target = (maj, mi, pa)

    def ok(v):
        if op == "^":
            return v[0] == maj and v[1] == mi and v >= target
        if op in ("=", ""):
            return v == target
        if op in (">=", ">"):
            return v >= target
        if op in ("<=", "<"):
            return v <= target
        if op == "~":
            return v[0] == maj and v[1] == mi and v >= target
        return v[0] == maj and v[1] == mi

    cands = [v for v in installed if ok(v)] or [v for v in installed if v[0] == maj and v[1] == mi]
    if not cands:
        return None
    best = max(cands)
    return (installed[best], best)


def _run_solc(target: str, binary: str = "solc", version=None) -> dict | None:
    cmd = [binary, "--ast-compact-json", target]
    if version is None or version >= (0, 6, 0):       # --stop-after parsing exists from 0.6.0
        cmd = [binary, "--stop-after", "parsing", "--ast-compact-json", target]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    i = r.stdout.find("{")
    if i < 0:
        return None
    try:
        return json.loads(r.stdout[i:])
    except ValueError:
        return None


def _solc_ast(path: pathlib.Path) -> dict | None:
    """Parse a contract to its structural AST, VERSION-AWARE: pick the installed solc matching the
    file's pragma (so a 0.8.30 / 0.6.x / 0.7.x file isn't lost to the default compiler). Fall back to
    the default `solc` with the pragma relaxed to the current compiler for the syntactically-compatible
    0.7↔0.8 case when no matching version is installed."""
    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    sel = _select_solc(src)
    if sel is not None:
        ast = _run_solc(str(path), sel[0], sel[1])    # the matching compiler
        if ast is not None:
            return ast
    ast = _run_solc(str(path))                         # the default compiler
    if ast is not None:
        return ast
    # ROBUSTNESS SWEEP: relax the version pragma and try installed compilers OLDEST-first. This
    # recovers (a) an exact pin to an uncached version (`pragma 0.4.15;` — a nearby 0.4.x accepts
    # it once relaxed; SpankChain) and (b) a no-pragma pre-0.5 contract whose syntax the default
    # compiler rejects (theRun/Lottery). One compiler per minor bounds this to ~6 tries, and it
    # only runs on the failure path — so normal files pay nothing. Anything that still fails to
    # parse here genuinely cannot be read, and solidity_audit escalates a parse_failure blindspot.
    relaxed = _PRAGMA.sub("pragma solidity >=0.4.0;", src, count=1)
    installed = _installed_solc()
    # only compilers that can emit the compact-JSON AST the pipeline needs (the flag was added in
    # 0.4.12); older binaries (0.3.x, early 0.4.x) produce a different, incompatible legacy AST, so
    # trying them just wastes a subprocess. (Contracts whose syntax predates 0.4.12 — e.g. The DAO's
    # bare `_` / value-returning fallbacks, Parity WalletLibrary's old assembly — are therefore an
    # honest hard boundary: they escalate a parse_failure, never a silent all-clear.)
    cjson = {v: b for v, b in installed.items() if v >= (0, 4, 12)}
    if not cjson:
        return None
    per_minor: dict = {}
    for v in cjson:                                    # highest patch within each (major, minor)
        if v[:2] not in per_minor or v > per_minor[v[:2]]:
            per_minor[v[:2]] = v
    sweep = [per_minor[k] for k in sorted(per_minor)]  # oldest minor first
    import tempfile
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as tf:
            tf.write(relaxed)
            tmp = tf.name
        for ver in sweep:
            ast = _run_solc(tmp, cjson[ver], ver)
            if ast is not None:
                return ast
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return None


def _byte_line(nl: list[int], src: str) -> int:
    """Line number from a solc `src` ("byteStart:len:fileIdx"), using newline offsets."""
    return bisect.bisect_right(nl, int(src.split(":")[0])) + 1


def _base_names(contract: dict) -> list[str]:
    out: list[str] = []
    for b in contract.get("baseContracts", []) or []:
        bn = b.get("baseName", {})
        name = bn.get("name") or bn.get("namePath")
        if name:
            out.append(name.split(".")[-1])
    return out


def _calls_in(node, nl: list[int]):
    """Yield ``(line, callee, receiver, external)`` for each function call."""
    if isinstance(node, dict):
        if node.get("nodeType") == "FunctionCall":
            expr = node.get("expression", {})
            if expr.get("nodeType") == "FunctionCallOptions":
                expr = expr.get("expression", {})       # unwrap `.call{value: x}(...)`
            et = expr.get("nodeType")
            line = _byte_line(nl, node.get("src", "0:0:0"))
            if et == "MemberAccess":
                member = expr.get("memberName", "")
                receiver = _sol_expr_name(expr.get("expression") or {})
                # low-level calls are unambiguously external; other member calls
                # (`other.method()`) are external handoffs too (the callee isn't local).
                yield (line, member, receiver, True)
            elif et == "Identifier":
                yield (line, expr.get("name", ""), None, False)  # internal call by name
        for v in node.values():
            yield from _calls_in(v, nl)
    elif isinstance(node, list):
        for x in node:
            yield from _calls_in(x, nl)


def _sol_expr_name(node: dict) -> str | None:
    nt = node.get("nodeType")
    if nt == "Identifier":
        return node.get("name")
    if nt == "MemberAccess":
        base = _sol_expr_name(node.get("expression") or {})
        member = node.get("memberName")
        return f"{base}.{member}" if base and member else member
    return None


def _mask_solidity_comments(source: str) -> str:
    """Replace comments with spaces while preserving strings and newline offsets."""
    chars = list(source)
    i = 0
    quote: str | None = None
    while i < len(chars):
        ch = chars[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < len(chars) and chars[i + 1] == "/":
            chars[i] = chars[i + 1] = " "
            i += 2
            while i < len(chars) and chars[i] != "\n":
                chars[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < len(chars) and chars[i + 1] == "*":
            chars[i] = chars[i + 1] = " "
            i += 2
            while i < len(chars):
                if i + 1 < len(chars) and chars[i] == "*" and chars[i + 1] == "/":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    break
                if chars[i] != "\n":
                    chars[i] = " "
                i += 1
            continue
        i += 1
    return "".join(chars)


def _solidity_imports(source: str):
    masked = _mask_solidity_comments(source)
    i = 0
    while i < len(masked):
        if masked[i] in ("'", '"'):
            quote = masked[i]
            i += 1
            while i < len(masked):
                if masked[i] == "\\":
                    i += 2
                elif masked[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            continue
        if masked[i].isalpha() or masked[i] == "_":
            start = i
            i += 1
            while i < len(masked) and (masked[i].isalnum() or masked[i] == "_"):
                i += 1
            if masked[start:i] != "import":
                continue
            line = masked.count("\n", 0, start) + 1
            paths: list[str] = []
            while i < len(masked) and masked[i] != ";":
                if masked[i] not in ("'", '"'):
                    i += 1
                    continue
                quote = masked[i]
                i += 1
                value: list[str] = []
                while i < len(masked) and masked[i] != quote:
                    if masked[i] == "\\" and i + 1 < len(masked):
                        value.append(masked[i + 1])
                        i += 2
                    else:
                        value.append(masked[i])
                        i += 1
                if i < len(masked):
                    i += 1
                paths.append("".join(value))
            if paths:
                yield line, paths[-1]
            if i < len(masked):
                i += 1
            continue
        i += 1


def solidity_ingest(root, language: str = "solidity") -> RawIngest:
    root = pathlib.Path(root)
    direct_file = root if root.is_file() else None
    if direct_file is not None:
        sol_files = [direct_file] if direct_file.suffix == ".sol" else []
        root = root.parent
    else:
        sol_files = sorted(
            p for p in root.rglob("*.sol")
            if not (_SKIP_DIRS & set(p.relative_to(root).parts)))

    symbols: list[RawSymbol] = []
    references: list[RawReference] = []
    diagnostics: list[dict] = []
    files = [path.relative_to(root).as_posix() for path in sol_files]
    known = set(files)
    pending: list[tuple] = []  # (file, line, callee, receiver, external, contract)
    contract_kinds: dict[tuple[str, str], str] = {}
    contract_bases: dict[tuple[str, str], list[str]] = {}
    method_metadata: dict[tuple[str, int, str, str], tuple[str, str]] = {}

    if not sol_files:
        kind = "unsupported_source_file" if direct_file is not None else "no_source_files"
        diagnostics.append({
            "kind": kind, "severity": "error", "language": "solidity",
            **({"file": direct_file.name} if direct_file is not None else {}),
            "message": (f"expected a .sol source file, got {direct_file.name}"
                        if direct_file is not None
                        else "no Solidity source files found"),
        })
        return RawIngest(language="solidity", root=str(root), diagnostics=diagnostics,
                         files=files)

    for path in sol_files:
        rel = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            diagnostics.append({
                "kind": "read_error", "severity": "error", "language": "solidity",
                "file": rel, "message": str(exc),
            })
            continue
        for line, spec in _solidity_imports(source):
            if spec.startswith("."):
                target = posixpath.normpath(str(pathlib.PurePosixPath(rel).parent / spec))
                resolved = target in known
                references.append(RawReference(
                    kind="imports", from_file=rel, from_line=line,
                    to_file=target, to_line=1 if resolved else None,
                    resolved=resolved, name=spec))
            else:
                target = posixpath.normpath(spec)
                resolved = target in known
                references.append(RawReference(
                    kind="imports", from_file=rel, from_line=line,
                    to_file=target if resolved else None,
                    to_line=1 if resolved else None, resolved=resolved, name=spec))

        ast = _solc_ast(path)
        if ast is None:
            diagnostics.append({
                "kind": "parse_error", "severity": "error", "language": "solidity",
                "file": rel,
                "message": "file failed to parse with the selected, default, and relaxed solc paths",
            })
            continue
        data = path.read_bytes()
        nl = [i for i, b in enumerate(data) if b == 0x0A]

        for node in _iter(ast, "ContractDefinition"):
            cname = node.get("name", "")
            cstart, cend = _span(node["src"], nl)
            contract_kind = node.get("contractKind", "contract")
            contract_kinds[(rel, cname)] = contract_kind
            contract_bases[(rel, cname)] = _base_names(node)
            kind = "interface" if contract_kind == "interface" else "class"
            symbols.append(RawSymbol(
                name=cname, kind=kind, file=rel, start_line=cstart, end_line=cend,
                exported=True, extends=_base_names(node)))
            for fn in node.get("nodes", []):
                if fn.get("nodeType") != "FunctionDefinition":
                    continue
                fname = fn.get("name") or fn.get("kind", "function")   # constructor/fallback/receive
                fstart, fend = _span(fn["src"], nl)
                visibility = fn.get("visibility", "")
                exported = visibility in ("public", "external")
                symbols.append(RawSymbol(
                    name=fname, kind="method", file=rel, start_line=fstart, end_line=fend,
                    container=cname, exported=exported))
                method_metadata[(rel, fstart, cname, fname)] = (visibility, contract_kind)
                for line, callee, receiver, external in _calls_in(fn.get("body") or {}, nl):
                    pending.append((rel, line, callee, receiver, external, cname))

    by_name: dict[str, list[RawSymbol]] = {}
    for symbol in symbols:
        if symbol.kind == "method":
            by_name.setdefault(symbol.name, []).append(symbol)
    type_files: dict[str, set[str]] = {}
    for symbol in symbols:
        if symbol.kind in ("class", "interface"):
            type_files.setdefault(symbol.name, set()).add(symbol.file)

    def type_locations(name: str, context_file: str) -> tuple[list[str], bool]:
        files = type_files.get(name, set())
        if context_file in files:
            return [context_file], False
        if len(files) == 1:
            return list(files), False
        return sorted(files), len(files) > 1

    def base_implementations(from_file: str, contract: str,
                             method: str) -> tuple[list[RawSymbol], bool]:
        seen: set[tuple[str, str]] = set()
        stack: list[tuple[str, str]] = []
        ambiguous = False
        for base in contract_bases.get((from_file, contract), []):
            locations, is_ambiguous = type_locations(base, from_file)
            ambiguous = ambiguous or is_ambiguous
            stack.extend((location, base) for location in locations)
        candidates: list[RawSymbol] = []
        while stack:
            base_file, base = stack.pop(0)
            key = (base_file, base)
            if key in seen:
                continue
            seen.add(key)
            candidates.extend(s for s in by_name.get(method, [])
                              if s.file == base_file and s.container == base)
            for parent in contract_bases.get(key, []):
                locations, is_ambiguous = type_locations(parent, base_file)
                ambiguous = ambiguous or is_ambiguous
                stack.extend((location, parent) for location in locations)
        return candidates, ambiguous

    for from_file, from_line, callee, receiver, external, container in pending:
        if external:
            full = f"{receiver}.{callee}" if receiver else callee
            if receiver == "super":
                candidates, ambiguous = base_implementations(from_file, container, callee)
                if not ambiguous and len(candidates) == 1:
                    tgt = candidates[0]
                    references.append(RawReference(
                        kind="references", from_file=from_file, from_line=from_line,
                        to_file=tgt.file, to_line=tgt.start_line,
                        resolved=True, name=full,
                    ))
                else:
                    references.append(RawReference(
                        kind="references", from_file=from_file, from_line=from_line,
                        to_file=from_file, resolved=False, name=full,
                    ))
                continue
            target_container = container if receiver == "this" else receiver
            resolved_target: RawSymbol | None = None
            target_files, ambiguous_type = type_locations(target_container or "", from_file)
            if not ambiguous_type and target_files:
                candidates = [s for s in by_name.get(callee, [])
                              if s.file in target_files and s.container == target_container]
                if len(candidates) == 1:
                    tgt = resolved_target = candidates[0]
                    references.append(RawReference(
                        kind="references", from_file=from_file, from_line=from_line,
                        to_file=tgt.file, to_line=tgt.start_line,
                        resolved=True, name=full,
                    ))
            # `this.foo()` always crosses the EVM boundary. A statically named
            # library call does so only for its public/external ABI; internal/private
            # library calls compile as local jumps. Base/type-qualified contract calls
            # are likewise local. Unknown/variable receivers remain outbound unknowns.
            boundary = receiver == "this" or resolved_target is None
            if resolved_target is not None and receiver != "this":
                visibility, contract_kind = method_metadata.get(
                    (resolved_target.file, resolved_target.start_line,
                     resolved_target.container or "", resolved_target.name),
                    ("", contract_kinds.get(
                        (resolved_target.file, target_container or ""), "")),
                )
                boundary = (contract_kind == "library"
                            and visibility in ("public", "external"))
            if boundary:
                references.append(RawReference(kind="references", from_file=from_file,
                                               from_line=from_line, resolved=False,
                                               name=f"external:{full}"))
            continue
        candidates = [s for s in by_name.get(callee, [])
                      if s.file == from_file and s.container == container]
        if len(candidates) == 1:
            tgt = candidates[0]
            name = f"{container}.{callee}" if len(by_name.get(callee, [])) > 1 else callee
            references.append(RawReference(kind="references", from_file=from_file,
                                           from_line=from_line, to_file=tgt.file,
                                           to_line=tgt.start_line, resolved=True, name=name))
        else:
            references.append(RawReference(kind="references", from_file=from_file,
                                           from_line=from_line, resolved=False, name=callee))

    return RawIngest(language="solidity", root=str(root), symbols=symbols,
                     references=references, diagnostics=diagnostics, files=files)


def _base_ident(node) -> str | None:
    """The root identifier of an lvalue (`balances[msg.sender]` -> `balances`)."""
    while isinstance(node, dict):
        nt = node.get("nodeType")
        if nt == "Identifier":
            return node.get("name")
        if nt == "IndexAccess":
            node = node.get("baseExpression", {})
        elif nt == "MemberAccess":
            node = node.get("expression", {})
        else:
            return None
    return None


def _collect_reentry(node, state_vars: set, ext_calls: list, state_writes: list):
    if isinstance(node, dict):
        nt = node.get("nodeType")
        if nt == "FunctionCall":
            expr = _unwrap_lowlevel_expr(node.get("expression", {}))
            if expr.get("nodeType") == "MemberAccess" and expr.get("memberName") in _LOW_LEVEL:
                ext_calls.append(int(node.get("src", "0:0:0").split(":")[0]))
        elif nt == "Assignment" and _base_ident(node.get("leftHandSide", {})) in state_vars:
            state_writes.append(int(node.get("src", "0:0:0").split(":")[0]))
        for v in node.values():
            _collect_reentry(v, state_vars, ext_calls, state_writes)
    elif isinstance(node, list):
        for x in node:
            _collect_reentry(x, state_vars, ext_calls, state_writes)


_UNCHECKED_LOWLEVEL = ("call", "delegatecall", "send")    # narrow: NOT transfer (auto-reverts)
_AUTHORITY = ("owner", "admin", "creator", "master", "root", "governor", "governance", "ceo")
_RNG_BLOCK = {"timestamp", "number", "difficulty", "coinbase", "blockhash", "prevrandao"}


def _unwrap_lowlevel_expr(expr: dict) -> dict:
    """Unwrap a call expression to its underlying MemberAccess: `.call{value:..}(..)` options AND the
    legacy curried `.call.value(x)()` / `.call.gas(g)()` chains (pre-0.8 — the dominant idiom in the
    SWC corpus), where the `.call` indicator is wrapped in a `.value()`/`.gas()` FunctionCall."""
    while True:
        if expr.get("nodeType") == "FunctionCallOptions":
            expr = expr.get("expression", {})
        elif (expr.get("nodeType") == "FunctionCall"
              and (expr.get("expression") or {}).get("nodeType") == "MemberAccess"
              and (expr.get("expression") or {}).get("memberName") in ("value", "gas")):
            expr = expr["expression"]["expression"]
        else:
            return expr


def _lowlevel_member(call: dict) -> str | None:
    """The low-level member of a FunctionCall (`.call`/`.send`/`.delegatecall`), unwrapping both the
    modern options and the legacy curried `.call.value(x)()` form; else None."""
    expr = _unwrap_lowlevel_expr(call.get("expression", {}))
    if expr.get("nodeType") == "MemberAccess":
        return expr.get("memberName")
    return None


def _collect_facts(node, state_vars: set, facts: dict, in_loop: bool = False):
    """One walk per function collecting every structural fact the detectors need."""
    if isinstance(node, dict):
        nt = node.get("nodeType")
        loop = in_loop or nt in ("ForStatement", "WhileStatement", "DoWhileStatement")
        if nt == "FunctionCall":
            expr = _unwrap_lowlevel_expr(node.get("expression", {}))
            pos = int(node.get("src", "0:0:0").split(":")[0])
            if expr.get("nodeType") == "MemberAccess":
                mn = expr.get("memberName")
                if mn in ("call", "transfer", "send"):
                    facts["ext_calls"].append(pos)
                    if in_loop:                                # external value transfer in a loop
                        facts["loop_calls"].append(pos)
                    # push payment to a STORED address (SWC-113): a malicious stored party can
                    # revert and block everyone (vs pushing to msg.sender — the safe pull pattern).
                    if mn in ("transfer", "send") and _base_ident(expr.get("expression", {})) in state_vars:
                        facts["push_to_stored"].append(pos)
                elif mn == "delegatecall":
                    facts["delegatecalls"].append(pos)
                elif mn == "push" and in_loop:                # state-array growth in a loop (DoS)
                    if _base_ident(expr.get("expression", {})) in state_vars:
                        facts["growth_loops"].append(pos)
            elif expr.get("nodeType") == "Identifier":
                name = expr.get("name")
                if name in ("selfdestruct", "suicide"):
                    facts["selfdestructs"].append(pos)
                elif name == "blockhash":
                    facts["rng_seeds"].append(pos)            # blockhash() as a randomness source
                elif name == "require" and '"memberName": "sender"' in json.dumps(node):
                    facts["auth_checks"].append(pos)          # inline require(msg.sender == ...) guard
        elif nt == "IfStatement" and '"memberName": "sender"' in json.dumps(node.get("condition", {})):
            facts["auth_checks"].append(0)                    # `if (msg.sender != x) revert` guard
        elif nt == "InlineAssembly":
            facts["has_assembly"].append(int(node.get("src", "0:0:0").split(":")[0]))
        elif nt == "Identifier" and node.get("name") == "now":
            facts["rng_seeds"].append(int(node.get("src", "0:0:0").split(":")[0]))  # `now` (block.timestamp)
        elif nt == "BinaryOperation":
            op = node.get("operator")
            if op == "%":
                facts["has_modulo"].append(int(node.get("src", "0:0:0").split(":")[0]))
            elif op in ("==", "!="):
                blob = json.dumps(node)
                if '"memberName": "origin"' in blob and '"memberName": "sender"' in blob:
                    facts["safe_txorigin"].append(0)          # msg.sender==tx.origin (anti-contract)
                # strict equality on this.balance (SWC-132): an attacker force-sends ether via
                # selfdestruct to break the invariant — balance can be assumed >=, never ==.
                if '"memberName": "balance"' in blob and '"name": "this"' in blob:
                    facts["balance_invariant"].append(int(node.get("src", "0:0:0").split(":")[0]))
            if op in ("<", ">", "<=", ">=", "==", "!="):
                # block.timestamp / now inside a COMPARISON gates control flow on a
                # miner-manipulable value (SWC-116) — a stored timestamp (assignment) does not.
                blob = json.dumps(node)
                if ('"memberName": "timestamp"' in blob and '"name": "block"' in blob) \
                        or '"name": "now"' in blob:
                    facts["time_gates"].append(int(node.get("src", "0:0:0").split(":")[0]))
        elif nt == "VariableDeclarationStatement" and not node.get("initialValue"):
            # An uninitialized REFERENCE-type local aliases slot 0 — writes corrupt low slots
            # (SWC-109). The dangerous form is pre-0.5 IMPLICIT storage: `NameRecord r;` with no
            # `storage`/`memory` keyword (storageLocation 'default') defaults to storage and the
            # developer rarely realises it. Value-type locals (uint x;) are stack, never a pointer,
            # so the reference-type typeName gate is what keeps this from firing on every local.
            for d in (node.get("declarations") or []):
                if d and d.get("storageLocation") in ("storage", "default") \
                        and (d.get("typeName") or {}).get("nodeType") in (
                            "UserDefinedTypeName", "ArrayTypeName", "Mapping"):
                    facts["uninit_storage"].append(int(node.get("src", "0:0:0").split(":")[0]))
        elif nt == "ExpressionStatement":
            # a low-level call that IS the statement = its bool return is discarded (unchecked)
            e = node.get("expression", {})
            if e.get("nodeType") == "FunctionCall" and _lowlevel_member(e) in _UNCHECKED_LOWLEVEL:
                facts["unchecked_calls"].append(int(e.get("src", "0:0:0").split(":")[0]))
        elif nt == "Assignment":
            pos2 = int(node.get("src", "0:0:0").split(":")[0])
            base = _base_ident(node.get("leftHandSide", {}))
            if base in state_vars:
                facts["state_writes"].append(pos2)
                if base and any(a in base.lower() for a in _AUTHORITY):
                    facts["authority_writes"].append(pos2)    # writes a privileged var (access control)
                op = node.get("operator", "=")
                rhs = node.get("rightHandSide", {})
                if op in ("+=", "-=", "*=") or (op == "=" and rhs.get("nodeType") == "BinaryOperation"
                                                and rhs.get("operator") in ("+", "-", "*")):
                    facts["arith_writes"].append(pos2)        # arithmetic on a state var (overflow risk pre-0.8)
        elif nt == "MemberAccess":
            mn = node.get("memberName")
            e = node.get("expression", {})
            if mn == "origin" and e.get("nodeType") == "Identifier" and e.get("name") == "tx":
                facts["tx_origin"].append(int(node.get("src", "0:0:0").split(":")[0]))
            elif mn in _RNG_BLOCK and e.get("nodeType") == "Identifier" and e.get("name") == "block":
                facts["rng_seeds"].append(int(node.get("src", "0:0:0").split(":")[0]))
        for v in node.values():
            _collect_facts(v, state_vars, facts, loop)
    elif isinstance(node, list):
        for x in node:
            _collect_facts(x, state_vars, facts, in_loop)


def solidity_audit(source_root) -> list[dict]:
    """Structural Solidity vulnerability audit over the solc AST. Each finding is a path/
    ordering/guard fact: reentrancy (CEI), tx.origin auth, and selfdestruct/delegatecall
    reachable with no access control. One walk per function feeds every detector."""
    root = pathlib.Path(source_root)
    # reentrancy now comes from the SHEAF OBSTRUCTION (cross-function, FP-resistant); the
    # per-function loop below adds the other detectors.
    out: list[dict] = reentrancy_obstructions(source_root)
    files = _sol_files(root)
    # PROJECT-WIDE pre-pass: parse every file once and build the global contract -> (own vars, bases)
    # maps, so inheritance — including CROSS-FILE `is Base` — resolves for shadowing + the authority
    # model (per-file maps made cross-file shadowing and inherited-guard writes silent blind spots).
    asts: dict = {}
    proj_vars: dict = {}     # contract name -> its OWN directly-declared state-var names
    proj_bases: dict = {}    # contract name -> immediate base names
    for path in files:
        ast = _solc_ast(path)
        asts[path] = ast
        if ast is None:
            continue
        for c in _iter(ast, "ContractDefinition"):
            nm = c.get("name")
            proj_vars[nm] = {n.get("name") for n in c.get("nodes", [])
                             if n.get("nodeType") == "VariableDeclaration"}
            proj_bases[nm] = _base_names(c)

    def _inherited_vars(name, seen=None):
        """Transitive union of every base contract's state vars (whole inheritance closure)."""
        seen = seen if seen is not None else set()
        if name in seen:
            return set()
        seen.add(name)
        acc = set()
        for b in proj_bases.get(name, []):
            acc |= proj_vars.get(b, set())
            acc |= _inherited_vars(b, seen)
        return acc

    for path in files:
        rel = _audit_rel(path, root)
        ast = asts.get(path)
        if ast is None:
            # NO-SILENT-FN footing: a parse failure means the file was NOT analyzed. Emit a
            # LOUD blindspot so the consuming agent never mistakes "couldn't read it" for
            # "clean" — this is byte-distinct from a genuinely empty result.
            out.append({"kind": "parse_failure", "severity": "high", "contract": "",
                        "function": "", "file": rel, "line": 1,
                        "detail": "file failed to parse under every installed/relaxed solc — NOT "
                                  "ANALYZED; treat as an unaudited blind spot, do NOT assume clean"})
            continue
        nl = [i for i, b in enumerate(path.read_bytes()) if b == 0x0A]
        src_text = path.read_text(encoding="utf-8", errors="ignore")
        pc = _pragma_constraint(src_text)
        pre08 = bool(pc) and pc[1] == 0 and pc[2] < 8        # pre-0.8: no built-in overflow checks
        pre05 = bool(pc) and pc[1] == 0 and pc[2] < 5        # pre-0.5: implicit-storage-pointer footgun exists
        for contract in _iter(ast, "ContractDefinition"):
            cname = contract.get("name", "")
            own_vars = proj_vars.get(cname, {n.get("name") for n in contract.get("nodes", [])
                                             if n.get("nodeType") == "VariableDeclaration"})
            inherited = _inherited_vars(cname)
            # inherited state vars ARE accessible here, so detectors keyed on state writes
            # (authority / arithmetic / etc.) must see them too, not only own declarations.
            state_vars = own_vars | inherited
            # SWC-119: an own var that also exists anywhere in the inheritance closure is shadowed —
            # a base read (e.g. an access-control check) sees a different slot than the derived write.
            shadowed = own_vars & inherited
            if shadowed:
                out.append({"kind": "variable_shadowing", "severity": "medium",
                            "contract": cname, "function": "", "file": rel,
                            "line": _span(contract.get("src", "0:0:0"), nl)[0],
                            "detail": f"contract '{cname}' re-declares inherited state var(s) "
                                      f"{sorted(shadowed)} — the base slot is shadowed (SWC-119)"})
            for fn in contract.get("nodes", []):
                if fn.get("nodeType") != "FunctionDefinition":
                    continue
                fname = fn.get("name") or fn.get("kind", "function")
                vis = fn.get("visibility", "")
                # a <0.5 same-name constructor (or an explicit `constructor`) runs once at deploy
                # and is NOT publicly callable — writes to owner/etc. there are not a takeover.
                is_ctor = (fn.get("kind") == "constructor" or fn.get("isConstructor")
                           or (bool(fname) and fname == cname))
                mods = [m.get("modifierName", {}).get("name") for m in fn.get("modifiers", [])]
                facts = {k: [] for k in ("ext_calls", "delegatecalls", "selfdestructs",
                                         "state_writes", "tx_origin", "auth_checks",
                                         "unchecked_calls", "loop_calls", "has_assembly",
                                         "safe_txorigin", "authority_writes", "rng_seeds",
                                         "has_modulo", "growth_loops", "arith_writes",
                                         "uninit_storage", "time_gates", "push_to_stored",
                                         "balance_invariant")}
                _collect_facts(fn.get("body") or {}, state_vars, facts)

                def at(pos):
                    return _byte_line(nl, f"{pos}::")

                # (reentrancy is handled by reentrancy_obstructions — the sheaf H¹ detector)
                # tx.origin authentication — but NOT the safe `msg.sender == tx.origin`
                # anti-contract pattern (which compares the two rather than authing on origin)
                if len(facts["tx_origin"]) > len(facts["safe_txorigin"]):
                    out.append({"kind": "tx_origin_auth", "severity": "high", "contract": cname,
                                "function": fname, "file": rel, "line": at(facts["tx_origin"][0]),
                                "detail": "tx.origin used for authentication (phishable)"})
                # selfdestruct/delegatecall with NO access control (no modifier, no inline guard).
                # A constructor is excluded — it only runs at deploy, so it is not a public sink.
                unguarded = (vis in ("public", "external") and not mods
                             and not facts["auth_checks"] and not is_ctor)
                if unguarded and facts["selfdestructs"]:
                    out.append({"kind": "unprotected_selfdestruct", "severity": "critical",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["selfdestructs"][0]),
                                "detail": "selfdestruct reachable with no access control"})
                if unguarded and facts["delegatecalls"]:
                    out.append({"kind": "unprotected_delegatecall", "severity": "critical",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["delegatecalls"][0]),
                                "detail": "delegatecall reachable with no access control"})
                # unprotected privileged-state write (SWC-105/118) — a public/external fn with no
                # access guard that writes an authority var (owner/admin): anyone can seize control
                if unguarded and facts["authority_writes"]:
                    out.append({"kind": "unprotected_state_write", "severity": "high",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["authority_writes"][0]),
                                "detail": "public function writes a privileged var (owner/admin) with "
                                          "no access control — anyone can take over"})
                # weak randomness (SWC-120) — a block property used as a randomness/decision seed
                if facts["rng_seeds"] and (facts["has_modulo"] or
                                           any(s in json.dumps(fn) for s in ("difficulty", "coinbase", "blockhash"))):
                    out.append({"kind": "weak_randomness", "severity": "high",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["rng_seeds"][0]),
                                "detail": "block property (timestamp/number/blockhash/difficulty) used as a "
                                          "randomness seed — miner/validator can bias the outcome"})
                # unchecked integer overflow/underflow (SWC-101) — RAW arithmetic on a state var in
                # a pre-0.8 contract (before 0.8 the EVM wraps silently). `arith_writes` holds only
                # raw ops (BinaryOperation / compound-assign), never SafeMath `.add()` calls — so a
                # contract IMPORTING SafeMath but doing a raw `+=` is still unchecked there. (A blanket
                # 'contains SafeMath → safe' gate hid 27/50 SolidiFI Overflow injections.)
                if pre08 and facts["arith_writes"]:
                    out.append({"kind": "unchecked_arithmetic", "severity": "high",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["arith_writes"][0]),
                                "detail": "arithmetic on a state var in a pre-0.8 contract without "
                                          "SafeMath — silent overflow/underflow"})
                # forced-ether / balance-invariant (SWC-132) — strict equality on this.balance
                if facts["balance_invariant"]:
                    out.append({"kind": "forced_ether_invariant", "severity": "medium",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["balance_invariant"][0]),
                                "detail": "strict equality on this.balance — an attacker can force-send "
                                          "ether (selfdestruct) to break the invariant; assume >= not =="})
                # DoS push-payment (SWC-113) — value pushed to a stored address that can revert
                if facts["push_to_stored"]:
                    out.append({"kind": "dos_push_payment", "severity": "medium",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["push_to_stored"][0]),
                                "detail": "value pushed to a STORED address — a malicious recipient can "
                                          "revert and permanently block the function (use pull payments)"})
                # unbounded-loop DoS — a state array grown inside a loop (gas exhaustion / block-stuffing)
                if facts["growth_loops"]:
                    out.append({"kind": "dos_unbounded_loop", "severity": "medium",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["growth_loops"][0]),
                                "detail": "state array grown inside a loop — unbounded gas/storage growth "
                                          "can make the contract un-callable (DoS)"})
                # uninitialized storage pointer (SWC-109) — aliases slot 0, silently corrupts state.
                # ONLY a pre-0.5 bug: >=0.5 makes a default-location reference local a compile error,
                # and in parse-mode 'default' just means 'unresolved' (not implicit storage) — so
                # gating on pre05 kills the pragma-blind false positives on modern code.
                if pre05 and facts["uninit_storage"]:
                    out.append({"kind": "uninitialized_storage_pointer", "severity": "high",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["uninit_storage"][0]),
                                "detail": "uninitialized local storage pointer aliases slot 0 — "
                                          "writes through it overwrite unrelated state variables"})
                # timestamp dependence (SWC-116) — control flow gated on block.timestamp/now, which a
                # miner can nudge ~15s. SCREEN: a legitimate deadline check trips this too (agent judges).
                if facts["time_gates"]:
                    out.append({"kind": "timestamp_dependence", "severity": "low",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["time_gates"][0]),
                                "detail": "control flow compares against block.timestamp/now — a miner can "
                                          "bias the result within ~15s; avoid for randomness or tight deadlines"})
                # unchecked low-level call — bool return discarded (silent failure)
                for pos in facts["unchecked_calls"]:
                    out.append({"kind": "unchecked_external_call", "severity": "medium",
                                "contract": cname, "function": fname, "file": rel, "line": at(pos),
                                "detail": "low-level call return value not checked"})
                    break
                # DoS / gas griefing — external value transfer inside a loop (one revert blocks all)
                if facts["loop_calls"]:
                    out.append({"kind": "dos_gas_griefing", "severity": "medium",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["loop_calls"][0]),
                                "detail": "external call inside a loop (one failure griefs the batch)"})
                # inline assembly — a Yul block can hide calls/sinks the Solidity AST can't
                # see: escalate as a BLIND SPOT rather than silently passing the function.
                if facts["has_assembly"]:
                    out.append({"kind": "contains_assembly", "severity": "medium",
                                "contract": cname, "function": fname, "file": rel,
                                "line": at(facts["has_assembly"][0]),
                                "detail": "function uses inline assembly — sinks may be hidden "
                                          "from structural analysis; review manually"})
    return out


def _alias_target(stmt: dict, state_vars: set) -> tuple[str, str] | None:
    """If `stmt` binds a storage-pointer local to a state var, return (local, state_var). A storage
    local is a LIVE REFERENCE into the state slot, not a copy — writes through it mutate the state.
    Two forms: the explicit `T storage acc = ...` (>=0.5), and the 0.4.x `var acc = State[k]` where
    the location is implicit ("default") and the binding is an index/member into a state var (a
    struct/array element — a reference). The index/member gate keeps `var x = scalarVar` value-COPIES
    out (those don't alias). Returns None for memory / uninitialised / value-copy decls."""
    if stmt.get("nodeType") != "VariableDeclarationStatement":
        return None
    decls = [d for d in (stmt.get("declarations") or []) if d]
    if len(decls) != 1:
        return None
    init = stmt.get("initialValue")
    if not init:
        return None
    loc = decls[0].get("storageLocation")
    is_ref_access = init.get("nodeType") in ("IndexAccess", "MemberAccess")
    if loc != "storage" and not (loc == "default" and is_ref_access):
        return None
    root = _base_ident(init)
    return (decls[0].get("name"), root) if root in state_vars else None


_BUILTIN_NS = {"abi", "block", "msg", "tx"}
# members that do NOT hand control to an external contract: the gas-limited value sends (2300-gas
# stipend, cannot re-enter) and pure value/array/bytes builtins.
_SAFE_HL_MEMBERS = {"transfer", "send", "encode", "encodePacked", "encodeWithSelector",
                    "encodeWithSignature", "decode", "push", "pop", "length"}


def _has_external_call(node) -> bool:
    """True if `node` contains a call that hands control to an external contract: a low-level
    `.call`/`.delegatecall` OR a HIGH-LEVEL method call on a contract/address value
    (`Bank(msg.sender).f()`, `IToken(x).hook()`). Gas-limited `.transfer`/`.send` and pure
    builtins (`abi.*`, `keccak256`) are NOT external handoffs. Used to detect a modifier that
    opens a re-entrancy window before `_` — the case the low-level-only effect walk misses."""
    if isinstance(node, dict):
        if node.get("nodeType") == "FunctionCall":
            ux = _unwrap_lowlevel_expr(node.get("expression", {}))
            if ux.get("nodeType") == "MemberAccess":
                mn = ux.get("memberName", "")
                base = ux.get("expression", {})
                base_builtin = (base.get("nodeType") == "Identifier"
                                and base.get("name") in _BUILTIN_NS)
                if mn in _REENTRANT_CALLS:
                    return True                       # low-level .call/.delegatecall
                if mn not in _SAFE_HL_MEMBERS and not base_builtin:
                    return True                       # high-level contract method call
        for v in node.values():
            if _has_external_call(v):
                return True
    elif isinstance(node, list):
        for x in node:
            if _has_external_call(x):
                return True
    return False


def _fn_effects(node, state_vars: set, eff: dict):
    """Per-function 'local section': external-call positions, state-var mentions, state-var
    writes, and internal calls (name, call-site pos). The pieces a sheaf obstruction glues.
    `eff['alias']` maps storage-pointer locals to the state var they bind, so a write through
    the alias (`acc.balance -= x` where `acc = accounts[msg.sender]`) is seen as a state write."""
    if isinstance(node, dict):
        nt = node.get("nodeType")
        pos = int(node.get("src", "0:0:0").split(":")[0])
        alias = eff.setdefault("alias", {})
        if nt == "VariableDeclarationStatement":
            a = _alias_target(node, state_vars)
            if a:
                alias[a[0]] = a[1]                              # storage-pointer binding
        if nt == "FunctionCall":
            ux = _unwrap_lowlevel_expr(node.get("expression", {}))   # incl. legacy .call.value(x)()
            if ux.get("nodeType") == "MemberAccess" and ux.get("memberName") in _REENTRANT_CALLS:
                s = node.get("src", "0:0:0").split(":")
                eff["ext_calls"].append((int(s[0]), int(s[0]) + int(s[1])))   # (start, end)
            elif ux.get("nodeType") == "Identifier":
                eff["calls"].append((ux.get("name"), pos))         # internal call by name
        elif nt == "Assignment":
            base = _base_ident(node.get("leftHandSide", {}))
            base = base if base in state_vars else alias.get(base)   # resolve storage-pointer alias
            if base in state_vars:
                eff["writes"].setdefault(base, []).append(pos)
        elif nt == "Identifier":
            nm = node.get("name")
            tgt = nm if nm in state_vars else alias.get(nm)
            if tgt in state_vars:
                eff["mentions"].setdefault(tgt, []).append(pos)
        for v in node.values():
            _fn_effects(v, state_vars, eff)
    elif isinstance(node, list):
        for x in node:
            _fn_effects(x, state_vars, eff)


def reentrancy_obstructions(source_root) -> list[dict]:
    """Reentrancy as a SHEAF OBSTRUCTION: glue per-function read/write sections across the
    call graph. An obstruction = an external call after which a state var THAT WAS READ
    BEFORE the call is written — whether the write is in this function OR in a callee that
    runs after the call (the cross-function case per-function CEI can't see). Requiring the
    var to be read-before is what distinguishes a guard invariant from unrelated bookkeeping
    (killing the false positive)."""
    root = pathlib.Path(source_root)
    out: list[dict] = []
    for path in _sol_files(root):
        ast = _solc_ast(path)
        if ast is None:
            continue
        rel = _audit_rel(path, root)
        nl = [i for i, b in enumerate(path.read_bytes()) if b == 0x0A]
        for contract in _iter(ast, "ContractDefinition"):
            cname = contract.get("name", "")
            eff_ac = _effectively_ac_names(contract)   # internal fns reachable only via privileged entries
            state_vars = {n.get("name") for n in contract.get("nodes", [])
                          if n.get("nodeType") == "VariableDeclaration"}
            fns = {}
            for fn in contract.get("nodes", []):
                if fn.get("nodeType") != "FunctionDefinition":
                    continue
                eff = {"ext_calls": [], "mentions": {}, "writes": {}, "calls": []}
                _fn_effects(fn.get("body") or {}, state_vars, eff)
                fns[fn.get("name") or fn.get("kind", "function")] = eff
            # which modifiers themselves make an external call (callback BEFORE the function body)
            mod_extcall = {}
            for mn in contract.get("nodes", []):
                if mn.get("nodeType") == "ModifierDefinition":
                    # high-level too: `Bank(msg.sender).f()` in a modifier opens a re-entry window
                    mod_extcall[mn.get("name")] = _has_external_call(mn.get("body") or {})
            for fname, eff in fns.items():
                fn_def = next((f for f in contract.get("nodes", [])
                               if f.get("nodeType") == "FunctionDefinition"
                               and (f.get("name") or f.get("kind")) == fname), {})
                mods = [m.get("modifierName", {}).get("name", "") for m in fn_def.get("modifiers", [])]
                if "nonReentrant" in mods:
                    continue
                # reentrancy behind access control is only reachable by a privileged caller -> downgrade
                # (NOT suppress: the gate may be bypassable, so a permissionless-equivalent bug surfaces).
                # Direct gate OR interprocedural (internal fn reached only via privileged entries).
                ac = _access_controlled(fn_def) or ("a privileged caller (interprocedural)" if fname in eff_ac else None)
                _sev = "low" if ac else "high"
                # effective external boundaries: this fn's own calls + a callee that itself
                # makes an external call, lifted to the call site (the callee runs the ext call).
                boundaries = [(C, Cend, None) for (C, Cend) in eff["ext_calls"]]
                for callee, cpos in eff["calls"]:
                    if callee in fns and fns[callee]["ext_calls"]:
                        boundaries.append((cpos, cpos, callee))    # callee-lifted boundary
                fired = False
                for C, Cend, via in boundaries:
                    writes_after: dict = {}
                    for var, ws in eff["writes"].items():           # writes after C in this fn
                        if any(w > C for w in ws):
                            writes_after[var] = min(w for w in ws if w > C)
                    for callee, cpos in eff["calls"]:               # callee runs after C -> its writes too
                        if cpos > C and callee in fns:
                            for var in fns[callee]["writes"]:
                                writes_after.setdefault(var, cpos)
                    for var, wpos in writes_after.items():
                        # read at/before the call completes (incl. inside `call{value: v}`)
                        if any(m < Cend for m in eff["mentions"].get(var, [])):
                            detail = (f"sheaf obstruction: external call inside callee '{via}' then a write "
                                      f"to '{var}' (read before the call) — re-entry sees stale state") if via else \
                                     (f"sheaf obstruction: external call then a write to '{var}' "
                                      f"(read before the call) — re-entry sees stale state")
                            out.append({"kind": "reentrancy", "severity": _sev, "contract": cname,
                                        "function": fname, "file": rel, "line": _byte_line(nl, f"{C}::"),
                                        "call_line": _byte_line(nl, f"{C}::"),
                                        "write_line": _byte_line(nl, f"{wpos}::"),
                                        **({"confidence": "low"} if ac else {}),
                                        "detail": (f"[access-controlled by '{ac}': only a privileged caller "
                                                   f"reaches this — lower exploitability] " if ac else "") + detail})
                            fired = True
                            break
                    if fired:
                        break
                if fired:
                    continue
                # modifier-embedded external call: the callback fires BEFORE the body, so any
                # state var the body both reads and writes is exposed to re-entry (the body's
                # read happens after the callback, so the read-before-call guard does not apply).
                if any(mod_extcall.get(m) for m in mods):
                    for var, ws in eff["writes"].items():
                        if var in eff["mentions"] and ws:
                            out.append({"kind": "reentrancy", "severity": _sev, "contract": cname,
                                        "function": fname, "file": rel, "line": _byte_line(nl, f"{min(ws)}::"),
                                        "call_line": _byte_line(nl, f"{min(ws)}::"),
                                        "write_line": _byte_line(nl, f"{min(ws)}::"),
                                        **({"confidence": "low"} if ac else {}),
                                        "detail": (f"[access-controlled by '{ac}': lower exploitability] " if ac else "")
                                                  + f"modifier opens an external callback before the body; "
                                                  f"'{var}' is read+written in the body — re-entry sees stale state"})
                            break
    return out


def reentrancy_findings(source_root) -> list[dict]:
    """CEI-violation reentrancy (the bug that drained TheDAO) — a thin view over the audit."""
    return [{"contract": f["contract"], "function": f["function"], "file": f["file"],
             "call_line": f["call_line"], "write_line": f["write_line"]}
            for f in solidity_audit(source_root) if f["kind"] == "reentrancy"]


def _iter(node, node_type: str):
    """Yield every node of `node_type` in the AST."""
    if isinstance(node, dict):
        if node.get("nodeType") == node_type:
            yield node
        for v in node.values():
            yield from _iter(v, node_type)
    elif isinstance(node, list):
        for x in node:
            yield from _iter(x, node_type)


def _span(src: str, nl: list[int]) -> tuple[int, int]:
    """(start_line, end_line) from a solc src "start:len:file"."""
    start_b = int(src.split(":")[0])
    length = int(src.split(":")[1])
    return _byte_line(nl, f"{start_b}::"), _byte_line(nl, f"{start_b + length}::")
