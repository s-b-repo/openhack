# src/lattice/ingest/solidity_typed.py
"""Solidity adapter for the typed-constraint-algebra lift.

Turns the facts the parse-only solc AST gives us (state-var names, types, namespaces, per-function
read/write/call positions) into the abstract cells + edges + operations that typed_chain.py's three
legs consume. chain.py and typed_chain.py stay frontend-agnostic; everything Solidity-specific lives
here.

Storage layout is TIERED: tier-1 uses solc --storage-layout for the EXACT layout (real slots,
inherited vars flattened, byte-accurate packing, resolved encodings) for every contract that
TYPECHECKS; tier-2 falls back to a hand-rolled EVM packer (approximate under deep inheritance/structs)
when a contract only parses (unresolved imports / wrong version). The collision leg — which is
slot-driven — gets exact resolution wherever the contract compiles; homology is name-driven and is
unaffected. Unresolved Yul targets (computed slot) fall back to a COARSE sentinel / blindspot.

Honest scope (validated by adversarial red-team, not a marketing claim): these legs are HIGH-RECALL
SCREENS over AST-visible state. Trust a FIRE as a high-value lead worth triage; SILENCE does NOT
certify safety. Confirmed silent blind spots that the structure genuinely cannot see — escalated as
`blindspot` findings where detectable, never papered over:
  • inline-assembly / Yul sstore-tstore state writes (not AST Assignment nodes) — escalated as a
    blindspot when assembly co-occurs with an external call;
  • cross-CONTRACT reentrancy (A→B→A) — the homology leg follows internal calls, not external callbacks;
  • guard recognition is MODIFIER-scoped (self-referential set+reset mutex, one helper hop). A mutex
    written inline in the function BODY is not recognized, so a guarded function fires a false positive —
    the SAFE direction (a recoverable FP, never a suppressed bug); recognizing it is declined on purpose;
  • collision needs a RESOLVABLE proxy↔impl link (explicit type reference, naming family, or same-file
    delegatecall). A proxy whose implementation is a pure runtime address with no reference, no naming
    convention, and no co-location is unpaired — a true miss. Correct EIP-1967/EIP-1167 forwarders over
    HASHED slots legitimately don't collide (no shared declared region), so silence there is right;
  • EIP-1153 transient storage;
  • value leaks via plain `=` overwrite, per-key mapping invariants, and multi-variable functionals.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess

from lattice.typed_chain import (StateCell, intern_cells, homology_obstructions, typed_h1,
                                 ConservedFunctional, conservation_obstructions)


def _width(typename: dict) -> int | None:
    """Storage width in bytes of an elementary type; None for mapping/array/struct/dynamic
    (which take a fresh full slot)."""
    if not typename or typename.get("nodeType") != "ElementaryTypeName":
        return None
    name = typename.get("name") or ""
    if name == "address":
        return 20
    if name == "bool":
        return 1
    if name.startswith("uint") or name.startswith("int"):
        bits = name[4:] if name.startswith("uint") else name[3:]
        return (int(bits) // 8) if bits.isdigit() else 32      # bare uint/int == 256-bit
    if name.startswith("bytes") and name[5:].isdigit():
        return int(name[5:])
    # string, dynamic bytes, fixed/other -> fresh full slot
    return None


def _type_str(typename: dict) -> str:
    """A stable type label for the cell's typed tag."""
    if not typename:
        return ""
    nt = typename.get("nodeType")
    if nt == "ElementaryTypeName":
        return typename.get("name") or ""
    if nt == "Mapping":
        return "mapping"
    if nt == "ArrayTypeName":
        return "array"
    if nt == "UserDefinedTypeName":
        return typename.get("name") or "struct"
    return nt or ""


def _parse_layout_stdout(out: str) -> dict:
    """Parse solc --storage-layout text output into {contract: layout_json}."""
    layouts: dict = {}
    # the source path may contain spaces — match greedily to the LAST ':<Contract>' before '======='
    for m in re.finditer(r"=======\s+.+:(\w+)\s+=======", out):
        rest = out[m.end():]
        idx = rest.find("Contract Storage Layout:")
        if idx < 0:
            continue
        jstart = rest.find("{", idx)
        if jstart < 0:
            continue
        line = rest[jstart:].splitlines()[0]               # the layout JSON is emitted on one line
        try:
            layouts[m.group(1)] = json.loads(line)
        except Exception:
            continue
    return layouts


def _run_storage_layout(binary: str, target: str) -> dict:
    try:
        proc = subprocess.run([binary, "--storage-layout", target],
                              capture_output=True, text=True, timeout=30)
    except Exception:
        return {}
    return _parse_layout_stdout(proc.stdout)


def _storage_layouts(path) -> dict:
    """TIER-1 ingest: the REAL storage layout (exact slots/offsets/widths, inherited vars flattened,
    packing, resolved encodings) for every contract that TYPECHECKS. Compiled with the solc matching
    the file's pragma. When that compiler predates --storage-layout (0.4.x / 0.5.x / early 0.6) the
    layout is recovered by recompiling on the NEWEST installed solc with the pragma relaxed — storage
    layout is version-stable and forward-compatible for 0.5+ (0.4.x syntax won't compile on 0.8, so it
    falls through to the tier-2 packer). Returns {contract: layout_json}, or {} for the packer to handle."""
    from lattice.ingest.solidity import _select_solc, _pragma_constraint, _installed_solc
    try:
        src = pathlib.Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}
    sel = _select_solc(src)
    layouts = _run_storage_layout(sel[0] if sel else "solc", str(path))
    if layouts:
        return layouts

    # the matched compiler emitted no layout (no --storage-layout support) — retry on the newest solc
    # with the pragma relaxed to its own floor (so a 0.5.x file compiles on 0.8.x for the layout only)
    c = _pragma_constraint(src)
    installed = _installed_solc()
    if not c or not installed:
        return {}
    newest = installed[max(installed)]
    relaxed = re.sub(r"pragma\s+solidity[^;]+;", f"pragma solidity >={c[1]}.{c[2]}.0;", src, count=1)
    if relaxed == src:
        return {}
    import tempfile
    import os as _os
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as tf:
            tf.write(relaxed)
            tmp = tf.name
        return _run_storage_layout(newest, tmp)
    except Exception:
        return {}
    finally:
        if tmp:
            try:
                _os.unlink(tmp)
            except OSError:
                pass


def _layout_type(tid: str, t: dict) -> str:
    """A simplified type label from a storage-layout types-table entry, matching the labels the legs
    expect (mapping / array / struct / contract / the elementary name)."""
    enc = t.get("encoding")
    if enc == "mapping":
        return "mapping"
    if enc in ("dynamic_array",) or tid.startswith("t_array"):
        return "array"
    if tid.startswith("t_struct"):
        return "struct"
    if tid.startswith("t_contract"):
        return "contract"
    return t.get("label", "") or tid


def cells_from_layout(cname: str, layout: dict) -> dict[str, StateCell]:
    """Build StateCells from solc's REAL storage layout — exact slot/offset/width/type, with
    inheritance and packing already resolved by the compiler."""
    types = layout.get("types") or {}
    raw: list[tuple] = []
    for s in layout.get("storage") or []:
        tid = s.get("type", "")
        t = types.get(tid, {})
        width = int(t.get("numberOfBytes", 32))
        raw.append((s.get("label"), str(s.get("slot")), int(s.get("offset", 0)), width, _layout_type(tid, t)))
    sig = "|".join(f"{slot}:{off}:{w}:{ty}" for _, slot, off, w, ty in raw)
    impl = hashlib.sha1(sig.encode()).hexdigest()[:12]
    return {label: StateCell(slot=slot, offset=off, width=w, type=ty, namespace=cname, impl_version=impl)
            for label, slot, off, w, ty in raw}


def _inheritance_chain(contract: dict, registry: dict, seen: set | None = None) -> list[dict]:
    """The contracts whose storage precedes `contract`'s in the EVM layout: base contracts FIRST
    (depth-first over the `is X` list), self LAST. Approximates C3 linearization (which the parse-only
    AST doesn't provide) — correct for single/linear inheritance, the dominant case."""
    if seen is None:
        seen = set()
    name = contract.get("name")
    if name in seen:
        return []
    seen.add(name)
    chain: list[dict] = []
    for b in contract.get("baseContracts", []) or []:
        bn = (b.get("baseName") or {}).get("name") or ((b.get("baseName") or {}).get("pathNode") or {}).get("name")
        base = registry.get(bn)
        if base:
            chain.extend(_inheritance_chain(base, registry, seen))
    chain.append(contract)
    return chain


def storage_cells(contract_ast: dict, contract_types: set | None = None,
                  registry: dict | None = None) -> dict[str, StateCell]:
    """Map every state variable to its physical+typed StateCell by replaying the EVM storage
    packer over declaration order. namespace = the owning contract; impl_version = a hash of the
    ordered layout signature (so inserting a variable, which shifts every later slot, changes it —
    the unsafe-upgrade signal). constant/immutable take no storage slot. `contract_types` (the names
    of contracts/interfaces in scope) lets a contract/interface-typed pointer pack as a 20-byte
    ADDRESS instead of a fresh slot. `registry` (name -> contract AST) flattens INHERITED storage —
    base-contract vars are laid first, exactly as the EVM does, so inheriting contracts get real slots."""
    cname = contract_ast.get("name", "")
    chain = _inheritance_chain(contract_ast, registry) if registry else [contract_ast]
    decls = [n for c in chain for n in c.get("nodes", []) if n.get("nodeType") == "VariableDeclaration"]
    raw: list[tuple] = []                                   # (name, slot, offset, width, type)
    slot, offset = 0, 0
    for n in decls:
        if n.get("constant") or n.get("mutability") in ("constant", "immutable"):
            continue                                        # no storage slot consumed
        tn = n.get("typeName") or {}
        w = _width(tn)
        ts = _type_str(tn)
        if w is None and tn.get("nodeType") == "UserDefinedTypeName":
            nm = tn.get("name") or (tn.get("pathNode") or {}).get("name")
            if contract_types and nm in contract_types:
                w = 20                                       # a contract/interface pointer is an address
        if w is None:                                       # mapping/array/struct/dynamic -> fresh slot
            if offset != 0:
                slot += 1
                offset = 0
            raw.append((n.get("name"), slot, 0, 32, ts))
            slot += 1
            offset = 0
        else:
            if offset + w > 32:                             # doesn't fit -> open a new slot
                slot += 1
                offset = 0
            raw.append((n.get("name"), slot, offset, w, ts))
            offset += w

    sig = "|".join(f"{s}:{o}:{w}:{t}" for _, s, o, w, t in raw)
    impl = hashlib.sha1(sig.encode()).hexdigest()[:12]
    return {name: StateCell(slot=str(s), offset=o, width=w, type=t,
                            namespace=cname, impl_version=impl)
            for name, s, o, w, t in raw}


# ── fact extraction: per-function effects (reads, SIGNED writes, calls, delegatecalls) ────────

def _base_name(node: dict) -> str | None:
    """The root state-var name of an lvalue, unwrapping balances[u]/s.field to `balances`/`s`."""
    while isinstance(node, dict) and node.get("nodeType") in ("IndexAccess", "MemberAccess"):
        node = node.get("baseExpression") or node.get("expression") or {}
    if isinstance(node, dict) and node.get("nodeType") == "Identifier":
        return node.get("name")
    return None


def _pos(node: dict) -> int:
    return int(node.get("src", "0:0:0").split(":")[0])


_YUL_WRITES = {"sstore"}                      # PERSISTENT storage only
_YUL_READS = {"sload"}
_YUL_TRANSIENT = {"tstore", "tload"}          # EIP-1153 — a DIFFERENT namespace; commonly a guard,
                                              # so it must NEVER feed homology as a confident write


def _yul_resolve_slots(args: list, slot_to_vars: dict | None) -> tuple[list, str]:
    """The state vars an sstore/sload targets, and a status. A literal slot maps to ALL vars packed
    there (over-attribute → over-fire, never silently miss the 2nd packed var). An `x.slot`
    identifier → base var `x`. Status: 'resolved' (vars found), 'literal_empty' (a literal slot
    occupied by NO declared var — provably touches nothing, SAFE), 'unresolved' (a computed/keccak
    slot — genuinely opaque, escalate)."""
    if not args or not isinstance(args[0], dict):
        return [], "unresolved"
    a = args[0]
    if a.get("nodeType") == "YulLiteral":
        if slot_to_vars is None:
            return [], "unresolved"
        raw = a.get("value")
        try:
            key = str(int(str(raw), 0))        # solc emits the literal verbatim ('0x1') — normalize to decimal
        except (ValueError, TypeError):
            key = str(raw)
        vs = slot_to_vars.get(key, [])
        return list(vs), ("resolved" if vs else "literal_empty")
    if a.get("nodeType") == "YulIdentifier":
        name = a.get("name", "")
        if name.endswith(".slot"):
            return [name[:-5]], "resolved"
    return [], "unresolved"


def _walk_yul(node, slot_to_vars: dict | None, eff: dict, state_vars: set | None = None):
    """Resolve Yul sstore (writes) and sload (reads) to state vars where the slot is a literal or
    `.slot` reference; an unresolved (computed) write — or a `.slot` on a LOCAL storage pointer that
    can't be traced to a declared state var — is recorded for blindspot escalation. tstore/tload are
    recorded as TRANSIENT (a guard signal), never as storage writes that could fire."""
    sv = state_vars if state_vars is not None else None
    if isinstance(node, dict):
        if node.get("nodeType") == "YulFunctionCall":
            fname = (node.get("functionName") or {}).get("name")
            if fname in _YUL_WRITES:
                vs, status = _yul_resolve_slots(node.get("arguments") or [], slot_to_vars)
                real = [v for v in vs if sv is None or v in sv]
                if real:
                    for v in real:
                        eff["writes"].setdefault(v, []).append((0, _pos(node)))   # opaque amount -> sign 0
                elif status == "unresolved" or vs:   # computed slot, or a .slot on an untraceable local
                    eff["asm_unresolved"].append(_pos(node))
                # literal_empty (no vs) -> provably touches no state var -> SAFE, no escalation
            elif fname in _YUL_READS:
                vs, status = _yul_resolve_slots(node.get("arguments") or [], slot_to_vars)
                real = [v for v in vs if sv is None or v in sv]
                if real:
                    for v in real:
                        eff["reads"].setdefault(v, []).append(_pos(node))
                elif status == "unresolved" or vs:   # a laundered read (computed/local .slot) — escalate,
                    eff["asm_unresolved"].append(_pos(node))   # don't drop it silently (FN otherwise)
            elif fname == "delegatecall":
                eff["delegatecalls"].append(_pos(node))   # assembly-forwarding proxy (EIP-1967/1167/2535)
            elif fname in _YUL_TRANSIENT:
                eff["transient"].append(_pos(node))
        for v in node.values():
            _walk_yul(v, slot_to_vars, eff, state_vars)
    elif isinstance(node, list):
        for x in node:
            _walk_yul(x, slot_to_vars, eff, state_vars)


# member names that are NOT an external call (builtins on arrays/bytes/abi/address metadata)
_NONEXTERNAL_MEMBERS = {"push", "pop", "length", "encode", "decode", "encodePacked",
                        "encodeWithSelector", "encodeWithSignature", "encodeCall", "selector",
                        "balance", "code", "codehash", "wrap", "unwrap", "value", "gas"}
# base identifiers that are namespaces/keywords, never an external contract value
_NONEXTERNAL_BASES = {"abi", "super", "msg", "block", "tx", "type", "bytes", "string"}


def _is_external_base(baseexpr: dict, callable_bases: set) -> bool:
    """Is a member-access call's base a contract/address-typed VALUE (so the call transfers control
    externally)? A cast `IFoo(x)`, `this`, or a state-var/parameter holding a contract → yes; a
    library/type name (`SafeMath.add`) or `abi`/`super` → no. This is what makes a high-level
    interface call (the dominant modern reentrancy hook) an external boundary, without firing on
    every library or pure helper call."""
    nt = baseexpr.get("nodeType")
    if nt == "FunctionCall":                 # a cast: IReceiver(x).onTokens() / payable(x)...
        return True
    if nt == "Identifier":
        name = baseexpr.get("name")
        if name in _NONEXTERNAL_BASES:
            return False
        return name == "this" or name in callable_bases
    if nt == "MemberAccess":                 # nested base: registry.token.transfer(...)
        return _is_external_base(baseexpr.get("expression", {}), callable_bases)
    return False


def _typed_effects(node, state_vars: set, eff: dict, slot_to_var: dict | None = None,
                   callable_bases: set | None = None):
    """Per-function section: state reads (var->positions), SIGNED writes (var->[(sign,pos)] where
    += is +1, -= is -1, = is 0/overwrite), external-call spans, delegatecall positions, internal
    calls. Richer than solidity.py._fn_effects (adds write sign + delegatecalls) for the value leg.
    With slot_to_var, also resolves Yul sstore/sload to state vars (closing the assembly-write FN).
    External calls include high-level interface-method calls on a contract-typed value (the dominant
    modern reentrancy syntax), not just .call/.transfer/.send."""
    if callable_bases is None:
        callable_bases = state_vars
    if isinstance(node, dict):
        nt = node.get("nodeType")
        if nt == "FunctionCall":
            ux = node.get("expression", {})
            # unwrap .call{value:..}() options AND the old-style .call.value(x)() / .call.gas(g)()
            # chain (pre-0.8 reentrancy syntax) — the `.call` indicator is wrapped in a .value()/.gas()
            while True:
                if ux.get("nodeType") == "FunctionCallOptions":
                    ux = ux.get("expression", {})
                elif (ux.get("nodeType") == "FunctionCall"
                      and (ux.get("expression") or {}).get("nodeType") == "MemberAccess"
                      and (ux.get("expression") or {}).get("memberName") in ("value", "gas")):
                    ux = ux["expression"]["expression"]
                else:
                    break
            if ux.get("nodeType") == "MemberAccess":
                mn = ux.get("memberName")
                if mn == "call":
                    s = node.get("src", "0:0:0").split(":")
                    eff["ext_calls"].append((int(s[0]), int(s[0]) + int(s[1])))
                elif mn in ("transfer", "send"):
                    # `addr.transfer(amt)` / `.send(amt)` (ONE arg) is a LOW-LEVEL ETH send — it forwards a
                    # fixed 2300-gas stipend, so the callee cannot call back or write storage and CANNOT
                    # enable reentrancy (the structural leg already excludes these). A `token.transfer(to,
                    # amt)` (TWO args) is a FULL-GAS ERC20 method call that CAN reenter (ERC777) — keep it.
                    if len(node.get("arguments") or []) >= 2:
                        s = node.get("src", "0:0:0").split(":")
                        eff["ext_calls"].append((int(s[0]), int(s[0]) + int(s[1])))
                elif mn == "delegatecall":
                    eff["delegatecalls"].append(_pos(node))
                elif mn not in _NONEXTERNAL_MEMBERS and _is_external_base(ux.get("expression", {}), callable_bases):
                    s = node.get("src", "0:0:0").split(":")
                    eff["ext_calls"].append((int(s[0]), int(s[0]) + int(s[1])))   # high-level interface call
            elif ux.get("nodeType") == "Identifier":
                eff["calls"].append((ux.get("name"), _pos(node)))
        elif nt == "Assignment":
            base = _base_name(node.get("leftHandSide", {}))
            if base in state_vars:
                op = node.get("operator", "=")
                sign = +1 if op == "+=" else (-1 if op == "-=" else 0)
                eff["writes"].setdefault(base, []).append((sign, _pos(node)))
        elif nt == "UnaryOperation" and node.get("operator") == "delete":
            base = _base_name(node.get("subExpression", {}))
            if base in state_vars:                       # `delete balances[u]` zeroes it — a decrement/burn
                eff["writes"].setdefault(base, []).append((-1, _pos(node)))
        elif nt == "Identifier" and node.get("name") in state_vars:
            eff["reads"].setdefault(node["name"], []).append(_pos(node))
        elif nt == "InlineAssembly":
            eff["assembly"].append(_pos(node))       # Yul block — resolve what we can, escalate the rest
            _walk_yul(node, slot_to_var, eff, state_vars)
        for v in node.values():
            _typed_effects(v, state_vars, eff, slot_to_var, callable_bases)
    elif isinstance(node, list):
        for x in node:
            _typed_effects(x, state_vars, eff, slot_to_var, callable_bases)


def _fn_params(fn: dict) -> set:
    """The parameter names of a function — vars that may hold an external contract/address value."""
    return {p.get("name") for p in (fn.get("parameters") or {}).get("parameters", []) if p.get("name")}


def _new_eff() -> dict:
    return {"reads": {}, "writes": {}, "ext_calls": [], "delegatecalls": [], "calls": [],
            "assembly": [], "asm_unresolved": [], "transient": []}


def _slot_to_vars(cells: dict) -> dict:
    """slot string -> ALL state vars occupying it (packed vars share a slot), for resolving Yul
    literal slots. A literal sstore writes the whole word, so it touches every packed var."""
    out: dict = {}
    for name, cell in cells.items():
        out.setdefault(cell.slot, []).append(name)
    return out


def _collect_state_idents(node, state_vars: set, out: set):
    """State-var names referenced under `node` (Identifier or MemberAccess base)."""
    if isinstance(node, dict):
        if node.get("nodeType") == "Identifier" and node.get("name") in state_vars:
            out.add(node["name"])
        elif node.get("nodeType") == "MemberAccess":
            base = _base_name(node)
            if base in state_vars:
                out.add(base)
        for v in node.values():
            _collect_state_idents(v, state_vars, out)
    elif isinstance(node, list):
        for x in node:
            _collect_state_idents(x, state_vars, out)


def _refs_name(node, name: str) -> bool:
    """Does `name` appear as an Identifier anywhere under `node`?"""
    if isinstance(node, dict):
        if node.get("nodeType") == "Identifier" and node.get("name") == name:
            return True
        return any(_refs_name(v, name) for v in node.values())
    if isinstance(node, list):
        return any(_refs_name(x, name) for x in node)
    return False


def _internal_call_names(body) -> set:
    """Names of internal function calls (Identifier-expression FunctionCalls) in a body."""
    out: set = set()

    def walk(n):
        if isinstance(n, dict):
            if n.get("nodeType") == "FunctionCall":
                ex = n.get("expression", {})
                if ex.get("nodeType") == "Identifier":
                    out.add(ex.get("name"))
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for x in n:
                walk(x)

    walk(body or {})
    return out


def _placeholder_pos(body) -> int | None:
    """Source position of the `_` placeholder in a modifier body (the boundary the protected
    function runs at)."""
    found = [None]

    def walk(n):
        if isinstance(n, dict):
            if n.get("nodeType") == "PlaceholderStatement":
                found[0] = _pos(n)
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for x in n:
                walk(x)

    walk(body or {})
    return found[0]


def _unwrap(node: dict) -> dict:
    """Strip redundant parentheses: a single-component TupleExpression — require((!locked)),
    (status) != ENTERED — is the inner expression for predicate/flag purposes."""
    while isinstance(node, dict) and node.get("nodeType") == "TupleExpression":
        comps = node.get("components") or []
        if len(comps) == 1 and isinstance(comps[0], dict):
            node = comps[0]
        else:
            break
    return node


def _value_repr(node: dict) -> str | None:
    """A comparable representation of a value: 'true'/'0' for a Literal, 'id:NAME' for an Identifier,
    'mem:Base.member' for a MemberAccess (enum sentinels Status.ENTERED, and msg.sender as a key).
    None for anything else (a cast/call) — which then never matches another key."""
    node = _unwrap(node)
    if not isinstance(node, dict):
        return None
    nt = node.get("nodeType")
    if nt == "Literal":
        return str(node.get("value"))
    if nt == "Identifier":
        return "id:" + str(node.get("name"))
    if nt == "MemberAccess":
        base = node.get("expression", {})
        bn = base.get("name") if base.get("nodeType") == "Identifier" else _value_repr(base)
        return f"mem:{bn}.{node.get('memberName')}"
    return None


def _is_fixed(node: dict, params: set, state_vars: set) -> bool:
    """Is `node` a FIXED sentinel value (a literal, a named constant, or an enum member like
    Status.ENTERED) rather than a dynamic, possibly attacker-controlled one (msg.sender, a
    parameter, another state var)? A real mutex compares its flag against a fixed sentinel."""
    node = _unwrap(node)
    nt = node.get("nodeType")
    if nt == "Literal":
        return True
    if nt == "Identifier":
        name = node.get("name")
        return name not in params and name not in state_vars      # a module-level constant
    if nt == "MemberAccess":                                      # Status.ENTERED is fixed; msg.sender is not
        base = node.get("expression", {})
        if base.get("nodeType") == "Identifier":
            return base.get("name") not in ("msg", "tx", "block", "abi")
        return False
    return False                                                  # a cast / call -> dynamic


def _flag_id(node: dict, state_vars: set) -> str | None:
    """The full access PATH of a storage flag rooted at a state var — 'locked[mem:msg.sender]',
    's.locked' — so the check, set, and reset are only treated as the same flag when they target
    the SAME key/member (a lock set on a different key than it checks protects nobody)."""
    node = _unwrap(node)
    if not isinstance(node, dict):
        return None
    nt = node.get("nodeType")
    if nt == "Identifier":
        return node["name"] if node.get("name") in state_vars else None
    if nt == "IndexAccess":
        base = _flag_id(node.get("baseExpression", {}), state_vars)
        return f"{base}[{_value_repr(node.get('indexExpression', {}))}]" if base else None
    if nt == "MemberAccess":
        base = _flag_id(node.get("expression", {}), state_vars)
        return f"{base}.{node.get('memberName')}" if base else None
    return None


def _truthy(rep: str | None) -> bool:
    if rep in ("true",):
        return True
    if rep in ("false", "0", None):
        return False
    try:
        return int(rep) != 0
    except (ValueError, TypeError):
        return True


def _trips(kind: str, kval: str | None, set_rep: str | None) -> bool:
    """Does setting the flag to `set_rep` make the guard predicate FALSE (so a re-entrant call
    reverts)? That is what gives mutual exclusion."""
    if kind == "neg":                                   # require(!V): passes when V falsy
        return _truthy(set_rep)
    if kind == "pos":                                   # require(V): passes when V truthy
        return not _truthy(set_rep)
    if kind == "eq":                                    # require(V==k): passes when V==k
        return set_rep is not None and set_rep != kval
    if kind == "neq":                                   # require(V!=k): passes when V!=k
        return set_rep is not None and set_rep == kval
    return False


def _sole_state_var(node: dict, state_vars: set) -> str | None:
    if not isinstance(node, dict):
        return None
    if node.get("nodeType") == "Identifier" and node.get("name") in state_vars:
        return node["name"]
    if node.get("nodeType") in ("MemberAccess", "IndexAccess"):   # s.locked / locked[msg.sender]
        b = _base_name(node)
        return b if b in state_vars else None
    return None


def _check_predicates(condition, state_vars: set, params: set, out: list):
    """Mutex-eligible predicates (flag_id, kind, kval) from a check: !V, bare V, V==k, V!=k where V
    is a state-flag access (keyed by its full path) and k is a FIXED sentinel. Inequalities and
    dynamic comparison values are excluded (not real exclusion)."""
    condition = _unwrap(condition)
    if not isinstance(condition, dict):
        return
    nt = condition.get("nodeType")
    op = condition.get("operator")
    if nt == "UnaryOperation" and op == "!":
        v = _flag_id(condition.get("subExpression", {}), state_vars)
        if v:
            out.append((v, "neg", None))
    elif nt in ("Identifier", "IndexAccess", "MemberAccess"):
        v = _flag_id(condition, state_vars)                  # bare boolean flag: require(locked[x])
        if v:
            out.append((v, "pos", None))
    elif nt == "BinaryOperation" and op in ("==", "!="):
        l, r = condition.get("leftExpression", {}), condition.get("rightExpression", {})
        lv, rv = _flag_id(l, state_vars), _flag_id(r, state_vars)
        if lv and _is_fixed(r, params, state_vars):
            out.append((lv, "eq" if op == "==" else "neq", _value_repr(r)))
        elif rv and _is_fixed(l, params, state_vars):
            out.append((rv, "eq" if op == "==" else "neq", _value_repr(l)))
    elif nt == "BinaryOperation" and op == "&&":
        # only a CONJUNCTION preserves each operand as a REQUIRED check. In `A || !locked`, !locked
        # is not required (the check passes when A holds), so it is not a sound mutex predicate.
        _check_predicates(condition.get("leftExpression"), state_vars, params, out)
        _check_predicates(condition.get("rightExpression"), state_vars, params, out)


def _helper_pred_writes(body, state_vars: set, params: set) -> tuple[list, dict]:
    """(check predicates, {var: set-value-repr}) in a helper body. Like the modifier walker, a set
    is recorded as a guaranteed lock only when it is UNCONDITIONAL (not nested in an if/loop body) —
    otherwise a conditional helper set would be misread as an always-taken lock (a silent FN)."""
    preds: list = []
    writes: dict = {}

    def walk(n, cond: bool):
        if isinstance(n, dict):
            nt = n.get("nodeType")
            if nt == "IfStatement":
                _check_predicates(n.get("condition", {}), state_vars, params, preds)
                walk(n.get("trueBody"), True)
                walk(n.get("falseBody"), True)
                return
            if nt in ("ForStatement", "WhileStatement", "DoWhileStatement"):
                for k in ("initializationExpression", "condition", "loopExpression"):
                    walk(n.get(k), cond)
                walk(n.get("body"), True)
                return
            if nt == "FunctionCall":
                ex = n.get("expression", {})
                if ex.get("nodeType") == "Identifier" and ex.get("name") in ("require", "assert"):
                    for arg in n.get("arguments", []):
                        _check_predicates(arg, state_vars, params, preds)
            elif nt == "Assignment":
                fid = _flag_id(n.get("leftHandSide", {}), state_vars)
                if fid and not cond and n.get("operator", "=") == "=":
                    rhs = n.get("rightHandSide", {})
                    writes[fid] = (_value_repr(rhs), _is_fixed(rhs, params, state_vars))
            for v in n.values():
                walk(v, cond)
        elif isinstance(n, list):
            for x in n:
                walk(x, cond)

    walk(body or {}, False)
    return preds, writes


def _modifier_guard_kind(mod_def: dict, state_vars: set, helpers: dict) -> str | None:
    """Classify a modifier as a reentrancy guard — POSITION- and VALUE-aware. A 'mutex' requires a
    state var V with: a check predicate (require(!V) / V==k / V!=k against a FIXED sentinel k — not an
    inequality clamp, not a dynamic/attacker value), a SET of V BEFORE the `_` placeholder to a value
    that TRIPS that predicate (so a re-entrant call reverts), and a RESET after `_`. One internal-call
    hop is followed. 'asm' = an unverifiable Yul/transient guard (escalate, don't bound or fire).
    None otherwise. Bias is conservative — when the set value can't be shown to trip the check, fire."""
    body = mod_def.get("body") or {}
    params = _fn_params(mod_def)
    ph = _placeholder_pos(body)
    preds: list = []                                    # (var, kind, kval)
    set_before: dict = {}                               # var -> (pos, value_repr) of the latest set before `_`
    write_after: set = set()
    calls_before, calls_after = set(), set()
    asm = [False]

    def walk(n, cond: bool):
        if isinstance(n, dict):
            nt = n.get("nodeType")
            if nt == "IfStatement":
                _check_predicates(n.get("condition", {}), state_vars, params, preds)
                walk(n.get("trueBody"), True)            # branch bodies may be skipped -> conditional
                walk(n.get("falseBody"), True)
                return
            if nt in ("ForStatement", "WhileStatement", "DoWhileStatement"):
                for k in ("initializationExpression", "condition", "loopExpression"):
                    walk(n.get(k), cond)
                walk(n.get("body"), True)                # loop body may run 0 times -> conditional
                return
            if nt == "FunctionCall":
                ex = n.get("expression", {})
                if ex.get("nodeType") == "Identifier":
                    name = ex.get("name")
                    if name in ("require", "assert"):
                        for arg in n.get("arguments", []):
                            _check_predicates(arg, state_vars, params, preds)
                    else:
                        (calls_before if ph is not None and _pos(n) < ph else calls_after).add(name)
            elif nt == "Assignment":
                lhs = n.get("leftHandSide", {})
                fid = _flag_id(lhs, state_vars)
                base = _base_name(lhs)
                if fid and ph is not None:
                    if _pos(n) < ph:
                        # a guaranteed lock-set is UNCONDITIONAL and assigns a FIXED value (symmetric
                        # with the check side): a set from a state var / parameter (locked=paused,
                        # locked=engage) may never engage, so it is not a confirmed lock
                        rhs = n.get("rightHandSide", {})
                        if (not cond and n.get("operator", "=") == "="
                                and not _refs_name(rhs, base)
                                and _is_fixed(rhs, params, state_vars)):
                            p = _pos(n)
                            if fid not in set_before or p > set_before[fid][0]:
                                set_before[fid] = (p, _value_repr(rhs))
                    else:
                        write_after.add(fid)             # a (even conditional) reset is reentrancy-safe
            elif nt == "InlineAssembly":
                blob = json.dumps(n)
                if any(o in blob for o in ("tstore", "tload", "sstore", "sload")):
                    asm[0] = True
            for v in n.values():
                walk(v, cond)
        elif isinstance(n, list):
            for x in n:
                walk(x, cond)

    walk(body, False)
    for h in calls_before:                              # helper before `_`: its checks + FIXED sets
        if h in helpers:
            # _is_fixed inside the helper must use the HELPER's own params — a set from the helper's
            # parameter (locked=v, _lock(false)) is dynamic, not a confirmed lock
            hpreds, hwrites = _helper_pred_writes(helpers[h].get("body") or {}, state_vars, _fn_params(helpers[h]))
            preds += hpreds
            for var, (val, fixed) in hwrites.items():
                if fixed:                               # a state-var/param set is not a confirmed lock
                    set_before.setdefault(var, (-1, val))
    for h in calls_after:                               # helper after `_`: its resets (value irrelevant)
        if h in helpers:
            hpreds, hwrites = _helper_pred_writes(helpers[h].get("body") or {}, state_vars, _fn_params(helpers[h]))
            preds += hpreds
            write_after |= set(hwrites)

    for var, kind, kval in preds:                       # a confirmed mutex: set trips its own check
        if var in set_before and var in write_after and _trips(kind, kval, set_before[var][1]):
            return "mutex"
    if asm[0]:
        return "asm"
    return None


# ── conserved-functional recognition (heuristic over state-var names) ─────────────────────────

_TOTAL_NAMES = ("totalsupply", "totalassets", "totalshares", "totaldebt", "totalborrows")
_BALANCE_NAMES = ("balanceof", "balances", "shares", "sharesof", "deposits", "balance")
# which balance mappings a given total scalar is actually conserved against — so we never assert
# totalDebt = Σdeposits in a lending pool (debt and deposits are independent quantities)
_TOTAL_AFFINITY = {
    "totalsupply": ("balances", "balanceof", "balance"),
    "totalshares": ("shares", "sharesof"),
    "totalassets": ("assets", "deposits", "balances"),
    "totaldebt": ("debt", "debts", "borrows", "borrowed", "borrowbalance"),
    "totalborrows": ("borrows", "borrowed", "borrowbalance", "debt"),
}


def recognize_functional(cells: dict[str, StateCell], cell_to_id: dict) -> ConservedFunctional | None:
    """q = total − Σbalance, but ONLY when the total scalar and the balance mapping are name-affine
    (totalSupply↔balances, totalDebt↔debt — never totalDebt↔deposits). Returns None when no affine
    pair exists (the caller then emits a blindspot, not a false conservation assertion)."""
    for total_var in (n for n in cells if n.lower() in _TOTAL_NAMES):
        aff = _TOTAL_AFFINITY.get(total_var.lower(), ())
        bal_var = next((n for n in cells if cells[n].type == "mapping" and n.lower() in aff), None)
        if bal_var:
            weights = {cell_to_id[cells[total_var]]: +1, cell_to_id[cells[bal_var]]: -1}
            return ConservedFunctional(id=f"{total_var}-Σ{bal_var}", weights=weights)
    return None


# ── orchestrator: run all three legs over a source tree ───────────────────────────────────────

EXTERNAL = "__EXTERNAL__"


def _contract_fns(contract: dict) -> list[dict]:
    return [n for n in contract.get("nodes", []) if n.get("nodeType") == "FunctionDefinition"]


def _state_var_names(contract: dict) -> set:
    return {n.get("name") for n in contract.get("nodes", [])
            if n.get("nodeType") == "VariableDeclaration"
            and not n.get("constant") and n.get("mutability") not in ("constant", "immutable")}


def typed_audit(source_root) -> list[dict]:
    """Run the three typed-complex legs over every .sol file and return uniform findings:

      homology       — cross-function reentrancy (a cell read before an external call and written
                        after, with no bounding nonReentrant/CEI 2-cell).
      typed_collision — delegatecall/proxy storage collision (a storage slot carries conflicting
                        typed interpretations across a resolved proxy↔implementation or version
                        pair — cross-file, gated on a relationship, not bare co-location).
      conservation   — value leak (a function whose net signed delta breaks a recognized conserved
                        functional q = total − Σbalance).

    Each finding carries leg, contract, function, file, line, detail, confidence — the same shape
    solidity_audit emits, so the triage/intake layers consume them identically.

    Two passes: the homology and conservation legs are per-contract (no cross-file need); the
    typed-collision leg is GLOBAL across the whole tree but gated on a resolved proxy↔implementation
    relationship (explicit reference, naming family, or same-file delegatecall) — never on bare
    co-location, so cross-file coverage does not become a false-positive explosion."""
    from lattice.ingest.solidity import _solc_ast, _iter, _byte_line, _sol_files, _audit_rel

    root = pathlib.Path(source_root)
    out: list[dict] = []
    units: list[dict] = []                                  # every contract across all files

    # pass 0: parse every file once and collect all contract/interface names (for address-sized
    # contract pointers and explicit-reference resolution)
    parsed: list[tuple] = []
    known_types: set = set()
    registry: dict = {}                                    # name -> contract AST, for inheritance flatten
    for path in _sol_files(root):
        ast = _solc_ast(path)
        if ast is None:
            continue
        parsed.append((path, ast))
        for c in _iter(ast, "ContractDefinition"):
            known_types.add(c.get("name"))
            registry[c.get("name")] = c

    for path, ast in parsed:
        rel = _audit_rel(path, root)
        nl = [i for i, b in enumerate(path.read_bytes()) if b == 0x0A]

        contracts = list(_iter(ast, "ContractDefinition"))
        # TIER-1 real layout where the file typechecks, TIER-2 hand-rolled packer otherwise
        layouts = _storage_layouts(path)
        cells_by_contract = {}
        for c in contracts:
            name = c.get("name", "")
            if name in layouts:
                cells_by_contract[name] = cells_from_layout(name, layouts[name])
            else:
                cells_by_contract[name] = storage_cells(c, known_types, registry)
        all_cells = [cell for cmap in cells_by_contract.values() for cell in cmap.values()]
        cell_to_id, _ = intern_cells(all_cells)

        out += _homology_leg(contracts, cells_by_contract, cell_to_id, rel, nl)
        out += _conservation_leg(contracts, cells_by_contract, cell_to_id, rel, nl)
        for c in contracts:
            units.append({"name": c.get("name", ""), "ast": c, "file": rel,
                          "cells": cells_by_contract.get(c.get("name", ""), {}),
                          "delegates": _contract_delegates(c),
                          "kind": c.get("contractKind", "contract"), "bases": _base_names(c)})

    out += _collision_leg_global(units)
    return out


def _contract_delegates(contract: dict) -> bool:
    """Does any function of this contract perform a delegatecall (the cross-boundary that aliases
    caller storage onto a callee's layout)?"""
    svars = _state_var_names(contract)
    for fn in _contract_fns(contract):
        eff = _new_eff()
        _typed_effects(fn.get("body") or {}, svars, eff, None, svars | _fn_params(fn))
        if eff["delegatecalls"]:
            return True
    return False


def _homology_leg(contracts, cells_by_contract, cell_to_id, rel, nl) -> list[dict]:
    from lattice.ingest.solidity import _byte_line
    out = []
    mod_defs = {}
    for contract in contracts:
        cname = contract.get("name", "")
        cells = cells_by_contract.get(cname, {})
        svars = set(cells)                              # all state vars incl. INHERITED (flattened cells)
        mod_defs = {m.get("name"): m for m in contract.get("nodes", [])
                    if m.get("nodeType") == "ModifierDefinition"}
        s2v = _slot_to_vars(cells)
        fns = {}
        for fn in _contract_fns(contract):
            eff = _new_eff()
            _typed_effects(fn.get("body") or {}, svars, eff, s2v, svars | _fn_params(fn))
            fns[fn.get("name") or fn.get("kind", "function")] = (fn, eff)
        helpers = {name: fn for name, (fn, _e) in fns.items()}   # one-hop guard-check resolution

        from lattice.ingest.solidity import _access_controlled, _effectively_ac_names
        eff_ac = _effectively_ac_names(contract)   # internal fns reachable only via privileged entries
        for fname, (fn, eff) in fns.items():
            # reentrancy behind access control is only reachable by a privileged caller -> downgrade to
            # low confidence (NOT suppress: the gate may be bypassable, so a permissionless-equivalent bug
            # still surfaces; the cold not-so-smart permissionless reentrancies stay HIGH). Direct gate OR
            # interprocedural (internal fn reached only via privileged entries — the _addDeposit residual).
            ac = _access_controlled(fn) or ("a privileged caller (interprocedural)" if fname in eff_ac else None)
            # a guard recognized by BODY (self-referential mutex), following one helper hop
            applied = [m.get("modifierName", {}).get("name") for m in fn.get("modifiers", [])]
            kinds = [_modifier_guard_kind(mod_defs[mn], svars, helpers) for mn in applied if mn in mod_defs]
            guarded = "mutex" in kinds
            # an UNVERIFIABLE guard (assembly/transient, in the modifier OR the function body): we
            # can't confirm it bounds the loop, so we neither suppress (FN) nor fire confidently —
            # an obstruction here is escalated as a blindspot, the honest middle.
            # only a MODIFIER-based transient/assembly guard demotes to a blindspot; a function-body
            # transient op is data, and must NOT mask a genuine persistent-storage reentrancy (FN)
            asm_guard = (not guarded) and ("asm" in kinds)
            # a COMPUTED-slot assembly write is itself a blindspot (target var unresolvable)
            if eff["asm_unresolved"] and eff["ext_calls"]:
                out.append({"leg": "blindspot", "kind": "assembly_after_external_call",
                            "severity": "review", "contract": cname, "function": fname, "file": rel,
                            "line": _byte_line(nl, f"{eff['asm_unresolved'][0]}::"), "confidence": "review",
                            "detail": "inline assembly writes a COMPUTED (non-literal) slot in a function "
                                      "with an external call — the target var cannot be resolved, so a "
                                      "Yul stale-write would be invisible; review the ordering manually"})
            for C, Cend in eff["ext_calls"]:
                # cells written after C (in this fn or a callee invoked after C)
                obstruction = []
                for var, ws in eff["writes"].items():
                    if var not in cells:
                        continue
                    if any(p > C for _, p in ws) and any(r < Cend for r in eff["reads"].get(var, [])):
                        wpos = min(p for _, p in ws if p > C)
                        obstruction.append((var, wpos))
                for callee, cpos in eff["calls"]:
                    if cpos > C and callee in fns:
                        for var in fns[callee][1]["writes"]:
                            if var in cells and any(r < Cend for r in eff["reads"].get(var, [])):
                                obstruction.append((var, cpos))
                if not obstruction:
                    continue
                # build the cell-space loop complex: cid --read--> EXT --write--> cid per cell
                cell_edges, two_cells, meta = [], [], []
                for i, (var, wpos) in enumerate(obstruction):
                    cid = f"c{cell_to_id[cells[var]]}"
                    cell_edges += [(cid, EXTERNAL), (EXTERNAL, cid)]
                    if guarded:                            # real mutex -> the loop BOUNDS (2-cell)
                        two_cells.append([2 * i, 2 * i + 1])
                    meta.append((var, wpos))
                b1, reps = homology_obstructions(cell_edges, two_cells)
                if b1 <= 0:
                    continue
                # surviving cells -> findings
                survived = {e[0] for rep in reps for e in rep} | {e[1] for rep in reps for e in rep}
                for i, (var, wpos) in enumerate(meta):
                    if f"c{cell_to_id[cells[var]]}" not in survived:
                        continue
                    if asm_guard:
                        # the ordering looks reentrant, but an assembly/transient guard we cannot
                        # verify may prevent it — escalate, do not confidently fire (and do not suppress)
                        out.append({"leg": "blindspot", "kind": "unverifiable_reentrancy_guard",
                                    "severity": "review", "contract": cname, "function": fname,
                                    "file": rel, "line": _byte_line(nl, f"{C}::"), "confidence": "review",
                                    "detail": f"external call then a write to '{var}' read before it — "
                                              f"reentrant ORDERING, but an assembly/transient (EIP-1153) "
                                              f"guard is present that cannot be statically verified; "
                                              f"confirm the guard actually covers this path"})
                    else:
                        out.append({"leg": "homology", "kind": "reentrancy",
                                    "severity": "low" if ac else "high",
                                    "contract": cname, "function": fname, "file": rel,
                                    "line": _byte_line(nl, f"{C}::"),
                                    "call_line": _byte_line(nl, f"{C}::"),
                                    "write_line": _byte_line(nl, f"{wpos}::"),
                                    "confidence": "low" if ac else "heuristic",
                                    "detail": (f"[access-controlled by '{ac}': only a privileged caller "
                                               f"reaches this — lower exploitability] " if ac else "")
                                              + f"typed sheaf obstruction: external call then a write to "
                                              f"'{var}' read before the call — re-entry sees stale state"})
    # collapse per-CELL reentrancy duplicates to ONE per (contract, function): N state vars written after
    # the same call is ONE reentrancy to triage, not N findings (Morpho.liquidate wrote ~15 -> 15 dupes).
    # Recall-safe — the function is still flagged; the extra vars are noted on the single finding.
    deduped: list[dict] = []
    seen: dict = {}
    for f in out:
        if f.get("kind") != "reentrancy":
            deduped.append(f)
            continue
        key = (f.get("contract"), f.get("function"))
        if key in seen:
            seen[key]["also_writes"] = seen[key].get("also_writes", 1) + 1
        else:
            seen[key] = f
            deduped.append(f)
    return deduped


_ROLE_SUFFIX = re.compile(r"(Proxy|Implementation|Impl|Logic|Upgradeable|Beacon|Storage|Facet)$")
_VERSION_SUFFIX = re.compile(r"V\d+$")


def _family_base(name: str) -> str:
    """Strip a trailing version (V2) and one role suffix (Proxy/Logic/...) to a family base, so
    `VaultProxy`/`Vault` and `TokenV1`/`TokenV2` map to the same base. Never returns empty."""
    b = _VERSION_SUFFIX.sub("", name)
    stripped = _ROLE_SUFFIX.sub("", b)
    return stripped or b


def _referenced_names(node, known: set, out: set):
    """Contract-type names referenced anywhere in a contract's AST (UserDefinedTypeName / casts /
    `new X()`) — the explicit proxy→implementation link when the proxy names its logic type."""
    if isinstance(node, dict):
        if node.get("nodeType") == "UserDefinedTypeName":
            nm = node.get("name") or (node.get("pathNode") or {}).get("name")
            if nm in known:
                out.add(nm)
        elif node.get("nodeType") == "Identifier" and node.get("name") in known:
            out.add(node["name"])
        for v in node.values():
            _referenced_names(v, known, out)
    elif isinstance(node, list):
        for x in node:
            _referenced_names(x, known, out)


def _index_by_name(units: list[dict]) -> dict:
    """name -> unit, preferring the unit that actually carries storage cells when a name is reused
    (e.g. an `interface Logic` and a `contract Logic` — compare against the stateful one)."""
    by_name: dict = {}
    for u in units:
        cur = by_name.get(u["name"])
        if cur is None or len(u["cells"]) > len(cur["cells"]):
            by_name[u["name"]] = u
    return by_name


def _base_names(contract: dict) -> set:
    """The contracts/interfaces a contract inherits (its `is X, Y` list)."""
    out: set = set()
    for b in contract.get("baseContracts", []) or []:
        bn = b.get("baseName") or {}
        nm = bn.get("name") or (bn.get("pathNode") or {}).get("name")
        if nm:
            out.add(nm)
    return out


def _resolve_pairs(units: list[dict]) -> list[tuple]:
    """Resolve which contract pairs share a proxy↔implementation (or version-upgrade) relationship,
    so the collision leg compares ONLY related layouts — never bare co-location. Three bases:
    explicit type reference, naming family, and same-file delegatecall. Returns (nameA, nameB, basis)."""
    by_name = _index_by_name(units)
    known = set(by_name)
    pairs: dict = {}

    # (1) explicit: a delegatecaller references another contract's type. A reference to an INTERFACE
    # (cell-less) resolves to the concrete contracts that IMPLEMENT it — otherwise the real collision
    # is masked by an empty interface layout.
    for u in units:
        if not u["delegates"]:
            continue
        refs: set = set()
        _referenced_names(u["ast"], known, refs)
        for ref in refs:
            if ref == u["name"]:
                continue
            ref_unit = by_name.get(ref)
            if ref_unit and ref_unit.get("kind") == "interface":
                for impl in units:
                    if ref in impl.get("bases", set()) and impl["name"] != u["name"]:
                        pairs.setdefault(frozenset((u["name"], impl["name"])), "explicit-reference")
            else:
                pairs.setdefault(frozenset((u["name"], ref)), "explicit-reference")

    # (2) naming family: XProxy↔X, XV1↔XV2 — ONLY when a member actually delegatecalls. A shared
    # family base + a proxy-ish name is NOT enough (lexical coincidence over-fires on independent
    # V1/V2 or Proxy/Logic contracts); a real delegating member is the corroborating evidence.
    fam: dict = {}
    for u in units:
        fam.setdefault(_family_base(u["name"]), []).append(u["name"])
    for base, members in fam.items():
        if len(members) < 2 or not any(by_name[m]["delegates"] for m in members):
            continue
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                pairs.setdefault(frozenset((members[i], members[j])), "naming-family")

    # (3) same-file delegatecall co-location (the original within-file behavior, lowest confidence).
    # Skip cell-less interfaces as targets — pairing a delegatecaller with a co-located interface
    # produces an empty (no-collision) comparison that MASKS the real same-file implementation.
    by_file: dict = {}
    for u in units:
        by_file.setdefault(u["file"], []).append(u)
    for us in by_file.values():
        for d in (u for u in us if u["delegates"]):
            for u in us:
                if u["name"] != d["name"] and u.get("kind") != "interface" and u.get("cells"):
                    pairs.setdefault(frozenset((d["name"], u["name"])), "same-file")

    # only genuine two-distinct-name pairs (duplicate names collapse the frozenset to size 1)
    out = []
    for fs, basis in pairs.items():
        names = sorted(fs)
        if len(names) == 2:
            out.append((names[0], names[1], basis))
    return out


def _collision_leg_global(units: list[dict]) -> list[dict]:
    """Compare the storage layouts of resolved proxy↔implementation pairs (across files). A
    collision is a storage REGION (slot, offset) both contracts occupy with conflicting types —
    caller storage reinterpreted by the callee's layout, or an upgrade that shifts a slot. Stateless
    proxies (no declared cells) contribute nothing and never false-fire; a correct matching layout
    agrees on every region. Findings are needs-confirmation (the target is not statically proven)."""
    by_name = _index_by_name(units)
    out: list[dict] = []
    seen_findings: set = set()
    pairs = _resolve_pairs(units)
    # a contract that PROVABLY delegatecalls but whose target is not STATICALLY RESOLVED (only an
    # explicit type reference proves the target; a naming/same-file pairing is a heuristic guess that
    # may coincidentally match a co-located layout and mask a runtime/beacon target) forwards storage
    # to foreign code we cannot see — escalate a blindspot rather than go silent (no-silent-FN footing).
    resolved = {n for a, b, basis in pairs if basis == "explicit-reference" for n in (a, b)}
    for u in units:
        if u["delegates"] and u["name"] not in resolved:
            out.append({"leg": "blindspot", "kind": "unresolvable_delegatecall_target",
                        "severity": "review", "contract": u["name"], "function": "<delegatecall>",
                        "file": u["file"], "line": 1, "confidence": "review",
                        "detail": "contract delegatecalls to a target that cannot be statically resolved "
                                  "(runtime address / selector router / beacon) with no implementation "
                                  "pair found — storage collision with the foreign layout is unchecked; "
                                  "review the target's storage layout manually"})
    for a, b, basis in pairs:
        ua, ub = by_name[a], by_name[b]
        # region edges across the two layouts -> typed_h1 fires on a region with conflicting types
        region_id: dict = {}
        edges, eid = [], 0
        for u in (ua, ub):
            for cell in u["cells"].values():
                rid = region_id.setdefault((cell.slot, cell.offset), len(region_id))
                edges.append({"id": eid, "cell": rid, "typed": cell.typed, "contract": u["name"]})
                eid += 1
        # severity keyed to the strength of the relationship evidence (RANK 7): an explicit type
        # reference is strong; a naming/same-file basis is a needs-confirmation lead, not 'high'.
        severity = "high" if basis == "explicit-reference" else "medium"
        _, obs = typed_h1(edges)
        for o in obs:
            key = (a, b, tuple(o["typed_keys"]))
            if key in seen_findings:
                continue
            seen_findings.add(key)
            out.append({"leg": "typed_collision", "kind": "storage_collision", "severity": severity,
                        "contract": f"{a} / {b}", "function": "<delegatecall>", "file": ua["file"],
                        "confidence": "unproven", "line": 1, "basis": basis,
                        "detail": f"potential storage collision between {a} and {b} ({basis}): a slot "
                                  f"carries conflicting typed interpretations {o['typed_keys']} — "
                                  f"UNVERIFIED: confirm the delegatecall/upgrade relationship "
                                  f"(caller storage would be reinterpreted by the other's layout)"})
    return out


def _conservation_path_uncertain(body, conserved_vars: set) -> bool:
    """True if a conserved-quantity write is control-flow dependent — nested in an if/loop body, or
    the function has a conditional (early) return — so the flat signed-Z sum cannot confirm balance
    across all paths. Conservative: writes-a-conserved-var AND (a conditional write OR an early return)."""
    flag = {"cond_write": False, "early_return": False, "writes": False}

    def walk(n, cond):
        if isinstance(n, dict):
            nt = n.get("nodeType")
            if nt == "IfStatement":
                walk(n.get("trueBody"), True)
                walk(n.get("falseBody"), True)
                return
            if nt in ("ForStatement", "WhileStatement", "DoWhileStatement"):
                walk(n.get("body"), True)
                return
            if nt == "Return" and cond:
                flag["early_return"] = True
            elif nt == "Assignment":
                if _base_name(n.get("leftHandSide", {})) in conserved_vars:
                    flag["writes"] = True
                    if cond:
                        flag["cond_write"] = True
            for v in n.values():
                walk(v, cond)
        elif isinstance(n, list):
            for x in n:
                walk(x, cond)

    walk(body or {}, False)
    return flag["writes"] and (flag["cond_write"] or flag["early_return"])


def _struct_hides_accounting(contract: dict) -> bool:
    """A StructDefinition with a total*/balance-named member — accounting the top-level scan misses
    (ERC-7201 namespaced storage, diamond storage). Conservative blindspot trigger, not silent."""
    for sd in contract.get("nodes", []):
        if sd.get("nodeType") == "StructDefinition":
            for m in sd.get("members", []):
                nm = (m.get("name") or "").lower()
                if nm in _TOTAL_NAMES or nm in _BALANCE_NAMES:
                    return True
    return False


def _has_accounting_shape(cells: dict) -> bool:
    """Token/vault-shaped state worth a blindspot when no invariant is matched: a balance-like
    mapping + a scalar, OR any recognized total* scalar at all (so a total with an ARRAY/struct
    ledger — which q cannot model, since q needs a mapping — still escalates rather than passing)."""
    has_map = any(c.type == "mapping" for c in cells.values())
    has_scalar = any(c.type.startswith(("uint", "int")) for c in cells.values())
    has_total = any(n.lower() in _TOTAL_NAMES for n in cells)
    return (has_map and has_scalar) or has_total


def _conservation_leg(contracts, cells_by_contract, cell_to_id, rel, nl) -> list[dict]:
    from lattice.ingest.solidity import _byte_line
    out = []
    for contract in contracts:
        cname = contract.get("name", "")
        cells = cells_by_contract.get(cname, {})
        functional = recognize_functional(cells, cell_to_id)
        if functional is None:
            # no-silent-FN: accounting-shaped state we can't pin an invariant for becomes a
            # blindspot, not a clean pass — including a total*/balance hidden inside a STRUCT or
            # ERC-7201 namespaced-storage struct (storage_cells only enumerates top-level vars)
            if _has_accounting_shape(cells) or _struct_hides_accounting(contract):
                out.append({"leg": "blindspot", "kind": "unrecognized_conserved_quantity",
                            "severity": "review", "contract": cname, "function": "<contract>",
                            "file": rel, "line": 1, "confidence": "review",
                            "detail": "token/vault-shaped accounting state (possibly in a struct/namespaced "
                                      "layout) with no matched conservation invariant — the value leg "
                                      "cannot vouch for it; review manually"})
            continue
        # a SECOND total* scalar (a multi-quantity vault: totalAssets AND totalShares) is not
        # modeled by the single-q functional — escalate it rather than silently drop it
        totals = [n for n in cells if n.lower() in _TOTAL_NAMES]
        if len(totals) > 1:
            out.append({"leg": "blindspot", "kind": "multi_quantity_accounting",
                        "severity": "review", "contract": cname, "function": "<contract>",
                        "file": rel, "line": 1, "confidence": "review",
                        "detail": f"multiple conserved scalars {totals} but only one is modeled in q "
                                  f"({functional.id}) — the others' invariants are unchecked; review manually"})
        svars = set(cells)                              # incl. inherited vars (flattened cells)
        # per-function deltas + internal calls; an operation is a PUBLIC/EXTERNAL entry point with
        # its internal-helper deltas folded in (so a mint split across helpers nets correctly and
        # the helpers are not double-counted as standalone unbalanced ops)
        fn_info: dict = {}
        for fn in _contract_fns(contract):
            eff = _new_eff()
            _typed_effects(fn.get("body") or {}, svars, eff, None, svars | _fn_params(fn))
            deltas: dict = {}
            for var, ws in eff["writes"].items():
                if var not in cells:
                    continue
                cid = cell_to_id[cells[var]]
                deltas[cid] = deltas.get(cid, 0) + sum(s for s, _ in ws)
            # state cells written via a plain `=` overwrite (sign 0): the DELTA is unknown, so the
            # signed-Z sum can't account for it (a rebase / setSupply)
            overwrites = {var for var, ws in eff["writes"].items()
                          if var in cells and any(s == 0 for s, _ in ws)}
            fname = fn.get("name") or fn.get("kind", "function")
            fn_info[fname] = {"deltas": deltas, "calls": [c for c, _ in eff["calls"]],
                              "vis": fn.get("visibility", ""), "body": fn.get("body") or {},
                              "overwrites": overwrites}
        def _folded(fname: str, seen: set) -> dict:
            """A function's own deltas plus the TRANSITIVE deltas of every internal helper it reaches
            (so a leak — or its compensating write — any number of hops deep is accounted for)."""
            agg = dict(fn_info.get(fname, {}).get("deltas", {}))
            for callee in fn_info.get(fname, {}).get("calls", []):
                cinfo = fn_info.get(callee)
                if cinfo and cinfo["vis"] in ("internal", "private") and callee not in seen:
                    seen.add(callee)
                    for cid, d in _folded(callee, seen).items():
                        agg[cid] = agg.get(cid, 0) + d
            return agg

        # the flat signed-Z sum is PATH-INSENSITIVE: a function that credits a balance
        # unconditionally but the supply only conditionally (an if-guarded write, or a write after an
        # early return) can net to zero yet leak on the un-taken path. Where conserved writes are
        # control-flow dependent, escalate a blindspot — the balance verdict can't be trusted.
        conserved_vars = {n for n in cells if cell_to_id[cells[n]] in functional.weights}
        ops = []
        for fname, info in fn_info.items():
            if info["vis"] not in ("public", "external"):
                continue                                    # internal/private helpers are sub-steps
            if _conservation_path_uncertain(info["body"], conserved_vars):
                out.append({"leg": "blindspot", "kind": "path_dependent_accounting",
                            "severity": "review", "contract": cname, "function": fname,
                            "file": rel, "line": 1, "confidence": "review",
                            "detail": "a conserved quantity is written under a branch/loop or after an "
                                      "early return — the flat conservation check cannot confirm balance "
                                      "across all paths; review the un-taken path for a value leak"})
            if info["overwrites"] & conserved_vars:
                out.append({"leg": "blindspot", "kind": "conserved_scalar_overwrite",
                            "severity": "review", "contract": cname, "function": fname,
                            "file": rel, "line": 1, "confidence": "review",
                            "detail": "a conserved quantity is OVERWRITTEN via `=` (e.g. a rebase / "
                                      "setSupply) — its delta is unknown to the sign-only value check, "
                                      "so conservation cannot be verified; review manually"})
            agg = _folded(fname, {fname})
            if agg:
                ops.append({"op": fname, "deltas": agg, "edges": [], "symbolic": True})
        for o in conservation_obstructions(ops, functional):
            out.append({"leg": "conservation", "kind": "value_conservation", "severity": "high",
                        "contract": cname, "function": o.get("op"), "file": rel, "line": 1,
                        "confidence": "heuristic",
                        "detail": o.get("detail", "conservation break")})
    return out
