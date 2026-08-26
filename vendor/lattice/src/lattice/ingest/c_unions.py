"""THIRD-leg, second-language ingest — proof the COLLISION operator (the disagreement sheaf,
`typed_h1`) carries beyond Solidity. A C `union` overlays several declared types on ONE physical
location (offset 0); writing one member and reading another is type confusion — the SAME
obstruction as a Solidity proxy storage collision (one slot, conflicting declared types under
delegatecall). A `struct` puts its fields at DISTINCT offsets (distinct physical cells), so it
must NOT collide — the control. The engine (`typed_h1`) is untouched; only this ~40-line adapter
is language-specific (a regex parse here; a real ingest would use libclang/pycparser).
"""
import re
import hashlib
import pathlib
from lattice.typed_chain import typed_h1

# Common C integer widths (best-effort, LP64). Adding the stdint / stddef typedefs closes
# the offset-calculation gap where a struct using `size_t`/`uint64_t`/`uintptr_t` had its
# subsequent members mis-aligned relative to the union comparison — silently missing
# collision when the offset didn't match. The width of `long`/`long long`/`size_t`/`ptrdiff_t`
# is architecture-dependent (LP64 assumed); if this gets wrong on ILP32 we still surface a
# blindspot, we just don't over-fire (FIRE=lead / SILENCE≠proof).
_SIZEOF = {
    "char": 1, "int8_t": 1, "uint8_t": 1, "bool": 1, "_Bool": 1,
    "short": 2, "int16_t": 2, "uint16_t": 2,
    "int": 4, "unsigned": 4, "float": 4, "int32_t": 4, "uint32_t": 4,
    "long": 8, "double": 8, "int64_t": 8, "uint64_t": 8,
    "size_t": 8, "ssize_t": 8, "ptrdiff_t": 8,
    "uintptr_t": 8, "intptr_t": 8,
    "long long": 8, "unsigned long": 8, "unsigned long long": 8,
    "unsigned int": 4, "unsigned short": 2, "unsigned char": 1,
    "off_t": 8, "time_t": 8,
}
_MEMBER = re.compile(r"([A-Za-z_][\w \t\*]*?)\s+([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*;")
_AGG = re.compile(r"\b(union|struct)\s+(\w+)\s*\{([^}]*)\}", re.S)


def _norm_type(t: str) -> str:
    t = t.strip()
    if "*" in t:
        return "pointer"                      # any pointer type — confusing it forges an address
    parts = t.split()
    return parts[-1] if parts else t


def _cid(key) -> int:
    return int(hashlib.md5(str(key).encode()).hexdigest()[:8], 16)


def union_audit(path) -> list[dict]:
    """Run the SHARED typed-collision operator over a C file's aggregate type layouts."""
    src = pathlib.Path(path).read_text(encoding="utf-8", errors="ignore")
    edges: list[dict] = []
    for agg in _AGG.finditer(src):
        kind, name, body = agg.group(1), agg.group(2), agg.group(3)
        off = 0
        for mt in _MEMBER.finditer(body):
            typ = _norm_type(mt.group(1))
            mem = mt.group(2)
            # union: every member shares offset 0 (one physical cell). struct: distinct offsets.
            cell = _cid((name, 0)) if kind == "union" else _cid((name, off))
            edges.append({"cell": cell, "typed": (typ, name), "id": f"{name}.{mem}"})
            if kind == "struct":
                off += _SIZEOF.get(typ, 8)
    dim, obstructions = typed_h1(edges)
    out: list[dict] = []
    for o in obstructions:
        ns = o["namespaces"][0] if o["namespaces"] else "?"
        out.append({
            "kind": "type_confusion", "severity": "high", "union": ns, "types": o["typed_keys"],
            "detail": (f"union '{ns}' overlays conflicting declared types {o['typed_keys']} on one "
                       f"location — writing one member and reading another reinterprets the bytes "
                       f"(type confusion); same typed-collision obstruction as a proxy storage clash"),
        })
    return out
