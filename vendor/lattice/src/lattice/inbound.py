# src/lattice/inbound.py
"""Inbound boundary analysis — what each entrypoint asks for, and whether access is
explicitly bounded at the point.

An entrypoint is where untrusted requests enter — the start of every attack path. Two
facts matter at each one: WHAT'S BEING ASKED FOR (the input surface — the parameters it
accepts) and WHETHER ACCESS IS BOUNDED RIGHT HERE (a visible guard in its own body, not
assumed three calls downstream). "Explicit at the point" is load-bearing: an entry whose
bound is implicit and far away is still a hole at the entry. An entry that accepts input
with no guard at the point is surfaced as unbounded — a fact (no guard in its body), not
a verdict (middleware we can't see might cover it; that's the agent's call).

This is the dual of exposure.py (the outbound boundary): inbound = asked-for + bounded
at entry; outbound = accessible-to-callee + bounded at handoff. Both read from the
visible side only.
"""
from __future__ import annotations
import pathlib
from dataclasses import dataclass, field

from lattice.graph.models import Hypernetwork
from lattice.taxonomy import GATES, _norm
from lattice.security import _params_of, _called


@dataclass
class EntryPoint:
    symbol: str
    kind: str                                    # entrypoint | public_api
    location: str
    asks_for: list = field(default_factory=list)       # parameters — the input surface
    gates_at_point: list = field(default_factory=list)  # guard categories called in body
    bounded: bool = False                         # is access explicitly bounded at the point

    def to_dict(self) -> dict:
        return {"symbol": self.symbol, "kind": self.kind, "location": self.location,
                "asks_for": self.asks_for, "gates_at_point": self.gates_at_point,
                "bounded": self.bounded}


def _gates_in_body(body: str) -> list[str]:
    """Guard categories whose function is CALLED in this body (a bound at the point)."""
    hits: set[str] = set()
    for c in _called(body):
        n = _norm(c)
        for gate, pats in GATES.items():
            if any(p in n for p in pats):
                hits.add(gate)
    return sorted(hits)


def entrypoint_surface(net: Hypernetwork, source_root) -> list[EntryPoint]:
    """For each inbound boundary (entrypoint / exported public_api), report what it asks
    for and whether a guard is present at the point. The holes — accepts input, no bound
    here — are what an agent triages first."""
    root = pathlib.Path(source_root)
    vmap = {v.id: v for v in net.vertices}
    file_text: dict[str, str] = {}

    def ftext(f: str) -> str:
        if f not in file_text:
            try:
                file_text[f] = (root / f).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                file_text[f] = ""
        return file_text[f]

    # the inbound boundary: program entrypoints + exported callables (the attack surface)
    seen: set[str] = set()
    out: list[EntryPoint] = []
    for s in net.surfaces:
        if s.kind not in ("entrypoint", "public_api"):
            continue
        v = vmap.get(s.vertex_id)
        if v is None or v.kind not in ("function", "method") or v.id in seen:
            continue
        seen.add(v.id)
        text = ftext(v.file)
        body = "\n".join(text.splitlines()[v.start_line - 1: v.end_line])
        gates = _gates_in_body(body)
        out.append(EntryPoint(
            symbol=v.id, kind=s.kind, location=f"{v.file}:{v.start_line}",
            asks_for=_params_of(v, text), gates_at_point=gates, bounded=bool(gates)))
    return out
