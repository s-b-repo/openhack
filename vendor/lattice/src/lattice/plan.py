# src/lattice/plan.py
"""Change planner — the RRT backward half, in structural form.

Given a target symbol and a kind of change, produce an ordered sequence of steps
that makes the change land reliably: implement-if-stub, change the target, then
propagate to dependents in reverse-dependency layers (closest first), with a
verification gate after each layer. Flags public-API crossings (external
coordination needed) and dependency-cycle risk (no clean order — must change
together). This is goal-backward planning: from "change landed + all green",
collect the preconditions in the order that keeps each step verifiable.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView


@dataclass
class Step:
    order: int
    action: str          # implement | change | update | verify | warn
    target: str
    detail: str


@dataclass
class Plan:
    goal: str
    steps: list[Step] = field(default_factory=list)
    crosses_public_api: list[str] = field(default_factory=list)
    has_cycle_risk: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _reverse_layers(g: GraphView, target: str) -> list[list[str]]:
    """BFS over the reverse (dependents) graph: layer 1 = direct dependents, etc."""
    layers: list[list[str]] = []
    seen = {target}
    frontier = [target]
    while True:
        nxt: list[str] = []
        for n in frontier:
            for r in g.references_to(n):
                if r not in seen:
                    seen.add(r)
                    nxt.append(r)
        if not nxt:
            break
        layers.append(sorted(set(nxt)))
        frontier = nxt
    return layers


def plan(net: Hypernetwork, target: str, kind: str = "modify") -> Plan:
    g = GraphView(net)
    vmap = {v.id: v for v in net.vertices}
    public_ids = {s.vertex_id for s in net.surfaces
                  if s.kind in ("public_api", "entrypoint")}

    steps: list[Step] = []
    crosses: list[str] = []
    n = [0]

    def add(action: str, tgt: str, detail: str):
        n[0] += 1
        steps.append(Step(n[0], action, tgt, detail))

    v = vmap.get(target)
    if v is not None and v.stub:
        add("implement", target,
            "target is an unimplemented stub — implement it before dependents rely on it")

    add("change", target, f"apply the {kind} to {target}")
    add("verify", target,
        "run `footings verify --against HEAD` — confirm the target is green before propagating")

    for i, layer in enumerate(_reverse_layers(g, target), start=1):
        for sym in layer:
            detail = f"update to conform to {target}'s new contract"
            if sym in public_ids:
                detail += "  ⚠ PUBLIC API — coordinate external consumers"
                crosses.append(sym)
            add("update", sym, detail)
        add("verify", f"layer-{i}", f"verify after updating dependency layer {i}")

    has_cycle_risk = False
    for scc in g.find_cycles():
        if target in scc and len(scc) > 1:
            has_cycle_risk = True
            add("warn", "cycle",
                f"target is in a dependency cycle {sorted(scc)} — these must change "
                f"together; there is no clean incremental order")

    return Plan(goal=f"{kind} {target}", steps=steps,
                crosses_public_api=sorted(set(crosses)), has_cycle_risk=has_cycle_risk)
