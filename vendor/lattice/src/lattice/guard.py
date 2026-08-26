# src/lattice/guard.py
"""Guarded reachability — the one primitive behind every security/operations check.

For paths from a `source` set to a `sink` set:
  - a TOUCHPOINT finding for each reachable (source -> sink): the path touches a
    sensitive operation.
  - a MISSING-GATE finding when a required gate can be BYPASSED: i.e. the sink is
    still reachable from the source after the gate nodes are removed. (Every path
    crosses the gate  <=>  removing the gate disconnects source from sink. So an
    ungated route exists iff the sink stays reachable with the gate removed.)

secaudit's sink reachability, authorization, authentication, input-validation,
rate-limiting — all are this function with different (sinks, gates). One engine,
many configurations.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict

from lattice.graph.models import Hypernetwork
from lattice.graph.query import GraphView


@dataclass
class GuardFinding:
    kind: str            # touchpoint category (e.g. "command_exec") or "missing_<gate>"
    severity: str
    source: str
    sink: str
    path: list
    gate: str = ""       # set for missing-gate findings

    def to_dict(self) -> dict:
        return asdict(self)


def guarded_reachability(net: Hypernetwork, sources, sinks: dict, gates: dict) -> list[GuardFinding]:
    """sources: iterable of source vertex ids.
       sinks:   {category: (set_of_sink_vids, severity)}.
       gates:   {gate_name: set_of_gate_vids} — required waypoints.
    """
    g = GraphView(net)
    findings: list[GuardFinding] = []
    seen: set = set()
    for src in sources:
        reach = g.reachable_from(src)
        reach.add(src)
        for cat, (sink_set, sev) in sinks.items():
            for sink in sorted(sink_set & reach):
                key = (src, sink, cat)
                if key in seen:
                    continue
                seen.add(key)
                path = g.shortest_path(src, sink) or [src, sink]
                findings.append(GuardFinding(cat, sev, src, sink, path))

                # gate check: is there a route to this sink that avoids the gate?
                for gate_name, gate_vids in gates.items():
                    if not gate_vids or sink in gate_vids:
                        continue
                    ungated = g.reachable_from(src, avoid=gate_vids)
                    if sink in ungated or sink == src:
                        bypass = g.shortest_path(src, sink, avoid=gate_vids) or [src, sink]
                        findings.append(GuardFinding(
                            f"missing_{gate_name}", "high", src, sink, bypass, gate=gate_name))
    return findings
