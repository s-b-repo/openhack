# src/lattice/complete/report.py
from __future__ import annotations
from dataclasses import dataclass, field, asdict

@dataclass
class HypernetworkReport:
    resolution: float
    dangling_edges: list[str] = field(default_factory=list)
    unresolved_imports: list[str] = field(default_factory=list)
    stubs: list[str] = field(default_factory=list)
    surface_coverage: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)        # recall indicator (not a guarantee)
    diagnostics: list[dict] = field(default_factory=list)
    verdict: str = "fail"
    failing_checks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
