# src/lattice/graph/models.py
from __future__ import annotations
from dataclasses import dataclass, field, asdict

SCHEMA_VERSION = "lattice.hypernetwork.v1"

@dataclass
class Vertex:
    id: str
    kind: str          # module|class|interface|function|method|variable|type|external
    name: str
    file: str
    start_line: int
    end_line: int
    type: str | None = None
    exported: bool = False
    stub: bool = False
    params: list = field(default_factory=list)   # param names (rest as "...name") — join contract

@dataclass
class Hyperedge:
    id: str
    kind: str          # imports|calls|references|inherits|implements|defines|returns|reconciles
    members: list[str]
    directed: bool = True
    resolved: bool = False
    # Provenance + confidence separate asserted facts from proposals. LSP/import edges
    # are fact-grade (confidence 1.0, provenance "ingest"). Cross-language `reconciles`
    # edges are candidates (confidence < 1.0, provenance names the matcher) to be
    # confirmed or rejected in review before they count as trusted structure.
    confidence: float = 1.0
    provenance: str = "ingest"

@dataclass
class Surface:
    id: str
    vertex_id: str
    kind: str          # entrypoint|external_call|public_api|trust_boundary

@dataclass
class Hypernetwork:
    language: str
    root: str
    vertices: list[Vertex] = field(default_factory=list)
    hyperedges: list[Hyperedge] = field(default_factory=list)
    surfaces: list[Surface] = field(default_factory=list)
    # Frontend/parser diagnostics are part of the graph artifact.  Dropping them at
    # the RawIngest -> Hypernetwork boundary lets a failed parser look like a clean,
    # empty graph when the artifact is later checked or loaded from cache.
    diagnostics: list[dict] = field(default_factory=list)

    @property
    def stats(self) -> dict:
        return {"vertices": len(self.vertices),
                "hyperedges": len(self.hyperedges),
                "surfaces": len(self.surfaces)}

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "language": self.language,
            "root": self.root,
            "vertices": [asdict(v) for v in self.vertices],
            "hyperedges": [asdict(e) for e in self.hyperedges],
            "surfaces": [asdict(s) for s in self.surfaces],
            "diagnostics": self.diagnostics,
            "stats": self.stats,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Hypernetwork":
        return cls(
            language=d["language"],
            root=d["root"],
            vertices=[Vertex(**v) for v in d.get("vertices", [])],
            hyperedges=[Hyperedge(**e) for e in d.get("hyperedges", [])],
            surfaces=[Surface(**s) for s in d.get("surfaces", [])],
            diagnostics=list(d.get("diagnostics", [])),
        )
