# src/lattice/typed_chain.py
"""The typed-constraint-algebra lift — frontend-agnostic.

chain.py is the raw GF(2)/Z math; this module is the TYPED complex that sits on it. The prior
load-bearing insight: Footings reads H¹=0 because its edges carry no constraint structure, so
every stalk is 1-dimensional and the boundary matrix is trivially full-rank. The lift makes
storage cells SHARED across edges (interned by physical key) and puts a constraint algebra on
edges, so the boundary/coboundary loses rank exactly where local promises fail to glue.

Three honest, separately-typed legs over the SAME interned 0-cells (the judges' central
correction — NOT one faked unified H¹, whose index spaces don't even align):

  1. HOMOLOGY      — reentrancy/stale-state: a read-before-call cell written after the call,
                     with no bounding guard 2-cell. β₁ = nullity(∂₁) − rank(∂₂) over GF(2).
  2. TYPED-COLLISION — delegatecall slot-aliasing / proxy collision: two conflicting typed keys
                     on one physical cell. Čech coboundary D; dim H¹ = Σdₑ − rank(D);
                     obstructions = ker(Dᵀ). Benign aliasing bounds UPSTREAM (impl_version match).
  3. CONSERVATION  — value leaks: a cycle whose signed delta against a conserved functional q is
                     nonzero. Signed-Z incidence; the one place Smith rank is justified
                     (even-multiplicity leaks are 0 mod 2).

Every leg reads the same interned cell table and edge list; they differ only in which matrix
they build and never write each other's outputs. A 2-cell/certificate can only KILL a finding,
never create one (so a missing relation over-fires rather than hides a bug — within what the
extraction can SEE).

Honest scope: these are high-recall SCREENS, not an oracle. A FIRE is a high-value lead; SILENCE
does not certify safety. The recall guarantee holds only over AST-visible state — assembly/Yul
writes, transient storage, and cross-contract/cross-file flows are confirmed blind spots
(escalated as `blindspot` findings by the adapter where detectable). See ingest/solidity_typed.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from lattice import chain


@dataclass(frozen=True)
class StateCell:
    """A typed storage location. The 6-tuple the lift demands. DEDUP IDENTITY is the PHYSICAL
    key (slot, offset, width) only — two effects on the same physical slot share one 0-cell,
    which is what loses rank and lets H¹ fire. The typed triple (type, namespace, impl_version)
    is carried for the collision leg but is NOT part of physical identity.

    `slot` is a str so it can hold an int index, a struct/diamond base, or a coarse sentinel
    ('*'+base) for unresolved targets (mapping element, computed slot, assembly) — over-sharing,
    biased toward over-fire, never a silent false negative.
    """
    slot: str
    offset: int = 0
    width: int = 32
    type: str = ""
    namespace: str = ""
    impl_version: str = ""

    @property
    def physical(self) -> tuple:
        """The dedup/interning identity — what physically aliases."""
        return (self.slot, self.offset, self.width)

    @property
    def typed(self) -> tuple:
        """What SHOULD be consistent — conflict here across a physical alias is a collision."""
        return (self.type, self.namespace, self.impl_version)


def intern_cells(cells: list[StateCell]) -> tuple[dict[StateCell, int], list[StateCell]]:
    """Dedup cells by their PHYSICAL key. Returns (cell -> shared id, id -> representative cell).
    Cells that differ only in the typed triple map to the SAME id (that physical sharing is the
    collision signal); the representative keeps the first-seen typed tag."""
    phys_to_id: dict[tuple, int] = {}
    id_to_cell: list[StateCell] = []
    cell_to_id: dict[StateCell, int] = {}
    for c in cells:
        k = c.physical
        if k not in phys_to_id:
            phys_to_id[k] = len(id_to_cell)
            id_to_cell.append(c)
        cell_to_id[c] = phys_to_id[k]
    return cell_to_id, id_to_cell


# ── Leg 1: HOMOLOGY (reentrancy / stale-state) ───────────────────────────────────────────────

def homology_obstructions(cell_edges: list[tuple],
                          two_cells: list[list[int]] | None = None) -> tuple[int, list[list[tuple]]]:
    """The homology leg. `cell_edges` is the read/call/write edge list projected to cell space —
    a reentrancy loop is `cid --read--> EXTERNAL --write--> cid`, which CLOSES because the
    read-before-call cell and the write-after-call cell intern to the same id. Returns
    (β₁, surviving non-bounding representative cycles), reusing chain.py unchanged: the 2-cells
    from confirmed invariants (nonReentrant / CEI / onlyOwner) make benign loops bound."""
    two_cells = two_cells or []
    verts = sorted({v for e in cell_edges for v in e}, key=str)
    b1 = chain.betti_1(verts, cell_edges, two_cells)
    reps = chain.h1_representatives(verts, cell_edges, two_cells)
    return b1, reps


# ── Leg 2: TYPED-COLLISION (delegatecall slot-aliasing / proxy storage collision) ─────────────

def typed_h1(edges: list[dict]) -> tuple[int, list[dict]]:
    """The typed-collision leg — H¹ of the typed-VALUE sheaf over physical cells.

    Each edge restricts its physical cell to one typed interpretation (its `typed` tag). A global
    section assigns each cell ONE type; it exists iff every edge on a cell agrees on the type.
    When a delegatecall/upgrade alias edge forces a SECOND, conflicting type onto a physical cell
    (owner-as-address vs value-as-uint256 on slot 0), the section fails to glue → H¹ > 0. dim H¹
    for a cell = (#distinct types it is forced into) − 1, summed over cells.

    Note (a verified correction to the design panel): this is the DISAGREEMENT sheaf, the dual of
    the homology leg's gluing sheaf — there an obstruction is two edges SHARING a key; here it is
    two edges DISAGREEING on a cell's type. Conflating them inverts the detector. Benign aliasing
    (matching layout) carries the SAME type, so it never enters this sum — the impl_version-match
    certificate is applied UPSTREAM in the adapter, which simply does not emit a conflicting alias
    edge when layouts agree.
    """
    by_cell: dict[int, list[dict]] = {}
    for e in edges:
        cid = e.get("cell")
        if cid is None:
            continue
        by_cell.setdefault(cid, []).append(e)

    dim = 0
    obstructions: list[dict] = []
    for cid, es in sorted(by_cell.items()):
        types = sorted({e["typed"][0] for e in es})       # distinct typed interpretations
        if len(types) > 1:
            dim += len(types) - 1
            obstructions.append({
                "leg": "typed_collision",
                "physical_cell": cid,
                "typed_keys": types,
                "conflicting_edges": sorted(e["id"] for e in es),
                "namespaces": sorted({e["typed"][1] for e in es if len(e["typed"]) > 1}),
            })
    return dim, obstructions


# ── Leg 3: CONSERVATION (value leaks against a conserved functional q) ────────────────────────

@dataclass(frozen=True)
class ConservedFunctional:
    """A linear conserved quantity q ∈ Hom(cells, Z): a weight per cell. q = totalSupply − Σbalance
    is `weights={supply_cell:+1, balance_cell:-1}` and should be invariantly 0. Detected by
    name/shape heuristics over the contract's state vars (in the adapter)."""
    id: str
    weights: dict          # cell_id -> int weight


def q_delta(functional: ConservedFunctional, deltas: dict) -> int:
    """The q-projected net change of an operation: Σ_cell q[cell] · delta[cell]."""
    return sum(functional.weights.get(c, 0) * d for c, d in deltas.items())


def conservation_obstructions(operations: list[dict],
                              functional: ConservedFunctional | None,
                              sanctioned: set | None = None) -> list[dict]:
    """The conservation leg. For each state-mutating operation, project its net per-cell delta
    through the conserved functional q. A nonzero q-delta is a value leak: the operation moved a
    quantity q says must be conserved (an unbacked mint, a transfer that touches supply, …).

    Because q is LINEAR it is additive over composition (q(A∘B)=q(A)+q(B)), so any violation is
    localizable to a single operation — per-op detection is complete and no cycle-space/Smith-form
    machinery is needed. Summing SIGNED deltas over Z (Python big-ints) catches even-multiplicity
    leaks (two unbacked mints = +2, ≠0 over Z) that a GF(2) parity test would miss.

    When no functional is recognized for accounting-shaped state, a `blindspot` finding is emitted
    rather than a silent clean pass (the no-silent-FN footing)."""
    if functional is None:
        return [{"leg": "blindspot", "kind": "unrecognized_conserved_quantity", "ops": operations,
                 "detail": "accounting-shaped state with no matched conservation invariant — "
                           "the value leg cannot vouch for it; review manually"}]
    sanctioned = sanctioned or set()
    out: list[dict] = []
    for op in operations:
        if op.get("op") in sanctioned:
            continue
        drift = q_delta(functional, op.get("deltas", {}))
        if drift != 0:
            out.append({
                "leg": "conservation", "op": op.get("op"), "functional": functional.id,
                "drift": drift, "symbolic": op.get("symbolic", False), "edges": op.get("edges", []),
                "detail": (f"conservation break: operation '{op.get('op')}' changes q[{functional.id}] "
                           f"by {drift} (a quantity that must be conserved)"),
            })
    return out
