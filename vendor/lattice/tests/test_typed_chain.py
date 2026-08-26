from lattice.typed_chain import (StateCell, intern_cells, homology_obstructions, typed_h1,
                                 ConservedFunctional, conservation_obstructions)


def test_statecell_physical_key_ignores_typed_triple():
    """Dedup identity is the PHYSICAL key (slot,offset,width); the typed triple
    (type,namespace,impl_version) is carried but is NOT part of physical identity."""
    owner = StateCell(slot="0", offset=0, width=32, type="address", namespace="Proxy", impl_version="A")
    value = StateCell(slot="0", offset=0, width=32, type="uint256", namespace="Logic", impl_version="B")
    assert owner.physical == value.physical == ("0", 0, 32)
    assert owner.typed != value.typed            # they conflict on the typed triple
    assert owner != value                         # but are distinct objects (full equality)


def test_packed_vars_in_one_slot_are_distinct_cells():
    """Two uint128 packed into slot 1 occupy distinct (offset,width) -> distinct physical cells;
    a uint256 owns its slot."""
    a = StateCell(slot="1", offset=0, width=16, type="uint128")
    b = StateCell(slot="1", offset=16, width=16, type="uint128")
    full = StateCell(slot="0", offset=0, width=32, type="uint256")
    _, cells = intern_cells([a, b, full])
    assert len(cells) == 3


def test_intern_dedups_by_physical_key_collision_maps_to_one_id():
    """Two physically-identical cells with conflicting typed triples (a slot-aliasing collision)
    intern to ONE shared id — that sharing is what later loses rank and makes H¹ fire."""
    owner = StateCell(slot="0", offset=0, width=32, type="address", namespace="Proxy")
    value = StateCell(slot="0", offset=0, width=32, type="uint256", namespace="Logic")
    cell_to_id, cells = intern_cells([owner, value])
    assert len(cells) == 1                        # one physical slot
    assert cell_to_id[owner] == cell_to_id[value] == 0


def test_homology_reentrancy_fires_without_guard():
    """Cross-function CEI reentrancy (TheDAO-class). balances[u] is READ before the external
    .call, then WRITTEN after (the write may be in a callee). In cell space the loop CLOSES:
    B --read--> EXTERNAL --write--> B. With no guard 2-cell it is a live H₁ obstruction."""
    b1, reps = homology_obstructions([("B", "EXTERNAL"), ("EXTERNAL", "B")], two_cells=[])
    assert b1 == 1
    assert len(reps) == 1 and len(reps[0]) == 2


def test_homology_reentrancy_bounds_with_nonreentrant():
    """The benign control: the same loop, but the function carries a nonReentrant modifier, so
    two_cells_from_invariants emits a 2-cell binding the loop. It must drop to β₁=0 and ZERO
    surviving representatives (the load-bearing quotient — without it every guarded loop fires)."""
    b1, reps = homology_obstructions([("B", "EXTERNAL"), ("EXTERNAL", "B")], two_cells=[[0, 1]])
    assert b1 == 0
    assert reps == []


def test_homology_cei_ordering_bounds():
    """Checks-Effects-Interactions correct ordering is benign: the effect precedes the call, so
    no read-before-call cell is written after -> the loop never closes in cell space -> β₁=0."""
    # CEI-correct: write happens, THEN the external call; modelled as no return edge to B
    b1, reps = homology_obstructions([("B", "EXTERNAL")], two_cells=[])
    assert b1 == 0
    assert reps == []


# ── Leg 2: TYPED-COLLISION (delegatecall slot-aliasing / proxy collision) ──────────────────

def test_typed_collision_proxy_slot_aliasing_fires():
    """Unstructured-storage proxy collision. Proxy slot0 = owner(address); Logic slot0 =
    value(uint256). The delegatecall alias edge rebinds Logic's slot0 onto Proxy's slot0, so one
    PHYSICAL cell carries two conflicting typed interpretations — no consistent global type."""
    edges = [
        {"id": 0, "cell": 0, "typed": ("address", "Proxy", "A")},   # owner write
        {"id": 1, "cell": 0, "typed": ("uint256", "Logic", "B")},   # value write via delegatecall
    ]
    dim, obs = typed_h1(edges)
    assert dim >= 1
    assert obs and obs[0]["physical_cell"] == 0
    assert set(obs[0]["conflicting_edges"]) == {0, 1}
    assert set(obs[0]["typed_keys"]) == {"address", "uint256"}


def test_typed_collision_identical_layout_no_fire():
    """Well-formed EIP-1967 upgrade preserving layout: both sides interpret slot0 as the same
    type. One consistent global type -> H¹=0, no false positive on a correct proxy."""
    edges = [
        {"id": 0, "cell": 0, "typed": ("address", "Proxy", "A")},
        {"id": 1, "cell": 0, "typed": ("address", "Logic", "A")},   # same type, layout matches
    ]
    dim, obs = typed_h1(edges)
    assert dim == 0
    assert obs == []


def test_typed_collision_upgrade_layout_shift_fires():
    """Upgrade storage corruption: V2 inserts a variable, shifting `a` to a slot V1 used for a
    different type. Same physical slot, conflicting typed interpretations across impl_versions."""
    edges = [
        {"id": 0, "cell": 1, "typed": ("address", "Vault", "V1")},   # slot1 was `a`
        {"id": 1, "cell": 1, "typed": ("uint256", "Vault", "V2")},   # slot1 now `b` after insert
    ]
    dim, obs = typed_h1(edges)
    assert dim >= 1
    assert set(obs[0]["typed_keys"]) == {"address", "uint256"}


# ── Leg 3: CONSERVATION (value leaks against a conserved functional q) ─────────────────────

# q = totalSupply − Σ balances ; should be invariantly 0. cell 0 = totalSupply, cell 1 = balances.
SUPPLY_Q = ConservedFunctional(id="supply", weights={0: +1, 1: -1})


def test_conservation_unbacked_mint_fires():
    """Supply inflation (Cover-protocol-class): a reward mints balances[u] += amt but FORGETS
    totalSupply += amt. The op's q-projected delta is 0 − amt = −amt ≠ 0 — a value leak."""
    ops = [{"op": "reward", "deltas": {1: +1}, "edges": [0], "symbolic": True}]   # touches balance only
    obs = conservation_obstructions(ops, SUPPLY_Q)
    assert obs and obs[0]["op"] == "reward"
    assert obs[0]["drift"] != 0


def test_conservation_clean_mint_and_transfer_do_not_fire():
    """A correct mint touches BOTH cells with opposite q-sign (q-delta 0); a transfer nets 0 on
    the balance cell. Neither fires — intrinsically conservative bookkeeping stays silent."""
    clean_mint = {"op": "mint", "deltas": {0: +1, 1: +1}, "edges": [], "symbolic": True}
    transfer = {"op": "transfer", "deltas": {1: 0}, "edges": [], "symbolic": True}  # −amt then +amt
    assert conservation_obstructions([clean_mint, transfer], SUPPLY_Q) == []


def test_conservation_even_multiplicity_leak_fires_over_Z():
    """Even-multiplicity leak (the case GF(2) parity structurally MISSES): two unbacked mints,
    net +2 over Z but 0 mod 2. Summing signed deltas over Z catches it; no Smith form needed
    because q is linear, so the violation is localizable to the op."""
    ops = [{"op": "double_reward", "deltas": {1: +2}, "edges": [], "symbolic": True}]
    obs = conservation_obstructions(ops, SUPPLY_Q)
    assert obs and obs[0]["drift"] == -2          # q = +1*0 + (-1)*(+2)


def test_conservation_blindspot_when_no_functional_recognized():
    """No-silent-FN footing: when no conserved functional matches the accounting state, emit a
    blindspot finding rather than passing clean."""
    ops = [{"op": "weird_accounting", "deltas": {1: +1}, "edges": [], "symbolic": True}]
    obs = conservation_obstructions(ops, None)
    assert obs and obs[0]["leg"] == "blindspot"
