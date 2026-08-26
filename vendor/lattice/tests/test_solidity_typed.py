from lattice.ingest.solidity_typed import storage_cells, _width


def _var(name, type_name, node_type="ElementaryTypeName", mutability="mutable"):
    return {"nodeType": "VariableDeclaration", "name": name, "mutability": mutability,
            "typeName": {"nodeType": node_type, "name": type_name}}


def _contract(name, *vars):
    return {"nodeType": "ContractDefinition", "name": name, "nodes": list(vars)}


def test_width_of_elementary_types():
    assert _width({"nodeType": "ElementaryTypeName", "name": "address"}) == 20
    assert _width({"nodeType": "ElementaryTypeName", "name": "uint128"}) == 16
    assert _width({"nodeType": "ElementaryTypeName", "name": "uint256"}) == 32
    assert _width({"nodeType": "ElementaryTypeName", "name": "uint"}) == 32       # uint == uint256
    assert _width({"nodeType": "ElementaryTypeName", "name": "bool"}) == 1
    assert _width({"nodeType": "ElementaryTypeName", "name": "bytes32"}) == 32
    assert _width({"nodeType": "Mapping", "name": None}) is None                  # fresh full slot


def test_storage_cells_pack_like_the_evm():
    """The EVM storage packer over declaration order: address(20)+two uint128 pack, uint256 owns
    a slot, a mapping takes a fresh slot. This is the physical key the lift dedups on."""
    c = _contract("Probe",
                  _var("owner", "address"),
                  _var("a", "uint128"), _var("b", "uint128"),
                  _var("total", "uint256"),
                  _var("balances", None, node_type="Mapping"),
                  _var("flag", "bool"))
    cells = storage_cells(c)
    assert cells["owner"].physical == ("0", 0, 20)
    assert cells["a"].physical == ("1", 0, 16)
    assert cells["b"].physical == ("1", 16, 16)        # packs beside `a`
    assert cells["total"].physical == ("2", 0, 32)     # full word, own slot
    assert cells["balances"].physical == ("3", 0, 32)  # mapping = fresh slot
    assert cells["flag"].physical == ("4", 0, 1)
    assert cells["owner"].namespace == "Probe"


def test_storage_cells_flattens_inherited_storage():
    """CERT R8 (cardinal): the EVM lays INHERITED base-contract vars first. storage_cells must
    flatten the inheritance chain (base vars before derived) or every inheriting contract gets
    wrong slots — masking and inventing collisions."""
    base = _contract("Base", _var("owner", "address"), _var("baseVal", "uint256"))
    derived = {"nodeType": "ContractDefinition", "name": "Derived",
               "baseContracts": [{"baseName": {"name": "Base"}}],
               "nodes": [_var("derivedVal", "uint256")]}
    cells = storage_cells(derived, registry={"Base": base, "Derived": derived})
    assert cells["owner"].physical == ("0", 0, 20)        # inherited base vars come first
    assert cells["baseVal"].physical == ("1", 0, 32)
    assert cells["derivedVal"].physical == ("2", 0, 32)   # derived var after the base layout


def test_contract_typed_pointer_is_address_sized():
    """CERT FN: a contract/interface-typed storage pointer is a 20-byte ADDRESS, not a fresh
    32-byte slot — getting this wrong shifts every later slot and misses/misattributes collisions."""
    c = _contract("P",
                  _var("impl", "IFoo", node_type="UserDefinedTypeName"),
                  _var("flag", "bool"))
    cells = storage_cells(c, contract_types={"IFoo"})
    assert cells["impl"].physical == ("0", 0, 20)       # a 20-byte address, not a fresh 32-byte slot
    assert cells["flag"].physical == ("0", 20, 1)       # the bool packs beside the 20-byte pointer


def test_unknown_user_type_still_takes_a_fresh_slot():
    """A struct/enum/unknown UserDefinedType (not a known contract) keeps the conservative fresh-slot
    behavior — only contract/interface pointers are address-sized."""
    c = _contract("P", _var("data", "MyStruct", node_type="UserDefinedTypeName"), _var("n", "uint256"))
    cells = storage_cells(c, contract_types=set())
    assert cells["data"].physical == ("0", 0, 32)
    assert cells["n"].physical == ("1", 0, 32)


def test_constants_and_immutables_take_no_slot():
    c = _contract("C",
                  _var("K", "uint256", mutability="constant"),
                  _var("IMM", "address", mutability="immutable"),
                  _var("real", "uint256"))
    cells = storage_cells(c)
    assert "K" not in cells and "IMM" not in cells
    assert cells["real"].physical == ("0", 0, 32)      # the constant/immutable did not consume slot 0


def test_impl_version_distinguishes_layouts():
    """impl_version = a hash of the ordered layout. Inserting a variable (shifting every later
    slot) changes it — the signal the typed-collision leg uses to flag an unsafe upgrade."""
    v1 = storage_cells(_contract("V", _var("a", "address"), _var("b", "uint256")))
    # insert a FULL-WORD var: it can't pack, so it pushes `a` down a whole slot (the classic
    # upgrade-corruption case). (A bool would pack beside `a` in slot 0 — real EVM behavior.)
    v2 = storage_cells(_contract("V", _var("inserted", "uint256"), _var("a", "address"), _var("b", "uint256")))
    assert v1["a"].impl_version != v2["a"].impl_version   # layout changed -> impl_version changed
    assert v1["a"].physical == ("0", 0, 20)
    assert v2["a"].physical == ("1", 0, 20)               # `a` shifted off slot 0 by the insert
