"""Pins the collision-leg cross-language proof: the SAME typed_h1 disagreement-sheaf that finds
Solidity proxy storage collisions finds C union type-confusion — one location, conflicting types."""
import pathlib
from lattice.ingest.c_unions import union_audit


def _audit(tmp_path, src):
    (tmp_path / "m.c").write_text(src)
    return {(f["kind"], f["union"]) for f in union_audit(tmp_path / "m.c")}


def test_incompatible_union_is_type_confusion(tmp_path):
    got = _audit(tmp_path, "union V { void* p; long n; };")
    assert ("type_confusion", "V") in got


def test_same_type_union_is_clean(tmp_path):
    assert _audit(tmp_path, "union S { int a; int b; };") == set()


def test_struct_distinct_offsets_no_collision(tmp_path):
    # fields at distinct offsets share no physical cell — must NOT collide
    assert _audit(tmp_path, "struct H { int magic; long size; char flag; };") == set()
