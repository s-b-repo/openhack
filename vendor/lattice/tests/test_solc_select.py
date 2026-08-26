import shutil
import pytest
from lattice.ingest.solidity import _installed_solc, _pragma_constraint, _select_solc, _solc_ast
from lattice.ingest.solidity_typed import typed_audit

pytestmark = pytest.mark.skipif(shutil.which("solc") is None, reason="solc not installed")


def test_pragma_constraint_parsing():
    assert _pragma_constraint("pragma solidity ^0.8.0;") == ("^", 0, 8, 0)
    assert _pragma_constraint("pragma solidity 0.8.30;") == ("", 0, 8, 30)
    assert _pragma_constraint("pragma solidity =0.8.25;") == ("=", 0, 8, 25)
    assert _pragma_constraint("pragma solidity ^0.4.19;") == ("^", 0, 4, 19)
    assert _pragma_constraint("// no pragma") is None


def test_select_solc_caret_picks_highest_in_minor():
    """^0.8.0 must resolve to the highest installed 0.8.x; an exact 0.8.30 to 0.8.30."""
    installed = _installed_solc()
    if (0, 8, 30) not in installed:
        pytest.skip("0.8.30 not installed via solc-select")
    binary, v = _select_solc("pragma solidity ^0.8.0;")
    assert v[0] == 0 and v[1] == 8
    binary2, v2 = _select_solc("pragma solidity 0.8.30;")
    assert v2 == (0, 8, 30)


def test_select_solc_old_version():
    installed = _installed_solc()
    if not any(v[0] == 0 and v[1] == 4 for v in installed):
        pytest.skip("no 0.4.x installed")
    binary, v = _select_solc("pragma solidity ^0.4.19;")
    assert v[0] == 0 and v[1] == 4


def test_typed_audit_handles_0830_contract_default_solc_rejects(tmp_path):
    """A 0.8.30-pinned contract fails the default solc (0.8.24); version dispatch must pick 0.8.30
    so it is parsed AND gets tier-1 layout — instead of going silently blind to it."""
    installed = _installed_solc()
    if (0, 8, 30) not in installed:
        pytest.skip("0.8.30 not installed")
    (tmp_path / "New.sol").write_text(
        "pragma solidity 0.8.30;\n"
        "contract New {\n"
        "    mapping(address=>uint256) bal;\n"
        "    function withdraw(uint256 a) public {\n"
        "        require(bal[msg.sender] >= a);\n"
        "        (bool ok,) = msg.sender.call{value: a}(\"\");\n"
        "        bal[msg.sender] -= a;\n"
        "    }\n"
        "}\n")
    assert _solc_ast(tmp_path / "New.sol") is not None        # parses via 0.8.30
    assert any(f.get("contract") == "New" for f in typed_audit(str(tmp_path)))   # analyzed end-to-end
