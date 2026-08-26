import json

from lattice.exchange_status import SCHEMA_VERSION, build_exchange_status
from lattice.graph.models import Hyperedge, Hypernetwork, Surface, Vertex


PUB = "ts-sym:a.ts#pub"
HELPER = "ts-sym:a.ts#helper"


def _net() -> Hypernetwork:
    return Hypernetwork(
        language="typescript",
        root="/repo",
        vertices=[
            Vertex(
                id=PUB,
                kind="function",
                name="pub",
                file="a.ts",
                start_line=1,
                end_line=4,
                exported=True,
            ),
            Vertex(
                id=HELPER,
                kind="function",
                name="helper",
                file="a.ts",
                start_line=5,
                end_line=8,
            ),
        ],
        hyperedges=[
            Hyperedge(id="e1", kind="references", members=[PUB, HELPER], resolved=True),
        ],
        surfaces=[
            Surface(id="s-public", vertex_id=PUB, kind="public_api"),
            Surface(id="s-entry", vertex_id=PUB, kind="entrypoint"),
        ],
    )


def test_exchange_status_is_authority_neutral():
    payload = build_exchange_status(_net(), observed_at="2026-06-08T14:45:00.000Z")

    assert payload["schema"] == SCHEMA_VERSION
    assert payload["language"] == "typescript"
    assert payload["graph"]["vertices"] == 2
    assert payload["graph"]["hyperedges"] == 1
    assert payload["surface_inventory"]["surface_count"] == 2
    assert payload["surface_inventory"]["control_authority_count"] == 0
    assert payload["surface_inventory"]["write_surface_count"] == 0
    assert payload["authority"]["control_authority"] is False
    assert payload["authority"]["writes"] == []
    surfaces = payload["surface_inventory"]["surfaces"]
    assert all(surface["observer_only"] is True for surface in surfaces)
    assert all(surface["control_authority"] is False for surface in surfaces)
    assert all(surface["writes"] == [] for surface in surfaces)
    assert {surface["surface_kind"] for surface in surfaces} == {"entrypoint", "public_api"}


def test_cli_exchange_status_outputs_json(tmp_path, monkeypatch, capsys):
    from lattice.cli import main as cli

    monkeypatch.setattr(cli, "load_network", lambda path, language="auto": (_net(), tmp_path))
    out = tmp_path / "exchange-status.json"

    rc = cli.main(["exchange-status", str(tmp_path), "--out", str(out), "--pretty"])

    assert rc == 0
    stdout_payload = json.loads(capsys.readouterr().out)
    file_payload = json.loads(out.read_text())
    assert stdout_payload["schema"] == SCHEMA_VERSION
    assert file_payload["schema"] == SCHEMA_VERSION
    assert file_payload["surface_inventory"]["control_authority_count"] == 0
