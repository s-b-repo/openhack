from lattice.ingest.iac import iac_ingest


def test_dockerfile_stages_base_image_and_internal_from(tmp_path):
    """Dockerfile = the deployment boundary: build stages -> symbols, a base image
    (FROM node:18) -> an OUTBOUND dependency (supply chain), and a multi-stage
    `FROM build` -> an internal edge between stages."""
    (tmp_path / "Dockerfile").write_text(
        "FROM node:18 AS build\n"
        "RUN npm ci && npm run build\n"
        "FROM build AS final\n"
        "EXPOSE 8080\n"
        "USER root\n")
    raw = iac_ingest(tmp_path)
    names = {s.name for s in raw.symbols}
    assert {"build", "final"} <= names, names
    assert any(r.to_file is None and not r.resolved for r in raw.references), \
        "base image not modeled as outbound dependency"
    assert any(r.resolved for r in raw.references), "final->build stage edge missing"
