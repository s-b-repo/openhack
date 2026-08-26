import json, subprocess, sys, pathlib, pytest

FIX = pathlib.Path(__file__).parent / "fixtures" / "ts_sample"


@pytest.mark.integration
def test_cli_ingest_runs(tmp_path):
    db = str(tmp_path / "cli.sqlite3")
    subprocess.run(["recall", "init", "--db", db], check=True, capture_output=True)
    out = tmp_path / "hypernetwork.json"
    r = subprocess.run(
        [
            sys.executable, "-m", "lattice.cli.main", "ingest", str(FIX),
            "--lang", "ts", "--project", "lattice-cli-test",
            "--db", db, "--out", str(out),
        ],
        capture_output=True, text=True, cwd=str(pathlib.Path(FIX).parents[2]),
    )
    assert r.returncode == 0, r.stderr
    net = json.loads(out.read_text())
    assert net["stats"]["vertices"] >= 3
    report = json.loads((out.parent / "hypernetwork-report.json").read_text())
    assert report["verdict"] in ("pass", "partial")
