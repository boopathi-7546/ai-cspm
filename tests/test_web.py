import io
import json

import pytest

from cspm import pipeline
from cspm.config import CONFIG_DIR
from web.app import create_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "EXTRACTED_JSON", tmp_path / "cti.json")
    return create_app(tmp_path / "web.db").test_client()


def upload(client, name, data):
    return client.post("/api/scan", data={"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")


def test_index_and_static_served_with_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and b"AI-CSPM" in r.data
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/static/../app.py").status_code == 404  # no path traversal


def test_empty_state(client):
    assert client.get("/api/runs").get_json() == []
    assert client.get("/api/runs/nope").status_code == 404


def test_demo_scan_then_read_back(client):
    r = client.post("/api/scan/demo")
    runs = r.get_json()["runs"]
    assert set(runs) == {"vulnerable_env", "secure_env", "ambiguous_env"}
    assert len(client.get("/api/runs").get_json()) == 3
    d = client.get(f"/api/runs/{runs['vulnerable_env']}").get_json()
    assert d["summary"]["total"] == 24 and d["summary"]["total_reports"] == 8
    assert sum(d["summary"]["by_priority"].values()) == 24
    assert [f["fused_rank"] for f in d["findings"]] == list(range(1, 25))
    assert client.get(f"/api/runs/{runs['secure_env']}").get_json()["findings"] == []
    assert client.get("/api/cti").get_json()


def test_upload_json_scan(client):
    data = (CONFIG_DIR / "vulnerable_env.json").read_bytes()
    r = upload(client, "my env!.json", data)
    assert r.status_code == 200 and r.get_json()["findings"] == 24
    run = client.get("/api/runs").get_json()[0]
    assert run["config_name"] == "my_env_"  # filename sanitised


def test_upload_yaml_scan(client):
    r = upload(client, "c.yaml", b"s3_buckets:\n  - name: b\n    public_read: true\n    criticality: high\n")
    assert r.status_code == 200 and r.get_json()["findings"] == 1


def test_upload_rejections(client):
    assert client.post("/api/scan").status_code == 400
    assert upload(client, "x.txt", b"{}").status_code == 400
    assert upload(client, "x.json", b"not json").status_code == 400
    assert upload(client, "x.json", b"[1,2]").status_code == 400
    assert upload(client, "x.json", b'{"hello": 1}').status_code == 400
    assert upload(client, "x.json", b"\xff\xfe\x00").status_code == 400
    bad = json.dumps({"s3_buckets": [{"public_read": True}]}).encode()  # missing name
    assert upload(client, "x.json", bad).status_code == 400
    assert upload(client, "x.yaml", b"!!python/object/apply:os.system ['echo hi']").status_code == 400  # safe_load only
    assert upload(client, "big.json", b" " * 1_100_000).status_code == 413
    assert client.get("/api/runs").get_json() == []  # nothing saved from rejected uploads


def test_hostile_resource_names_stay_data(client):
    cfg = {"s3_buckets": [{"name": "<img src=x onerror=alert(1)>", "public_read": True}]}
    assert upload(client, "h.json", json.dumps(cfg).encode()).status_code == 200
    rid = client.get("/api/runs").get_json()[0]["run_id"]
    r = client.get(f"/api/runs/{rid}")
    assert r.mimetype == "application/json"
    assert r.get_json()["findings"][0]["resource"] == "<img src=x onerror=alert(1)>"


def test_evaluation_endpoint(client):
    r = client.get("/api/evaluation").get_json()
    assert r["detection"]["overall"]["recall"] == 1.0 and "note" in r
