from fastapi.testclient import TestClient
from atnlyze.api.app import app

client = TestClient(app)


def test_health():
    res = client.get("/health")
    assert res.status_code == 200


def test_predict_endpoint():
    sample_log = '127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] "GET /login?user=admin HTTP/1.1" 200 612 "-" "Mozilla/5.0"'

    res = client.post("/predict", json={"log_line": sample_log})
    assert res.status_code == 200
    data = res.json()

    assert "label" in data
    assert "score" in data
    assert "decision" in data
