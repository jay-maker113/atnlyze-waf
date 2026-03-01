"""
tests/integration/test_api.py

Integration tests for the AtnLyze WAF FastAPI endpoints.

IMPORTANT — lifespan handling:
    TestClient(app) at module level does NOT trigger the lifespan context manager.
    Models are initialized in lifespan, so a bare module-level client leaves
    baseline_engine and transformer_engine as None — every predict call crashes.

    Fix: use a pytest fixture that wraps TestClient in a `with` block.
    The `with` block starts the lifespan on enter and stops it on exit,
    exactly as a real server startup/shutdown would.
"""

import pytest
from fastapi.testclient import TestClient
from atnlyze.api.app import app


BENIGN_LOG = '127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] "GET /login?user=admin HTTP/1.1" 200 612 "-" "Mozilla/5.0"'
MALICIOUS_LOG = "127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] \"GET /webgoat/SqlInjection/attack?username=admin'-- HTTP/1.1\" 404 683 \"-\" \"python-requests/2.32.5\""
UNPARSEABLE_LOG = "this is not a valid nginx log line at all"


@pytest.fixture(scope="module")
def client():
    """
    Module-scoped fixture. The `with` block triggers app lifespan —
    models load on enter, unload on exit. Shared across all tests in
    this module to avoid reloading the transformer model for every test.
    """
    with TestClient(app) as c:
        yield c


# ── Health ────────────────────────────────────────────────────────────────────

def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


# ── Baseline engine ───────────────────────────────────────────────────────────

def test_predict_baseline_response_structure(client):
    """Baseline engine returns nested under 'baseline' key."""
    res = client.post("/predict?engine=baseline", json={"log_line": BENIGN_LOG})
    assert res.status_code == 200
    data = res.json()

    assert "baseline" in data
    assert "transformer" not in data  # only baseline requested

    result = data["baseline"]
    assert "label" in result
    assert "score" in result
    assert "decision" in result

    assert result["label"] in ("benign", "malicious")
    assert result["decision"] in ("allow", "block")
    assert isinstance(result["score"], float)
    assert 0.0 <= result["score"] <= 1.0


def test_predict_baseline_label_decision_consistency(client):
    """label and decision must agree — malicious→block, benign→allow."""
    res = client.post("/predict?engine=baseline", json={"log_line": BENIGN_LOG})
    result = res.json()["baseline"]

    if result["label"] == "malicious":
        assert result["decision"] == "block"
    else:
        assert result["decision"] == "allow"


# ── Transformer engine ────────────────────────────────────────────────────────

def test_predict_transformer_response_structure(client):
    """Transformer engine returns nested under 'transformer' key."""
    res = client.post("/predict?engine=transformer", json={"log_line": BENIGN_LOG})
    assert res.status_code == 200
    data = res.json()

    assert "transformer" in data
    assert "baseline" not in data  # only transformer requested

    result = data["transformer"]
    assert "label" in result
    assert "score" in result
    assert "decision" in result
    assert "model" in result
    assert result["model"] in ("transformer", "transformer_onnx")

    assert result["label"] in ("benign", "malicious")
    assert result["decision"] in ("allow", "block")
    assert isinstance(result["score"], float)
    assert 0.0 <= result["score"] <= 1.0


def test_predict_transformer_label_decision_consistency(client):
    res = client.post("/predict?engine=transformer", json={"log_line": BENIGN_LOG})
    result = res.json()["transformer"]

    if result["label"] == "malicious":
        assert result["decision"] == "block"
    else:
        assert result["decision"] == "allow"


# ── Both engines ──────────────────────────────────────────────────────────────

def test_predict_both_engines_response_structure(client):
    """Both engines requested — both keys must be present."""
    res = client.post("/predict?engine=both", json={"log_line": BENIGN_LOG})
    assert res.status_code == 200
    data = res.json()

    assert "baseline" in data
    assert "transformer" in data

    for engine_key in ("baseline", "transformer"):
        result = data[engine_key]
        assert "label" in result
        assert "score" in result
        assert "decision" in result


# ── Default engine ────────────────────────────────────────────────────────────

def test_predict_default_engine_is_baseline(client):
    """Calling /predict with no engine param defaults to baseline."""
    res = client.post("/predict", json={"log_line": BENIGN_LOG})
    assert res.status_code == 200
    data = res.json()

    assert "baseline" in data
    assert "transformer" not in data


# ── Invalid engine param ──────────────────────────────────────────────────────

def test_predict_invalid_engine_returns_422(client):
    """
    Unknown engine value must be rejected with 422.
    This works because engine is typed as Literal["baseline", "transformer", "both"]
    in app.py — Pydantic enforces this at runtime and returns 422 on unknown values.
    If app.py used bare str + Query(enum=[...]), this would silently return 200.
    """
    res = client.post("/predict?engine=unknown", json={"log_line": BENIGN_LOG})
    assert res.status_code == 422


# ── Empty / missing body ──────────────────────────────────────────────────────

def test_predict_missing_body_returns_422(client):
    res = client.post("/predict?engine=baseline", json={})
    assert res.status_code == 422


def test_predict_empty_log_line_does_not_crash(client):
    """Empty string should not raise a 500 — model falls back gracefully."""
    res = client.post("/predict?engine=both", json={"log_line": ""})
    assert res.status_code == 200


# ── Unparseable log line ──────────────────────────────────────────────────────

def test_predict_unparseable_log_falls_back_gracefully(client):
    """If parse_log_line() returns None, app falls back to raw text — no 500."""
    res = client.post("/predict?engine=both", json={"log_line": UNPARSEABLE_LOG})
    assert res.status_code == 200
    data = res.json()
    assert "baseline" in data
    assert "transformer" in data


# ── Known malicious sample ────────────────────────────────────────────────────

def test_predict_known_malicious_sample_transformer(client):
    """
    This is the one attack pattern the transformer was trained on.
    After the app.py skew fix, structured text is built correctly at inference.
    Transformer should block this with high confidence.
    NOTE: This test will need revisiting after retraining on expanded dataset.
    """
    res = client.post("/predict?engine=transformer", json={"log_line": MALICIOUS_LOG})
    assert res.status_code == 200
    result = res.json()["transformer"]

    assert result["label"] == "malicious"
    assert result["decision"] == "block"
    assert result["score"] >= 0.8  # high confidence on trained pattern
