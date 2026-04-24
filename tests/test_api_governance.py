from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from main import app

client = TestClient(app)


def test_invalid_runtime_request_returns_error_envelope() -> None:
    response = client.post("/api/v1/runtime/execute", json={})
    assert response.status_code == 422
    payload = response.json()
    assert payload["ok"] is False
    assert payload["error"]["code"] == "request_validation_error"


def test_success_responses_include_request_id_and_timestamp() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload.get("request_id"), str) and payload["request_id"]
    assert isinstance(payload.get("timestamp"), str) and payload["timestamp"]
