from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "ok"


def test_list_tools() -> None:
    response = client.get("/api/v1/tools")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert "items" in payload["data"]
    assert isinstance(payload["data"]["items"], list)


def test_runtime_execute() -> None:
    response = client.post(
        "/api/v1/runtime/execute",
        json={
            "user_query": "please search docs",
            "preferred_tool_name": "docs_search",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert "final_status" in payload["data"]
    assert "decision_action" in payload["data"]


def test_evaluation_run() -> None:
    response = client.post(
        "/api/v1/evaluation/run",
        json={
            "ablation_name": "baseline",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["ablation_name"] == "baseline"
    assert "summary" in payload["data"]
    assert "exported_paths" in payload["data"]
