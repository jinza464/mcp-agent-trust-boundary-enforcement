"""Reliability tests for the buffered audit service."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.audit_service import AuditService


def _jsonl_path(root: Path) -> Path:
    return root / "audit_events.jsonl"


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_write_event_buffers_events_before_threshold(tmp_path: Path) -> None:
    service = AuditService(root=tmp_path, flush_threshold=3)

    first_path = service.write_event("event_one", {"case_id": "c1"})
    second_path = service.write_event("event_two", {"case_id": "c2"})

    assert first_path == _jsonl_path(tmp_path)
    assert second_path == _jsonl_path(tmp_path)
    assert len(service._buffer) == 2
    assert not _jsonl_path(tmp_path).exists()


def test_threshold_flush_writes_jsonl_and_clears_buffer(tmp_path: Path) -> None:
    service = AuditService(root=tmp_path, flush_threshold=2)

    service.write_event("event_one", {"case_id": "c1"})
    service.write_event("event_two", {"case_id": "c2"})

    assert service._buffer == []
    path = _jsonl_path(tmp_path)
    assert path.exists()
    rows = _read_jsonl(path)
    assert len(rows) == 2
    for row in rows:
        assert row["event_id"]
        assert row["event_type"]
        assert row["created_at"]
        assert isinstance(row["payload"], dict)


def test_manual_flush_writes_buffered_events(tmp_path: Path) -> None:
    service = AuditService(root=tmp_path, flush_threshold=10)
    service.write_event("event_one", {"case_id": "c1"})
    service.write_event("event_two", {"case_id": "c2"})

    result = service.flush()

    assert result["written_events"] == 2
    assert result["file_path"] == str(_jsonl_path(tmp_path))
    assert service._buffer == []
    assert len(_read_jsonl(_jsonl_path(tmp_path))) == 2


def test_flush_failure_keeps_buffer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = AuditService(root=tmp_path, flush_threshold=10)
    service.write_event("event_one", {"case_id": "c1"})

    def broken_flush_batch(batch: list[object]) -> int:
        raise OSError("disk full")

    monkeypatch.setattr(service, "_flush_batch", broken_flush_batch)

    with pytest.raises(OSError, match="disk full"):
        service.flush()

    assert len(service._buffer) == 1
    assert service._closed is False
    assert not _jsonl_path(tmp_path).exists()


def test_close_flushes_and_marks_closed(tmp_path: Path) -> None:
    service = AuditService(root=tmp_path, flush_threshold=10)
    service.write_event("event_one", {"case_id": "c1"})

    result = service.close()
    second_result = service.close()

    assert result["written_events"] == 1
    assert result["closed"] is True
    assert second_result["closed"] is True
    assert second_result["written_events"] == 0
    assert service._buffer == []
    assert len(_read_jsonl(_jsonl_path(tmp_path))) == 1
    with pytest.raises(RuntimeError, match="closed"):
        service.write_event("event_after_close", {"case_id": "c2"})


def test_close_does_not_mark_closed_when_flush_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = AuditService(root=tmp_path, flush_threshold=10)
    service.write_event("event_one", {"case_id": "c1"})

    def broken_flush_batch(batch: list[object]) -> int:
        raise OSError("disk full")

    monkeypatch.setattr(service, "_flush_batch", broken_flush_batch)

    with pytest.raises(OSError, match="disk full"):
        service.close()

    assert service._closed is False
    assert len(service._buffer) == 1
    assert not _jsonl_path(tmp_path).exists()
