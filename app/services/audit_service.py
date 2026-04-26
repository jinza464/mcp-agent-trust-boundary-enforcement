from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from app.config.settings import settings


class AuditEvent(BaseModel):
    """Normalized audit event record persisted as one JSONL line."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    event_type: str
    created_at: datetime
    payload: dict[str, object]
    source: str | None = None
    request_id: str | None = None
    metadata: dict[str, object] | None = None


class AuditService:
    """Lightweight buffered audit writer for research platform artifacts."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        flush_threshold: int = 20,
        jsonl_filename: str = "audit_events.jsonl",
    ) -> None:
        self.root = root or (settings.default_output_root / "audit")
        self.root.mkdir(parents=True, exist_ok=True)
        self._jsonl_path = self.root / jsonl_filename
        self._flush_threshold = max(1, int(flush_threshold))
        self._buffer: list[AuditEvent] = []
        self._closed = False

    def _normalize_event(
        self,
        event_type: str,
        payload: dict[str, object],
        *,
        source: str | None = None,
        request_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=uuid4().hex,
            event_type=event_type,
            created_at=datetime.now(UTC),
            payload=dict(payload),
            source=source,
            request_id=request_id,
            metadata=dict(metadata) if metadata is not None else None,
        )

    @staticmethod
    def _event_to_jsonl_line(event: AuditEvent) -> str:
        return json.dumps(event.model_dump(mode="json"), ensure_ascii=False)

    def _flush_batch(self, batch: list[AuditEvent]) -> int:
        if not batch:
            return 0
        lines = [self._event_to_jsonl_line(event) for event in batch]
        with self._jsonl_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines))
            handle.write("\n")
        return len(batch)

    def write_event(
        self,
        event_type: str,
        payload: dict[str, object],
        *,
        source: str | None = None,
        request_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> Path:
        if self._closed:
            raise RuntimeError("AuditService is closed and cannot accept new events.")
        event = self._normalize_event(
            event_type,
            payload,
            source=source,
            request_id=request_id,
            metadata=metadata,
        )
        self._buffer.append(event)
        if len(self._buffer) >= self._flush_threshold:
            self.flush()
        # Keep compatibility with existing callers that expect a path-like return.
        return self._jsonl_path

    def flush(self) -> dict[str, object]:
        if not self._buffer:
            return {"file_path": str(self._jsonl_path), "written_events": 0}
        batch = list(self._buffer)
        written = self._flush_batch(batch)
        del self._buffer[: len(batch)]
        return {"file_path": str(self._jsonl_path), "written_events": written}

    def close(self) -> dict[str, object]:
        if self._closed:
            return {"file_path": str(self._jsonl_path), "written_events": 0, "closed": True}
        flush_result = self.flush()
        self._closed = True
        flush_result["closed"] = True
        return flush_result
