"""Tool Identity Registry for local MCP tool snapshot management."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import ToolSnapshot


class ToolIdentityRecord(BaseModel):
    """Registry record binding a tool snapshot to comparable identity fingerprints."""

    model_config = ConfigDict(extra="forbid")

    snapshot: ToolSnapshot = Field(..., description="Captured tool snapshot.")
    description_hash: str = Field(..., description="SHA-256 hash of tool description.")
    schema_hash: str = Field(..., description="SHA-256 hash of tool input/output schema payload.")
    server_origin: str = Field(..., description="Canonical server origin for the tool provider.")
    version: str = Field(..., description="Tool version at registration time.")
    registered_at: datetime = Field(..., description="Registry insertion timestamp.")


class RegistrationResult(BaseModel):
    """Result returned by registry registration with explicit field-level diff information."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="One of: registered_new, registered_duplicate, registered_update.")
    tool_id: str = Field(..., description="Tool identifier associated with this registration.")
    is_new: bool = Field(..., description="Whether this is the first time the tool is registered.")
    is_duplicate: bool = Field(..., description="Whether the compared identity fields are identical.")
    changed_fields: list[str] = Field(
        default_factory=list,
        description="Changed identity fields among description_hash, schema_hash, server_origin, version.",
    )
    previous_record: ToolIdentityRecord | None = Field(
        default=None,
        description="Previous latest record for the tool, if it existed.",
    )
    current_record: ToolIdentityRecord = Field(..., description="Current registered record.")


class ToolIdentityRegistry:
    """Local in-memory registry with JSON persistence for MCP tool identity snapshots."""

    def __init__(self) -> None:
        """Initialize an empty identity registry indexed by tool_id."""
        self._records_by_tool_id: dict[str, list[ToolIdentityRecord]] = {}

    @staticmethod
    def _hash_payload(payload: Any) -> str:
        """Compute deterministic SHA-256 hash from a JSON-serializable payload."""
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def _build_record(
        cls,
        snapshot: ToolSnapshot,
        schema_payload: dict[str, Any] | None,
        server_origin: str | None,
    ) -> ToolIdentityRecord:
        """Build a record from snapshot and identity-related comparison inputs."""
        resolved_server_origin = server_origin or snapshot.tool.source_uri or "unknown"
        return ToolIdentityRecord(
            snapshot=snapshot,
            description_hash=cls._hash_payload(snapshot.tool.description),
            schema_hash=cls._hash_payload(schema_payload or {}),
            server_origin=resolved_server_origin,
            version=snapshot.tool.version,
            registered_at=datetime.now(UTC),
        )

    @staticmethod
    def _diff_identity_fields(previous: ToolIdentityRecord, current: ToolIdentityRecord) -> list[str]:
        """Return changed field names across the identity comparison boundary."""
        changed_fields: list[str] = []
        if previous.description_hash != current.description_hash:
            changed_fields.append("description_hash")
        if previous.schema_hash != current.schema_hash:
            changed_fields.append("schema_hash")
        if previous.server_origin != current.server_origin:
            changed_fields.append("server_origin")
        if previous.version != current.version:
            changed_fields.append("version")
        return changed_fields

    def register(
        self,
        snapshot: ToolSnapshot,
        schema_payload: dict[str, Any] | None = None,
        server_origin: str | None = None,
    ) -> RegistrationResult:
        """Register a snapshot and return new/duplicate/update status with identity diffs."""
        tool_id = snapshot.tool.tool_id
        current_record = self._build_record(snapshot, schema_payload, server_origin)
        history = self._records_by_tool_id.setdefault(tool_id, [])

        if not history:
            history.append(current_record)
            return RegistrationResult(
                status="registered_new",
                tool_id=tool_id,
                is_new=True,
                is_duplicate=False,
                changed_fields=[],
                previous_record=None,
                current_record=current_record,
            )

        previous_record = history[-1]
        changed_fields = self._diff_identity_fields(previous_record, current_record)
        history.append(current_record)

        is_duplicate = not changed_fields
        return RegistrationResult(
            status="registered_duplicate" if is_duplicate else "registered_update",
            tool_id=tool_id,
            is_new=False,
            is_duplicate=is_duplicate,
            changed_fields=changed_fields,
            previous_record=previous_record,
            current_record=current_record,
        )

    def get_latest(self, tool_id: str) -> ToolIdentityRecord | None:
        """Get latest record for a tool, or None when not registered."""
        history = self._records_by_tool_id.get(tool_id)
        return history[-1] if history else None

    def get_history(self, tool_id: str) -> list[ToolIdentityRecord]:
        """Get full registration history for a tool."""
        return list(self._records_by_tool_id.get(tool_id, []))

    def save_to_json(self, file_path: str | Path) -> Path:
        """Persist the entire registry state into a local JSON file."""
        path = Path(file_path)
        data = {
            "records_by_tool_id": {
                tool_id: [record.model_dump(mode="json") for record in records]
                for tool_id, records in self._records_by_tool_id.items()
            }
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    @classmethod
    def load_from_json(cls, file_path: str | Path) -> ToolIdentityRegistry:
        """Load registry state from a local JSON file."""
        path = Path(file_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        registry = cls()
        for tool_id, raw_records in data.get("records_by_tool_id", {}).items():
            registry._records_by_tool_id[tool_id] = [
                ToolIdentityRecord.model_validate(raw_record) for raw_record in raw_records
            ]
        return registry
