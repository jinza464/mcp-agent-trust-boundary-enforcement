"""Local tool identity registry for MCP metadata snapshots."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import ToolMetadata, ToolSnapshot, TrustLabel


class ChangeDetectionResult(BaseModel):
    """Structured field-level diff result across trust-boundary identity fields."""

    model_config = ConfigDict(extra="forbid")

    changed: bool = Field(..., description="Whether any tracked identity field changed.")
    changed_fields: list[str] = Field(
        default_factory=list,
        description="Changed fields among description_hash, schema_hash, server_origin, version.",
    )
    old_values: dict[str, str] = Field(default_factory=dict, description="Previous values by identity field.")
    new_values: dict[str, str] = Field(default_factory=dict, description="New values by identity field.")


class RegisterToolResult(BaseModel):
    """Structured registration outcome for first registration, duplicate, or update."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="One of: registered_new, registered_duplicate, registered_update.")
    tool_name: str = Field(..., description="Tool name.")
    server_origin: str = Field(..., description="Server origin used for namespacing.")
    snapshot: ToolSnapshot = Field(..., description="Persisted snapshot after registration.")
    change_result: ChangeDetectionResult | None = Field(
        default=None,
        description="Diff result against previous snapshot when available.",
    )


class ToolRegistry:
    """In-memory registry with JSON persistence keyed by (tool_name, server_origin)."""

    def __init__(self) -> None:
        """Create an empty registry."""
        self._snapshots_by_key: dict[str, list[ToolSnapshot]] = {}

    @staticmethod
    def _hash_payload(payload: Any) -> str:
        """Return deterministic SHA-256 hash for a JSON-serializable payload."""
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_server_origin(metadata: ToolMetadata) -> str:
        """Resolve canonical server origin from tool metadata."""
        return metadata.source_uri or "unknown"

    @classmethod
    def _compute_description_hash(cls, metadata: ToolMetadata) -> str:
        """Compute description hash from the metadata description field."""
        return cls._hash_payload(metadata.description)

    @classmethod
    def _compute_schema_hash(cls, metadata: ToolMetadata) -> str:
        """Compute schema hash from schema-like metadata signals available in the prototype.

        Notes:
            The current core model does not carry raw JSON schema. We hash stable
            interface-like hints (`capabilities`, `tags`) as a practical proxy.
        """
        schema_like_payload = {
            "capabilities": sorted(cap.value for cap in metadata.capabilities),
            "tags": sorted(metadata.tags),
        }
        return cls._hash_payload(schema_like_payload)

    @classmethod
    def _make_identity_context(cls, metadata: ToolMetadata) -> dict[str, str]:
        """Build the identity context persisted in snapshot runtime metadata."""
        return {
            "description_hash": cls._compute_description_hash(metadata),
            "schema_hash": cls._compute_schema_hash(metadata),
            "server_origin": cls._normalize_server_origin(metadata),
            "version": metadata.version,
        }

    @staticmethod
    def _registry_key(tool_name: str, server_origin: str) -> str:
        """Build a stable string key for internal dictionary storage."""
        return f"{tool_name}::{server_origin}"

    def _build_snapshot(self, metadata: ToolMetadata) -> ToolSnapshot:
        """Create a new ToolSnapshot from ToolMetadata."""
        identity_context = self._make_identity_context(metadata)
        return ToolSnapshot(
            snapshot_id=f"snap-{uuid4().hex}",
            tool=metadata,
            captured_at=datetime.now(UTC),
            trust_label=TrustLabel.UNKNOWN,
            runtime_context=identity_context,
        )

    def register_tool(self, metadata: ToolMetadata) -> RegisterToolResult:
        """Register a tool metadata snapshot and return structured status."""
        server_origin = self._normalize_server_origin(metadata)
        key = self._registry_key(metadata.name, server_origin)
        new_snapshot = self._build_snapshot(metadata)
        history = self._snapshots_by_key.setdefault(key, [])

        if not history:
            history.append(new_snapshot)
            return RegisterToolResult(
                status="registered_new",
                tool_name=metadata.name,
                server_origin=server_origin,
                snapshot=new_snapshot,
                change_result=None,
            )

        old_snapshot = history[-1]
        change_result = self.detect_changes(old_snapshot, metadata)
        history.append(new_snapshot)
        return RegisterToolResult(
            status="registered_update" if change_result.changed else "registered_duplicate",
            tool_name=metadata.name,
            server_origin=server_origin,
            snapshot=new_snapshot,
            change_result=change_result,
        )

    def get_tool_snapshot(self, tool_name: str, server_origin: str) -> ToolSnapshot | None:
        """Return latest snapshot for a tool name on a given server origin."""
        key = self._registry_key(tool_name, server_origin)
        history = self._snapshots_by_key.get(key, [])
        return history[-1] if history else None

    def detect_changes(self, old_snapshot: ToolSnapshot, new_metadata: ToolMetadata) -> ChangeDetectionResult:
        """Compare identity fields between an old snapshot and new metadata."""
        old_values = {
            "description_hash": str(
                old_snapshot.runtime_context.get("description_hash", self._compute_description_hash(old_snapshot.tool))
            ),
            "schema_hash": str(old_snapshot.runtime_context.get("schema_hash", self._compute_schema_hash(old_snapshot.tool))),
            "server_origin": str(
                old_snapshot.runtime_context.get("server_origin", self._normalize_server_origin(old_snapshot.tool))
            ),
            "version": str(old_snapshot.runtime_context.get("version", old_snapshot.tool.version)),
        }
        new_values = self._make_identity_context(new_metadata)

        changed_fields = [field_name for field_name in old_values if old_values[field_name] != new_values[field_name]]
        return ChangeDetectionResult(
            changed=bool(changed_fields),
            changed_fields=changed_fields,
            old_values=old_values,
            new_values=new_values,
        )

    def save_to_json(self, file_path: str | Path) -> Path:
        """Persist registry snapshots to a local JSON file."""
        path = Path(file_path)
        data = {
            "snapshots_by_key": {
                key: [snapshot.model_dump(mode="json") for snapshot in snapshots]
                for key, snapshots in self._snapshots_by_key.items()
            }
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

