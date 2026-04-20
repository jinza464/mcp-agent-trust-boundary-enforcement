"""Tests for Tool Identity Registry behavior."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.core.models import ToolMetadata, ToolSnapshot, TrustLabel
from app.registry import ToolIdentityRegistry


def _build_snapshot(
    *,
    snapshot_id: str,
    tool_id: str = "tool.search",
    description: str = "Search public documents.",
    version: str = "1.0.0",
    source_uri: str = "https://mcp.example.org/server-a",
) -> ToolSnapshot:
    return ToolSnapshot(
        snapshot_id=snapshot_id,
        tool=ToolMetadata(
            tool_id=tool_id,
            name="Search Tool",
            version=version,
            provider="example-provider",
            description=description,
            source_uri=source_uri,
        ),
        captured_at=datetime(2026, 4, 20, 12, 0, 0, tzinfo=UTC),
        trust_label=TrustLabel.UNKNOWN,
    )


def test_first_registration_returns_new_status() -> None:
    registry = ToolIdentityRegistry()
    snapshot = _build_snapshot(snapshot_id="s-001")

    result = registry.register(snapshot, schema_payload={"type": "object", "properties": {}})

    assert result.status == "registered_new"
    assert result.is_new is True
    assert result.is_duplicate is False
    assert result.changed_fields == []
    assert result.previous_record is None
    assert registry.get_latest("tool.search") is not None


def test_repeated_registration_detects_duplicate() -> None:
    registry = ToolIdentityRegistry()
    schema_payload = {"type": "object", "properties": {"q": {"type": "string"}}}
    snapshot_a = _build_snapshot(snapshot_id="s-001")
    snapshot_b = _build_snapshot(snapshot_id="s-002")

    registry.register(snapshot_a, schema_payload=schema_payload)
    result = registry.register(snapshot_b, schema_payload=schema_payload)

    assert result.status == "registered_duplicate"
    assert result.is_new is False
    assert result.is_duplicate is True
    assert result.changed_fields == []


def test_re_registration_detects_all_identity_field_changes() -> None:
    registry = ToolIdentityRegistry()
    snapshot_a = _build_snapshot(snapshot_id="s-001", description="Search public documents.", version="1.0.0")
    snapshot_b = _build_snapshot(snapshot_id="s-002", description="Search private and public documents.", version="2.0.0")

    registry.register(
        snapshot_a,
        schema_payload={"type": "object", "properties": {"q": {"type": "string"}}},
        server_origin="https://mcp.example.org/server-a",
    )
    result = registry.register(
        snapshot_b,
        schema_payload={"type": "object", "properties": {"query": {"type": "string"}}},
        server_origin="https://mcp.example.org/server-b",
    )

    assert result.status == "registered_update"
    assert result.is_duplicate is False
    assert set(result.changed_fields) == {"description_hash", "schema_hash", "server_origin", "version"}


def test_save_and_load_json_roundtrip() -> None:
    registry = ToolIdentityRegistry()
    snapshot = _build_snapshot(snapshot_id="s-001")
    registry.register(snapshot, schema_payload={"type": "object"})

    test_data_dir = Path("data") / "test_outputs"
    test_data_dir.mkdir(parents=True, exist_ok=True)
    file_path = test_data_dir / f"registry-{uuid4().hex}.json"
    try:
        registry.save_to_json(file_path)

        loaded = ToolIdentityRegistry.load_from_json(file_path)
        latest = loaded.get_latest("tool.search")

        assert latest is not None
        assert latest.snapshot.snapshot_id == "s-001"
        assert latest.version == "1.0.0"
    finally:
        if file_path.exists():
            file_path.unlink()
