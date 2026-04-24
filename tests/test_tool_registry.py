"""Tests for strict tool identity registry behavior."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from app.core.models import CapabilityType, RiskLevel, ToolMetadata, TrustLabel
from app.mcp.protocol_models import RequestLineage
from app.registry.tool_registry import ToolRegistry


def _build_metadata(
    *,
    tool_id: str = "tool.search",
    tool_identity: str | None = None,
    name: str = "search",
    source_uri: str = "https://server-a.mcp.local",
    namespace: str | None = "provider-a",
    provider: str = "provider-a",
    provider_identity: str | None = None,
    description: str = "Search documents.",
    version: str = "1.0.0",
    capabilities: set[CapabilityType] | None = None,
    input_schema: dict[str, object] | None = None,
    output_schema: dict[str, object] | None = None,
    tags: list[str] | None = None,
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        tool_identity=tool_identity,
        name=name,
        namespace=namespace,
        version=version,
        provider=provider,
        provider_identity=provider_identity,
        description=description,
        capabilities=capabilities or {CapabilityType.READ},
        source_uri=source_uri,
        input_schema=input_schema,
        output_schema=output_schema,
        tags=tags or [],
    )


def test_same_name_same_origin_duplicate_observation() -> None:
    registry = ToolRegistry()
    metadata = _build_metadata()

    first = registry.register_tool(metadata)
    result = registry.register_tool(metadata)

    track = registry.get_identity_track(metadata.tool_id, metadata.source_uri)
    assert track is not None
    assert first.first_seen_at == first.last_seen_at
    assert result.status == "registered_duplicate"
    assert result.observation_kind == "duplicate_observation"
    assert result.is_duplicate is True
    assert result.observation_count == 2
    assert track.observation_count == 2
    assert track.drift_history_summary["duplicate_observation_count"] == 1
    assert track.drift_history_summary["last_observation_kind"] == "duplicate_observation"


def test_same_name_different_origin_shadowing_detection() -> None:
    registry = ToolRegistry()
    old = _build_metadata(name="search", source_uri="https://server-a.mcp.local")
    registry.register_tool(old)
    old_snapshot = registry.get_tool_snapshot("search", "https://server-a.mcp.local")
    assert old_snapshot is not None

    new = _build_metadata(name="search", source_uri="https://server-b.mcp.local")
    diff = registry.detect_changes(old_snapshot, new)

    assert diff.changed is True
    assert "server_relocation" in diff.change_categories
    assert diff.severity in {RiskLevel.HIGH, RiskLevel.CRITICAL}


def test_same_origin_schema_drift_detection() -> None:
    registry = ToolRegistry()
    old = _build_metadata(
        input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
        output_schema={"type": "object", "properties": {"items": {"type": "array"}}},
    )
    registry.register_tool(old)
    old_snapshot = registry.get_tool_snapshot("search", "https://server-a.mcp.local")
    assert old_snapshot is not None

    new = _build_metadata(
        input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        output_schema={"type": "object", "properties": {"results": {"type": "array"}}},
    )
    diff = registry.detect_changes(old_snapshot, new)

    assert diff.changed is True
    assert "schema_change" in diff.change_categories
    assert "schema_hash" in diff.changed_fields


def test_rollback_detection() -> None:
    registry = ToolRegistry()
    old = _build_metadata(version="2.0.0")
    registry.register_tool(old)
    old_snapshot = registry.get_tool_snapshot("search", "https://server-a.mcp.local")
    assert old_snapshot is not None

    new = _build_metadata(version="1.0.0")
    diff = registry.detect_changes(old_snapshot, new)

    assert "rollback" in diff.change_categories
    assert diff.severity == RiskLevel.CRITICAL


def test_namespace_conflict_detection_on_register() -> None:
    registry = ToolRegistry()
    first = _build_metadata(
        tool_id="tool.search.a",
        tool_identity="search.logical.a",
        name="search",
        source_uri="https://server-a.mcp.local",
        namespace="provider-a",
        provider="provider-a",
    )
    second = _build_metadata(
        tool_id="tool.search.b",
        tool_identity="search.logical.b",
        name="search",
        source_uri="https://server-a.mcp.local",
        namespace="provider-b",
        provider="provider-b",
    )

    result_a = registry.register_tool(first)
    result_b = registry.register_tool(second)

    assert result_a.status == "registered_new"
    assert result_b.status == "registered_suspicious_update"
    assert result_b.change_result is not None
    assert "namespace_conflict" in result_b.change_result.change_categories


def test_capability_drift_without_version_change_detection() -> None:
    registry = ToolRegistry()
    old = _build_metadata(version="1.0.0", capabilities={CapabilityType.READ})
    registry.register_tool(old)
    old_snapshot = registry.get_tool_snapshot("search", "https://server-a.mcp.local")
    assert old_snapshot is not None

    new = _build_metadata(version="1.0.0", capabilities={CapabilityType.READ, CapabilityType.WRITE})
    result = registry.register_tool(new)
    track = registry.get_identity_track(old.tool_id, old.source_uri)
    assert track is not None

    assert result.status == "registered_suspicious_update"
    assert result.change_result is not None
    assert "suspicious_capability_drift" in result.change_result.change_categories
    assert track.suspicious_update_count >= 1
    assert track.drift_history_summary["suspicious_update_count"] >= 1


def test_first_seen_last_seen_and_observation_count_progression() -> None:
    registry = ToolRegistry()
    metadata = _build_metadata()

    first = registry.register_tool(metadata)
    second = registry.register_tool(metadata)
    track = registry.get_identity_track(metadata.tool_id, metadata.source_uri)

    assert track is not None
    assert first.first_seen_at == track.first_seen_at
    assert second.first_seen_at == track.first_seen_at
    assert second.last_seen_at >= first.last_seen_at
    assert track.last_seen_at == second.last_seen_at
    assert track.observation_count == 2


def test_rollback_history_retention_and_summary() -> None:
    registry = ToolRegistry()
    baseline = _build_metadata(version="2.0.0")
    rollback = _build_metadata(version="1.0.0")

    registry.register_tool(baseline)
    result = registry.register_tool(rollback)
    track = registry.get_identity_track(baseline.tool_id, baseline.source_uri)

    assert track is not None
    assert result.status == "registered_suspicious_update"
    assert result.change_result is not None
    assert "rollback" in result.change_result.change_categories
    assert track.observation_history[-1] == "suspicious_update"
    assert track.suspicious_update_count >= 1
    assert track.drift_history_summary["suspicious_update_count"] >= 1
    assert "rollback" in track.drift_history_summary["recent_change_categories"]


def test_save_and_load_json_roundtrip() -> None:
    registry = ToolRegistry()
    metadata = _build_metadata()
    registry.register_tool(metadata)

    test_data_dir = Path("data") / "test_outputs"
    test_data_dir.mkdir(parents=True, exist_ok=True)
    file_path = test_data_dir / f"tool-registry-{uuid4().hex}.json"
    try:
        registry.save_to_json(file_path)
        loaded = ToolRegistry.load_from_json(file_path)
        snapshot = loaded.get_tool_snapshot("search", "https://server-a.mcp.local")
        assert snapshot is not None
        assert snapshot.tool.name == "search"
    finally:
        if file_path.exists():
            file_path.unlink()


def test_load_tracks_json_without_new_audit_fields_compatibility() -> None:
    registry = ToolRegistry()
    metadata = _build_metadata()
    registry.register_tool(metadata)
    registry.register_tool(metadata)

    track = registry.get_identity_track(metadata.tool_id, metadata.source_uri)
    assert track is not None

    legacy_track_payload = track.model_dump(mode="json")
    legacy_track_payload.pop("suspicious_update_count", None)
    legacy_track_payload.pop("drift_history_summary", None)

    test_data_dir = Path("data") / "test_outputs"
    test_data_dir.mkdir(parents=True, exist_ok=True)
    file_path = test_data_dir / f"tool-registry-legacy-track-{uuid4().hex}.json"
    try:
        payload = {
            "tracks_by_identity_origin": {
                f"{metadata.tool_id}::{metadata.source_uri}": legacy_track_payload,
            }
        }
        file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        loaded = ToolRegistry.load_from_json(file_path)
        loaded_track = loaded.get_identity_track(metadata.tool_id, metadata.source_uri)
        assert loaded_track is not None
        assert loaded_track.observation_count == 2
        assert "duplicate_observation_count" in loaded_track.drift_history_summary
        assert "suspicious_update_count" in loaded_track.drift_history_summary
    finally:
        if file_path.exists():
            file_path.unlink()


def test_register_tool_with_minimal_request_lineage_compatibility() -> None:
    registry = ToolRegistry()
    metadata = _build_metadata()
    lineage = RequestLineage(
        request_id="req-lineage-1",
        root_user_request_id="root-lineage-1",
        source_role="client",
        feature="tools",
        trust_label=TrustLabel.UNKNOWN,
    )

    result = registry.register_tool(metadata, request_lineage=lineage)
    assert result.last_seen_request_id == "req-lineage-1"
    assert result.last_seen_session_id is None
    assert result.feature_scope == "tools"
    assert result.lineage_root_request_id == "root-lineage-1"
