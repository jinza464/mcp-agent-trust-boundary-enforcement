"""Tests for strict tool identity registry behavior."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from app.core.models import CapabilityType, RiskLevel, ToolMetadata
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

    registry.register_tool(metadata)
    result = registry.register_tool(metadata)

    assert result.status == "registered_duplicate"
    assert result.observation_kind == "duplicate_observation"
    assert result.is_duplicate is True
    assert result.observation_count == 2


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

    assert result.status == "registered_suspicious_update"
    assert result.change_result is not None
    assert "suspicious_capability_drift" in result.change_result.change_categories


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
