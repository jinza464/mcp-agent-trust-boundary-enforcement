"""Tests for app.registry.tool_registry."""

from __future__ import annotations

from app.core.models import CapabilityType, ToolMetadata
from app.registry.tool_registry import ToolRegistry


def _build_metadata(
    *,
    tool_id: str = "tool.search",
    name: str = "search",
    source_uri: str = "https://server-a.mcp.local",
    description: str = "Search documents.",
    version: str = "1.0.0",
    capabilities: set[CapabilityType] | None = None,
    tags: list[str] | None = None,
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        name=name,
        version=version,
        provider="provider-a",
        description=description,
        capabilities=capabilities or {CapabilityType.READ},
        source_uri=source_uri,
        tags=tags or [],
    )


def test_register_tool_first_registration() -> None:
    registry = ToolRegistry()
    metadata = _build_metadata()

    result = registry.register_tool(metadata)

    assert result.status == "registered_new"
    assert result.change_result is None
    snapshot = registry.get_tool_snapshot("search", "https://server-a.mcp.local")
    assert snapshot is not None


def test_register_tool_duplicate_registration() -> None:
    registry = ToolRegistry()
    metadata = _build_metadata()

    registry.register_tool(metadata)
    result = registry.register_tool(metadata)

    assert result.status == "registered_duplicate"
    assert result.change_result is not None
    assert result.change_result.changed is False
    assert result.change_result.changed_fields == []


def test_detect_description_change() -> None:
    registry = ToolRegistry()
    old_metadata = _build_metadata(description="Search public docs.")
    registry.register_tool(old_metadata)
    old_snapshot = registry.get_tool_snapshot("search", "https://server-a.mcp.local")
    assert old_snapshot is not None

    new_metadata = _build_metadata(description="Search public and private docs.")
    diff = registry.detect_changes(old_snapshot, new_metadata)

    assert diff.changed is True
    assert "description_hash" in diff.changed_fields


def test_detect_schema_change() -> None:
    registry = ToolRegistry()
    old_metadata = _build_metadata(capabilities={CapabilityType.READ}, tags=["schema:v1"])
    registry.register_tool(old_metadata)
    old_snapshot = registry.get_tool_snapshot("search", "https://server-a.mcp.local")
    assert old_snapshot is not None

    new_metadata = _build_metadata(capabilities={CapabilityType.READ, CapabilityType.WRITE}, tags=["schema:v2"])
    diff = registry.detect_changes(old_snapshot, new_metadata)

    assert diff.changed is True
    assert "schema_hash" in diff.changed_fields


def test_same_name_different_origin() -> None:
    registry = ToolRegistry()
    metadata_a = _build_metadata(name="search", source_uri="https://server-a.mcp.local", tool_id="tool.search.a")
    metadata_b = _build_metadata(name="search", source_uri="https://server-b.mcp.local", tool_id="tool.search.b")

    result_a = registry.register_tool(metadata_a)
    result_b = registry.register_tool(metadata_b)

    assert result_a.status == "registered_new"
    assert result_b.status == "registered_new"

    snapshot_a = registry.get_tool_snapshot("search", "https://server-a.mcp.local")
    snapshot_b = registry.get_tool_snapshot("search", "https://server-b.mcp.local")
    assert snapshot_a is not None
    assert snapshot_b is not None
    assert snapshot_a.tool.tool_id == "tool.search.a"
    assert snapshot_b.tool.tool_id == "tool.search.b"
