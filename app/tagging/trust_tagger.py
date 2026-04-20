"""Rule-based trust tagging for heterogeneous input sources."""

from __future__ import annotations

from typing import Any

from app.core.models import TrustLabel


def _as_bool(metadata: dict[str, Any], key: str) -> bool | None:
    """Read an optional boolean flag from metadata."""
    value = metadata.get(key)
    return value if isinstance(value, bool) else None


def tag_source(source_type: str, content: str, metadata: dict[str, Any] | None = None) -> TrustLabel:
    """Assign a trust label for an input source using deterministic rules.

    Args:
        source_type: Input source category such as user_query or external_document.
        content: Raw content payload (reserved for future rule extensions).
        metadata: Optional source metadata used for conservative overrides.
    """
    _ = content
    meta = metadata or {}
    normalized_type = source_type.strip().lower()

    if normalized_type == "user_query":
        return TrustLabel.TRUSTED

    if normalized_type == "external_document":
        return TrustLabel.UNTRUSTED

    if normalized_type == "server_notification":
        return TrustLabel.UNTRUSTED

    if normalized_type == "cached_metadata":
        if _as_bool(meta, "integrity_verified") is False or _as_bool(meta, "is_stale") is True:
            return TrustLabel.UNTRUSTED
        return TrustLabel.SEMI_TRUSTED

    if normalized_type == "system_config":
        if _as_bool(meta, "integrity_verified") is False:
            return TrustLabel.UNTRUSTED
        return TrustLabel.TRUSTED

    if normalized_type == "tool_description":
        # Tool descriptions are never promoted above semi-trusted in v1.
        is_local = _as_bool(meta, "is_local") is True
        signature_valid = _as_bool(meta, "signature_valid") is True
        if is_local and signature_valid:
            return TrustLabel.SEMI_TRUSTED
        return TrustLabel.UNTRUSTED

    return TrustLabel.UNTRUSTED
