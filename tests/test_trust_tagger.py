"""Tests for rule-based trust tagging."""

from __future__ import annotations

from app.core.models import TrustLabel
from app.tagging.trust_tagger import tag_source


def test_user_query_defaults_to_trusted() -> None:
    assert tag_source("user_query", "help me summarize this") == TrustLabel.TRUSTED


def test_external_document_defaults_to_untrusted() -> None:
    assert tag_source("external_document", "remote pdf content") == TrustLabel.UNTRUSTED


def test_server_notification_defaults_to_untrusted() -> None:
    assert tag_source("server_notification", "tool updated") == TrustLabel.UNTRUSTED


def test_cached_metadata_defaults_to_semi_trusted() -> None:
    assert tag_source("cached_metadata", "cached tool manifest") == TrustLabel.SEMI_TRUSTED


def test_cached_metadata_can_be_downgraded() -> None:
    assert (
        tag_source("cached_metadata", "cached tool manifest", metadata={"is_stale": True})
        == TrustLabel.UNTRUSTED
    )


def test_system_config_defaults_to_trusted() -> None:
    assert tag_source("system_config", "policy=true") == TrustLabel.TRUSTED


def test_system_config_can_be_downgraded() -> None:
    assert (
        tag_source("system_config", "policy=true", metadata={"integrity_verified": False})
        == TrustLabel.UNTRUSTED
    )


def test_tool_description_defaults_to_untrusted() -> None:
    assert tag_source("tool_description", "Tool can read files") == TrustLabel.UNTRUSTED


def test_tool_description_can_be_semi_trusted_but_not_trusted() -> None:
    assert (
        tag_source(
            "tool_description",
            "Tool can read files",
            metadata={"is_local": True, "signature_valid": True},
        )
        == TrustLabel.SEMI_TRUSTED
    )


def test_unknown_source_defaults_to_untrusted() -> None:
    assert tag_source("unknown_source", "payload") == TrustLabel.UNTRUSTED
