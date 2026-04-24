"""Tests for evaluation attack case inventory and metadata enrichment."""

from __future__ import annotations

from app.eval.attack_cases import (
    CASE_FAMILIES,
    DIFFICULTY_LEVELS,
    build_case_lookup,
    default_attack_cases,
    summarize_case_families,
)


def test_default_attack_cases_have_unique_ids() -> None:
    cases = default_attack_cases()
    ids = [item.id for item in cases]
    assert ids
    assert len(ids) == len(set(ids))
    assert all(case_id.startswith("case-") for case_id in ids)


def test_default_attack_cases_are_enriched_with_research_metadata() -> None:
    cases = default_attack_cases()
    assert all(item.case_family in CASE_FAMILIES for item in cases)
    assert all(item.difficulty in DIFFICULTY_LEVELS for item in cases)
    assert all(item.primary_target_module for item in cases)
    assert all(item.expected_failure_mode for item in cases)


def test_build_case_lookup_contains_core_cases() -> None:
    lookup = build_case_lookup()
    assert "case-metadata-injection" in lookup
    assert "case-tool-shadowing" in lookup
    assert "case-source-to-sink-exfiltration" in lookup
    assert lookup["case-tool-shadowing"].primary_target_module == "metadata_validator"


def test_summarize_case_families_is_stable_and_non_empty() -> None:
    summary = summarize_case_families()
    assert summary
    assert sum(summary.values()) == len(default_attack_cases())
    assert any(count > 0 for count in summary.values())
