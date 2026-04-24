from __future__ import annotations

import json

from app.core.models import RiskLevel
from app.eval.pattern_memory import PatternMemory, PatternRecord


def test_pattern_record_constructs_and_dumps_json() -> None:
    record = PatternRecord(
        pattern_id="pattern-1",
        pattern_type="metadata_drift",
        text="metadata rollback drift",
        tags=["Metadata", "Drift"],
        risk_level=RiskLevel.HIGH,
        source_case_id="case-1",
    )

    dumped = record.model_dump(mode="json")
    assert dumped["pattern_id"] == "pattern-1"
    assert dumped["pattern_type"] == "metadata_drift"
    assert dumped["risk_level"] == "high"
    assert dumped["tags"] == ["drift", "metadata"]
    json.dumps(dumped)


def test_pattern_memory_add_and_add_many() -> None:
    memory = PatternMemory()
    memory.add({"pattern_id": "p1", "text": "metadata drift", "pattern_type": "metadata_drift"})
    memory.add_many(
        [
            PatternRecord(pattern_id="p2", text="sink exfiltration token", pattern_type="sink_exfiltration"),
            {"pattern_id": "p3", "text": "failure case shadowing", "pattern_type": "failure_case"},
        ]
    )

    assert [record.pattern_id for record in memory.records] == ["p1", "p2", "p3"]


def test_search_returns_scored_results_and_pattern_type_filter() -> None:
    memory = PatternMemory(
        [
            PatternRecord(pattern_id="metadata", text="metadata rollback drift prompt", pattern_type="metadata_drift"),
            PatternRecord(pattern_id="sink", text="external webhook token exfiltration", pattern_type="sink_exfiltration"),
        ]
    )

    hits = memory.search("metadata rollback drift", top_k=1)
    sink_hits = memory.search("webhook token", pattern_type="sink_exfiltration")

    assert hits[0].record.pattern_id == "metadata"
    assert hits[0].score > 0
    assert "metadata" in hits[0].matched_tokens
    assert [hit.record.pattern_id for hit in sink_hits] == ["sink"]


def test_save_and_load_jsonl_round_trip(tmp_path) -> None:
    path = tmp_path / "patterns.jsonl"
    memory = PatternMemory(
        [
            PatternRecord(pattern_id="p1", text="metadata drift", pattern_type="metadata_drift"),
            PatternRecord(pattern_id="p2", text="sink exfiltration", pattern_type="sink_exfiltration"),
        ]
    )

    memory.save_jsonl(path)
    loaded = PatternMemory.load_jsonl(path)

    assert path.exists()
    assert [record.pattern_id for record in loaded.records] == ["p1", "p2"]


def test_token_overlap_ranks_semantically_close_pattern_first() -> None:
    memory = PatternMemory(
        [
            PatternRecord(pattern_id="close", text="metadata schema rollback drift detected", pattern_type="metadata_drift"),
            PatternRecord(pattern_id="weak", text="metadata report generation", pattern_type="failure_case"),
        ]
    )

    hits = memory.search("schema rollback metadata drift", top_k=2)

    assert len(hits) == 2
    assert hits[0].record.pattern_id == "close"
    assert hits[1].record.pattern_id == "weak"
    assert hits[0].score > hits[1].score
