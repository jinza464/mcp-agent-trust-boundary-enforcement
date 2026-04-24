"""Lightweight pattern memory for drift, exfiltration, and failure-case recall."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.models import RiskLevel

PatternType: TypeAlias = Literal[
    "metadata_drift",
    "sink_exfiltration",
    "failure_case",
    "prompt_injection",
    "tool_shadowing",
    "other",
]


class PatternRecord(BaseModel):
    """One searchable research pattern extracted from cases, reports, or drift findings."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    pattern_type: PatternType = "other"
    text: str
    tags: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    source_case_id: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("pattern_id", "text")
    @classmethod
    def _non_empty_text_fields(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("pattern_id/text must be non-empty.")
        return normalized

    @field_validator("source_case_id")
    @classmethod
    def _normalize_optional_source_case(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        return sorted({item.strip().lower() for item in value if item.strip()})


class PatternSearchResult(BaseModel):
    """Search result wrapper with an interpretable lexical similarity score."""

    model_config = ConfigDict(extra="forbid")

    record: PatternRecord
    score: float
    matched_tokens: list[str] = Field(default_factory=list)


def _tokens(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-zA-Z0-9_./:-]+", text.lower())
        if len(token) > 1
    }


def _record_tokens(record: PatternRecord) -> set[str]:
    metadata_text = " ".join(str(value) for value in record.metadata.values())
    return _tokens(" ".join([record.text, " ".join(record.tags), metadata_text, record.pattern_type]))


def _score(query_tokens: set[str], record_tokens: set[str]) -> tuple[float, list[str]]:
    if not query_tokens or not record_tokens:
        return 0.0, []
    intersection = query_tokens.intersection(record_tokens)
    union = query_tokens.union(record_tokens)
    jaccard = len(intersection) / len(union)
    coverage = len(intersection) / len(query_tokens)
    score = (0.7 * jaccard) + (0.3 * coverage)
    return score, sorted(intersection)


class PatternMemory:
    """Small in-memory pattern index with JSONL persistence."""

    def __init__(self, records: list[PatternRecord] | None = None) -> None:
        self._records: dict[str, PatternRecord] = {}
        if records:
            self.add_many(records)

    @property
    def records(self) -> list[PatternRecord]:
        return list(self._records.values())

    def add(self, record: PatternRecord | dict[str, object]) -> PatternRecord:
        parsed = record if isinstance(record, PatternRecord) else PatternRecord.model_validate(record)
        self._records[parsed.pattern_id] = parsed
        return parsed

    def add_many(self, records: list[PatternRecord | dict[str, object]]) -> list[PatternRecord]:
        return [self.add(record) for record in records]

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        pattern_type: PatternType | str | None = None,
    ) -> list[PatternSearchResult]:
        if top_k <= 0:
            return []
        query_tokens = _tokens(query)
        results: list[PatternSearchResult] = []
        for record in self._records.values():
            if pattern_type is not None and record.pattern_type != pattern_type:
                continue
            score, matched_tokens = _score(query_tokens, _record_tokens(record))
            if score <= 0:
                continue
            results.append(PatternSearchResult(record=record, score=score, matched_tokens=matched_tokens))
        results.sort(key=lambda item: (-item.score, item.record.pattern_id))
        return results[:top_k]

    @classmethod
    def load_jsonl(cls, path: str | Path) -> "PatternMemory":
        memory = cls()
        file_path = Path(path)
        if not file_path.exists():
            return memory
        for line in file_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            memory.add(json.loads(stripped))
        return memory

    def save_jsonl(self, path: str | Path) -> Path:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            json.dumps(record.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
            for record in self.records
        ]
        file_path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")
        return file_path

    @classmethod
    def from_attack_cases(cls, cases: list[object]) -> "PatternMemory":
        records: list[PatternRecord] = []
        for case in cases:
            case_id = str(getattr(case, "id", getattr(case, "case_id", ""))).strip()
            if not case_id:
                continue
            attack_type = str(getattr(case, "attack_type", "other")).strip().lower()
            text = " ".join(
                str(value)
                for value in (
                    getattr(case, "attack_type", ""),
                    getattr(case, "scenario", ""),
                    getattr(case, "source_content", ""),
                    getattr(getattr(case, "tool_metadata", None), "description", ""),
                )
                if value
            )
            pattern_type: PatternType = "failure_case"
            if "metadata" in attack_type or "rug" in attack_type:
                pattern_type = "metadata_drift"
            elif "sink" in attack_type or "exfil" in attack_type:
                pattern_type = "sink_exfiltration"
            elif "injection" in attack_type:
                pattern_type = "prompt_injection"
            elif "shadow" in attack_type:
                pattern_type = "tool_shadowing"
            records.append(
                PatternRecord(
                    pattern_id=f"case:{case_id}",
                    pattern_type=pattern_type,
                    text=text or case_id,
                    tags=[
                        str(getattr(case, "case_family", "general")),
                        str(getattr(case, "primary_target_module", "unknown")),
                        attack_type,
                    ],
                    risk_level=getattr(case, "expected_risk", RiskLevel.LOW),
                    source_case_id=case_id,
                    metadata={
                        "is_attack": bool(getattr(case, "is_attack", False)),
                        "is_benign": bool(getattr(case, "is_benign", False)),
                        "involves_sink": bool(getattr(case, "involves_sink", False)),
                    },
                )
            )
        return cls(records)
