"""Trust inference for heterogeneous sources in client-side trust boundaries."""

from __future__ import annotations

from typing import Any
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import TrustLabel


class TrustFactor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    factor: str = Field(...)
    observed: str = Field(...)
    effect: str = Field(...)


class TrustInferenceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trust_label: TrustLabel = Field(...)
    baseline_prior: TrustLabel = Field(...)
    trust_factors: list[TrustFactor] = Field(default_factory=list)
    downgrade_reasons: list[str] = Field(default_factory=list)
    trust_score: int = Field(..., description="Internal heuristic score after factor adjustment.")
    provenance_chain: list["ProvenanceHop"] = Field(default_factory=list)
    evidence_strength: str = Field(default="weak")
    derived_from_untrusted_content: bool = Field(default=False)


class EvidenceStrength(str, Enum):
    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"


class ProvenanceHop(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(...)
    trust_label: TrustLabel | None = Field(default=None)
    note: str = Field(default="")


_PROMPT_LIKE_PATTERNS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all prior instructions",
    "system prompt",
    "developer message",
    "without user confirmation",
    "act as",
    "hidden override",
)


def _as_bool(metadata: dict[str, Any], key: str) -> bool | None:
    value = metadata.get(key)
    return value if isinstance(value, bool) else None


def _as_optional_string(metadata: dict[str, Any], key: str) -> str | None:
    value = metadata.get(key)
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    return None


def _as_optional_trust_label(metadata: dict[str, Any], key: str) -> TrustLabel | None:
    value = metadata.get(key)
    if isinstance(value, TrustLabel):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        for label in TrustLabel:
            if normalized == label.value:
                return label
    return None


def _looks_untrusted_source(source_type: str | None) -> bool:
    if not source_type:
        return False
    return _baseline_prior(source_type) == TrustLabel.UNTRUSTED


def _normalize_metadata_provenance_chain(raw: object) -> list[ProvenanceHop]:
    hops: list[ProvenanceHop] = []
    if raw is None:
        return hops
    if isinstance(raw, str):
        text = raw.strip()
        if text:
            hops.append(ProvenanceHop(source="metadata.provenance_chain", note=text))
        return hops
    if not isinstance(raw, list):
        return hops
    for item in raw:
        if isinstance(item, str):
            text = item.strip()
            if text:
                hops.append(ProvenanceHop(source="metadata.provenance_chain", note=text))
            continue
        if isinstance(item, dict):
            source = str(item.get("source") or item.get("source_type") or "metadata.provenance_chain")
            note = str(item.get("note") or item.get("hint") or item.get("reason") or "")
            raw_trust = item.get("trust_label")
            trust_label: TrustLabel | None = None
            if isinstance(raw_trust, TrustLabel):
                trust_label = raw_trust
            elif isinstance(raw_trust, str):
                lowered = raw_trust.strip().lower()
                for candidate in TrustLabel:
                    if lowered == candidate.value:
                        trust_label = candidate
                        break
            hops.append(ProvenanceHop(source=source, trust_label=trust_label, note=note))
    return hops


def _is_stale(metadata: dict[str, Any]) -> bool | None:
    stale = _as_bool(metadata, "is_stale")
    if stale is not None:
        return stale
    freshness = metadata.get("freshness")
    if isinstance(freshness, str):
        value = freshness.strip().lower()
        if value in {"stale", "expired"}:
            return True
        if value in {"fresh", "valid"}:
            return False
    freshness_seconds = metadata.get("freshness_seconds")
    max_freshness_seconds = metadata.get("max_freshness_seconds")
    if isinstance(freshness_seconds, (int, float)) and isinstance(max_freshness_seconds, (int, float)):
        return freshness_seconds > max_freshness_seconds
    return None


def _contains_prompt_like(content: str) -> bool:
    text = content.lower()
    return any(pattern in text for pattern in _PROMPT_LIKE_PATTERNS)


def _baseline_prior(source_type: str) -> TrustLabel:
    source = source_type.strip().lower()
    if source in {"user_query", "system_config"}:
        return TrustLabel.TRUSTED
    if source in {"cached_metadata", "tool_description", "registry_snapshot"}:
        return TrustLabel.SEMI_TRUSTED
    if source in {"external_document", "server_notification"}:
        return TrustLabel.UNTRUSTED
    return TrustLabel.UNKNOWN


def _label_to_score(label: TrustLabel) -> int:
    mapping = {
        TrustLabel.UNTRUSTED: -3,
        TrustLabel.UNKNOWN: -1,
        TrustLabel.CONDITIONAL: 0,
        TrustLabel.SEMI_TRUSTED: 1,
        TrustLabel.TRUSTED: 3,
    }
    return mapping[label]


def _score_to_label(score: int) -> TrustLabel:
    if score >= 3:
        return TrustLabel.TRUSTED
    if score >= 1:
        return TrustLabel.SEMI_TRUSTED
    if score == 0:
        return TrustLabel.CONDITIONAL
    if score == -1:
        return TrustLabel.UNKNOWN
    return TrustLabel.UNTRUSTED


def _build_provenance_chain(
    *,
    source_type: str,
    prior: TrustLabel,
    metadata: dict[str, Any],
    upstream_trust_label: TrustLabel | None,
    derived_from_source_type: str | None,
    derived_from_untrusted_content: bool,
) -> list[ProvenanceHop]:
    chain: list[ProvenanceHop] = [
        ProvenanceHop(source="source_type_baseline", trust_label=prior, note=f"source_type={source_type.strip().lower()}")
    ]
    if derived_from_source_type:
        inferred_label = _baseline_prior(derived_from_source_type)
        chain.append(
            ProvenanceHop(
                source="derived_from_source_type",
                trust_label=inferred_label,
                note=f"derived_from_source_type={derived_from_source_type}",
            )
        )
    if upstream_trust_label is not None:
        chain.append(
            ProvenanceHop(
                source="upstream_trust_label",
                trust_label=upstream_trust_label,
                note="explicit upstream trust label from metadata",
            )
        )
    chain.extend(_normalize_metadata_provenance_chain(metadata.get("provenance_chain")))
    if derived_from_untrusted_content:
        chain.append(
            ProvenanceHop(
                source="derived_from_untrusted_content",
                trust_label=TrustLabel.UNTRUSTED,
                note="metadata indicates upstream untrusted derivation",
            )
        )
    return chain


def _estimate_evidence_strength(
    *,
    integrity_verified: bool | None,
    signature_valid: bool | None,
    registry_consistent: bool | None,
    stale: bool | None,
    prompt_like: bool,
    derived_from_untrusted_content: bool,
) -> EvidenceStrength:
    positive = sum(
        (
            integrity_verified is True,
            signature_valid is True,
            registry_consistent is True,
            stale is False,
        )
    )
    negative = sum(
        (
            integrity_verified is False,
            signature_valid is False,
            registry_consistent is False,
            stale is True,
            prompt_like,
            derived_from_untrusted_content,
        )
    )
    if positive >= 3 and negative == 0:
        return EvidenceStrength.STRONG
    if positive + negative >= 2:
        return EvidenceStrength.MEDIUM
    return EvidenceStrength.WEAK


def infer_trust(source_type: str, content: str, metadata: dict[str, Any] | None = None) -> TrustInferenceResult:
    meta = metadata or {}
    prior = _baseline_prior(source_type)
    score = _label_to_score(prior)
    factors: list[TrustFactor] = []
    downgrade_reasons: list[str] = []

    integrity_verified = _as_bool(meta, "integrity_verified")
    signature_valid = _as_bool(meta, "signature_valid")
    is_local = _as_bool(meta, "is_local")
    is_remote = _as_bool(meta, "is_remote")
    registry_consistent = _as_bool(meta, "registry_consistent")
    stale = _is_stale(meta)
    prompt_like = _contains_prompt_like(content)
    upstream_trust_label = _as_optional_trust_label(meta, "upstream_trust_label")
    derived_from_source_type = _as_optional_string(meta, "derived_from_source_type")
    explicit_derived_from_untrusted = _as_bool(meta, "derived_from_untrusted_content") is True
    inferred_derived_from_untrusted = (
        upstream_trust_label == TrustLabel.UNTRUSTED
        or _looks_untrusted_source(derived_from_source_type)
    )
    metadata_chain = _normalize_metadata_provenance_chain(meta.get("provenance_chain"))
    chain_contains_untrusted = any(item.trust_label == TrustLabel.UNTRUSTED for item in metadata_chain)
    derived_from_untrusted_content = (
        explicit_derived_from_untrusted or inferred_derived_from_untrusted or chain_contains_untrusted
    )

    if integrity_verified is False:
        score -= 4
        downgrade_reasons.append("integrity verification failed")
        factors.append(TrustFactor(factor="integrity_verified", observed="false", effect="hard_downgrade"))
    elif integrity_verified is True:
        score += 1
        factors.append(TrustFactor(factor="integrity_verified", observed="true", effect="upgrade"))

    if signature_valid is False:
        score -= 3
        downgrade_reasons.append("signature invalid")
        factors.append(TrustFactor(factor="signature_valid", observed="false", effect="hard_downgrade"))
    elif signature_valid is True:
        score += 1
        factors.append(TrustFactor(factor="signature_valid", observed="true", effect="upgrade"))

    if stale is True:
        score -= 2
        downgrade_reasons.append("stale source evidence")
        factors.append(TrustFactor(factor="freshness", observed="stale", effect="downgrade"))
    elif stale is False:
        score += 1
        factors.append(TrustFactor(factor="freshness", observed="fresh", effect="upgrade"))

    if is_local is True:
        score += 1
        factors.append(TrustFactor(factor="locality", observed="local", effect="upgrade"))
    if is_remote is True:
        score -= 1
        factors.append(TrustFactor(factor="locality", observed="remote", effect="downgrade"))

    if registry_consistent is True:
        score += 1
        factors.append(TrustFactor(factor="registry_consistent", observed="true", effect="upgrade"))
    elif registry_consistent is False:
        score -= 2
        downgrade_reasons.append("registry inconsistency hint")
        factors.append(TrustFactor(factor="registry_consistent", observed="false", effect="downgrade"))

    if prompt_like:
        score -= 2
        downgrade_reasons.append("prompt-like control text detected")
        factors.append(TrustFactor(factor="content_signal", observed="prompt_like_control", effect="downgrade"))

    if derived_from_untrusted_content:
        score -= 2
        downgrade_reasons.append("derived from untrusted upstream content")
        factors.append(
            TrustFactor(
                factor="provenance",
                observed="derived_from_untrusted_content",
                effect="downgrade",
            )
        )

    if integrity_verified is False or signature_valid is False:
        score = min(score, -3)
    if source_type.strip().lower() == "cached_metadata" and stale is True:
        score = min(score, -3)

    if prior == TrustLabel.UNTRUSTED and integrity_verified is True and signature_valid is True and score >= -1:
        score = max(score, 0)
        factors.append(
            TrustFactor(
                factor="source_prior_override",
                observed="untrusted_with_integrity_evidence",
                effect="conditional_floor",
            )
        )

    inferred = _score_to_label(score)

    if source_type.strip().lower() == "tool_description" and inferred == TrustLabel.TRUSTED:
        inferred = TrustLabel.SEMI_TRUSTED
        factors.append(TrustFactor(factor="tool_description_cap", observed="cap_to_semi_trusted", effect="policy_cap"))

    if prior == TrustLabel.UNKNOWN and not factors:
        inferred = TrustLabel.UNKNOWN

    provenance_chain = _build_provenance_chain(
        source_type=source_type,
        prior=prior,
        metadata=meta,
        upstream_trust_label=upstream_trust_label,
        derived_from_source_type=derived_from_source_type,
        derived_from_untrusted_content=derived_from_untrusted_content,
    )
    evidence_strength = _estimate_evidence_strength(
        integrity_verified=integrity_verified,
        signature_valid=signature_valid,
        registry_consistent=registry_consistent,
        stale=stale,
        prompt_like=prompt_like,
        derived_from_untrusted_content=derived_from_untrusted_content,
    )

    return TrustInferenceResult(
        trust_label=inferred,
        baseline_prior=prior,
        trust_factors=factors,
        downgrade_reasons=downgrade_reasons,
        trust_score=score,
        provenance_chain=provenance_chain,
        evidence_strength=evidence_strength.value,
        derived_from_untrusted_content=derived_from_untrusted_content,
    )


def tag_source(source_type: str, content: str, metadata: dict[str, Any] | None = None) -> TrustLabel:
    return infer_trust(source_type, content, metadata=metadata).trust_label
