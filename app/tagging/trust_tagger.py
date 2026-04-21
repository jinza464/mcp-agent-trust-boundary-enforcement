"""Trust inference for heterogeneous sources in client-side trust boundaries."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import TrustLabel


class TrustFactor(BaseModel):
    """Structured factor used in trust inference."""

    model_config = ConfigDict(extra="forbid")

    factor: str = Field(...)
    observed: str = Field(...)
    effect: str = Field(...)


class TrustInferenceResult(BaseModel):
    """Structured trust inference result with explainable factors."""

    model_config = ConfigDict(extra="forbid")

    trust_label: TrustLabel = Field(...)
    baseline_prior: TrustLabel = Field(...)
    trust_factors: list[TrustFactor] = Field(default_factory=list)
    downgrade_reasons: list[str] = Field(default_factory=list)


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


def _is_stale(metadata: dict[str, Any]) -> bool | None:
    stale = _as_bool(metadata, "is_stale")
    if stale is not None:
        return stale
    freshness = metadata.get("freshness")
    if isinstance(freshness, str):
        f = freshness.strip().lower()
        if f in {"stale", "expired"}:
            return True
        if f in {"fresh", "valid"}:
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
    st = source_type.strip().lower()
    if st == "user_query":
        return TrustLabel.TRUSTED
    if st == "system_config":
        return TrustLabel.TRUSTED
    if st == "cached_metadata":
        return TrustLabel.SEMI_TRUSTED
    if st == "tool_description":
        return TrustLabel.SEMI_TRUSTED
    if st == "external_document":
        return TrustLabel.UNTRUSTED
    if st == "server_notification":
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


def infer_trust(source_type: str, content: str, metadata: dict[str, Any] | None = None) -> TrustInferenceResult:
    """Infer trust from source prior + integrity/context/content signals.

    Semantics:
    - trusted: strong provenance and no contradictory safety signal.
    - semi_trusted: partially trusted; suitable for guarded execution paths.
    - conditional: mixed evidence; requires downstream safeguards/confirmation.
    - unknown: insufficient evidence (primarily unknown source with weak signals).
    - untrusted: clear adverse evidence (integrity/signature failure or strong malicious signals).
    """
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

    if integrity_verified is False:
        score -= 4
        downgrade_reasons.append("integrity verification failed")
        factors.append(TrustFactor(factor="integrity_verified", observed="false", effect="hard downgrade"))
    elif integrity_verified is True:
        score += 1
        factors.append(TrustFactor(factor="integrity_verified", observed="true", effect="upgrade"))

    if signature_valid is False:
        score -= 3
        downgrade_reasons.append("signature invalid")
        factors.append(TrustFactor(factor="signature_valid", observed="false", effect="hard downgrade"))
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

    # Hard fail-closed rules for integrity/freshness failures.
    if integrity_verified is False or signature_valid is False:
        score = min(score, -3)
    if source_type.strip().lower() == "cached_metadata" and stale is True:
        score = min(score, -3)

    # If source is explicitly untrusted but integrity evidence exists, treat as conditional instead of pure untrusted.
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

    # Preserve baseline semantic boundary for tool descriptions: never above semi-trusted.
    if source_type.strip().lower() == "tool_description" and inferred == TrustLabel.TRUSTED:
        inferred = TrustLabel.SEMI_TRUSTED
        factors.append(
            TrustFactor(
                factor="tool_description_cap",
                observed="cap_to_semi_trusted",
                effect="policy_cap",
            )
        )

    # Unknown source with no strong evidence remains unknown instead of forced downgrade.
    if prior == TrustLabel.UNKNOWN and not factors:
        inferred = TrustLabel.UNKNOWN

    return TrustInferenceResult(
        trust_label=inferred,
        baseline_prior=prior,
        trust_factors=factors,
        downgrade_reasons=downgrade_reasons,
    )


def tag_source(source_type: str, content: str, metadata: dict[str, Any] | None = None) -> TrustLabel:
    """Compatibility wrapper returning only trust label."""
    return infer_trust(source_type, content, metadata=metadata).trust_label
