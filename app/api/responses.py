from __future__ import annotations

from datetime import UTC, datetime
from typing import Mapping, TypeAlias
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue

JsonObject: TypeAlias = dict[str, JsonValue]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _new_request_id(value: str | None = None) -> str:
    normalized = (value or "").strip()
    return normalized or f"req-{uuid4().hex}"


def _coerce_json_value(value: object) -> JsonValue:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, tuple):
        return [_coerce_json_value(item) for item in value]
    if isinstance(value, list):
        return [_coerce_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _coerce_json_value(item) for key, item in value.items()}
    return str(value)


def _normalize_mapping(value: Mapping[str, object] | None) -> JsonObject:
    if value is None:
        return {}
    return {str(key): _coerce_json_value(item) for key, item in value.items()}


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    details: JsonObject = Field(default_factory=dict)


class EnvelopeMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    request_id: str
    timestamp: str


class SuccessEnvelope(EnvelopeMeta):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    data: JsonObject
    artifacts: JsonObject = Field(default_factory=dict)


class ErrorEnvelope(EnvelopeMeta):
    model_config = ConfigDict(extra="forbid")

    ok: bool = False
    error: ErrorBody


def success_response(
    data: Mapping[str, object],
    *,
    request_id: str | None = None,
    artifacts: Mapping[str, object] | None = None,
) -> dict[str, JsonValue]:
    envelope = SuccessEnvelope(
        ok=True,
        request_id=_new_request_id(request_id),
        timestamp=_utc_now(),
        data=_normalize_mapping(data),
        artifacts=_normalize_mapping(artifacts),
    )
    return envelope.model_dump(mode="json")


def error_response(
    *,
    code: str,
    message: str,
    details: Mapping[str, object] | None = None,
    request_id: str | None = None,
) -> dict[str, JsonValue]:
    envelope = ErrorEnvelope(
        ok=False,
        request_id=_new_request_id(request_id),
        timestamp=_utc_now(),
        error=ErrorBody(
            code=code,
            message=message,
            details=_normalize_mapping(details),
        ),
    )
    return envelope.model_dump(mode="json")
