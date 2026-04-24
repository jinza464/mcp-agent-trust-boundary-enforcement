from __future__ import annotations

from typing import TypeAlias

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

JsonObject: TypeAlias = dict[str, JsonValue]


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    app_name: str
    version: str
    environment: str


class ToolItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str
    name: str
    version: str
    provider: str
    source_uri: str | None = None


class ToolListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ToolItem]
    total_tools: int


class SourceMetadata(BaseModel):
    """Source metadata with known trust-tagging fields plus extension bucket."""

    model_config = ConfigDict(extra="forbid")

    integrity_verified: bool | None = None
    is_stale: bool | None = None
    signature_valid: bool | None = None
    is_local: bool | None = None
    user_authorized: bool | None = None
    document_origin: str | None = None
    approval_ticket: str | None = None
    attributes: JsonObject = Field(default_factory=dict, description="Additional metadata attributes.")

    @model_validator(mode="before")
    @classmethod
    def _move_unknown_fields_to_attributes(cls, value: object) -> object:
        if value is None:
            return {}
        if isinstance(value, SourceMetadata):
            return value
        if not isinstance(value, dict):
            raise TypeError("source_metadata must be an object.")

        known_fields = {
            "integrity_verified",
            "is_stale",
            "signature_valid",
            "is_local",
            "user_authorized",
            "document_origin",
            "approval_ticket",
            "attributes",
        }
        payload = dict(value)
        raw_attributes = payload.get("attributes")
        attributes: JsonObject = {}
        if isinstance(raw_attributes, dict):
            attributes.update({str(k): v for k, v in raw_attributes.items()})
        for key in list(payload.keys()):
            if key in known_fields:
                continue
            attributes[str(key)] = payload.pop(key)
        payload["attributes"] = attributes
        return payload

    def to_runtime_dict(self) -> dict[str, JsonValue]:
        output: dict[str, JsonValue] = {}
        for key in (
            "integrity_verified",
            "is_stale",
            "signature_valid",
            "is_local",
            "user_authorized",
            "document_origin",
            "approval_ticket",
        ):
            value = getattr(self, key)
            if value is not None:
                output[key] = value
        output.update(self.attributes)
        return output


class SinkMetadata(BaseModel):
    """Sink metadata with known sink-guard controls plus extension bucket."""

    model_config = ConfigDict(extra="forbid")

    sink_type: str | None = None
    endpoint: str | None = None
    url: str | None = None
    destination: str | None = None
    allowlisted_domains: list[str] = Field(default_factory=list)
    allowlisted_endpoints: list[str] = Field(default_factory=list)
    internal_domains: list[str] = Field(default_factory=list)
    path: str | None = None
    file_path: str | None = None
    target_path: str | None = None
    operation: str | None = None
    user_authorized: bool | None = None
    integrity_verified: bool | None = None
    signature_valid: bool | None = None
    is_local: bool | None = None
    trusted_internal: bool | None = None
    attributes: JsonObject = Field(default_factory=dict, description="Additional sink metadata attributes.")

    @field_validator(
        "allowlisted_domains",
        "allowlisted_endpoints",
        "internal_domains",
        mode="before",
    )
    @classmethod
    def _normalize_string_list(cls, value: object) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise TypeError("list fields must be arrays.")
        normalized: list[str] = []
        seen: set[str] = set()
        for item in value:
            text = str(item).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized.append(text)
        return normalized

    @model_validator(mode="before")
    @classmethod
    def _move_unknown_fields_to_attributes(cls, value: object) -> object:
        if value is None:
            return {}
        if isinstance(value, SinkMetadata):
            return value
        if not isinstance(value, dict):
            raise TypeError("sink_metadata must be an object.")

        known_fields = {
            "sink_type",
            "endpoint",
            "url",
            "destination",
            "allowlisted_domains",
            "allowlisted_endpoints",
            "internal_domains",
            "path",
            "file_path",
            "target_path",
            "operation",
            "user_authorized",
            "integrity_verified",
            "signature_valid",
            "is_local",
            "trusted_internal",
            "attributes",
        }
        payload = dict(value)
        raw_attributes = payload.get("attributes")
        attributes: JsonObject = {}
        if isinstance(raw_attributes, dict):
            attributes.update({str(k): v for k, v in raw_attributes.items()})
        for key in list(payload.keys()):
            if key in known_fields:
                continue
            attributes[str(key)] = payload.pop(key)
        payload["attributes"] = attributes
        return payload

    def to_runtime_dict(self) -> dict[str, JsonValue]:
        output: dict[str, JsonValue] = {}
        for key in (
            "sink_type",
            "endpoint",
            "url",
            "destination",
            "path",
            "file_path",
            "target_path",
            "operation",
            "user_authorized",
            "integrity_verified",
            "signature_valid",
            "is_local",
            "trusted_internal",
        ):
            value = getattr(self, key)
            if value is not None:
                output[key] = value
        if self.allowlisted_domains:
            output["allowlisted_domains"] = list(self.allowlisted_domains)
        if self.allowlisted_endpoints:
            output["allowlisted_endpoints"] = list(self.allowlisted_endpoints)
        if self.internal_domains:
            output["internal_domains"] = list(self.internal_domains)
        output.update(self.attributes)
        return output


class SinkPayloadEnvelope(BaseModel):
    """Unified sink payload boundary that still accepts legacy str/dict input."""

    model_config = ConfigDict(extra="forbid")

    text_payload: str | None = None
    structured_payload: JsonObject | None = None

    @model_validator(mode="before")
    @classmethod
    def _coerce_legacy_payload(cls, value: object) -> object:
        if value is None:
            return {"text_payload": None, "structured_payload": None}
        if isinstance(value, SinkPayloadEnvelope):
            return value
        if isinstance(value, str):
            return {"text_payload": value}
        if isinstance(value, dict):
            if "text_payload" in value or "structured_payload" in value:
                return value
            return {"structured_payload": value}
        raise TypeError("sink_payload must be either a string or an object.")

    @model_validator(mode="after")
    def _validate_exclusive_payload(self) -> "SinkPayloadEnvelope":
        if self.text_payload is not None and self.structured_payload is not None:
            raise ValueError("sink_payload cannot contain both text_payload and structured_payload.")
        return self

    def to_runtime_payload(self) -> str | JsonObject | None:
        if self.structured_payload is not None:
            return self.structured_payload
        if self.text_payload is not None:
            return self.text_payload
        return None


class RuntimeExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_query: str = Field(...)
    preferred_tool_name: str | None = None
    source_type: str = "user_query"
    source_content: str | None = None
    source_metadata: SourceMetadata = Field(default_factory=SourceMetadata)
    user_authorized: bool = False
    sink_payload: SinkPayloadEnvelope | None = None
    sink_metadata: SinkMetadata = Field(default_factory=SinkMetadata)


class EvaluationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ablation_name: str = "baseline"
    output_dir: str | None = None
    emit_failure_report: bool = False


class FailureReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_results_path: str
    summary_path: str
    output_dir: str | None = None


class AblationReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    output_json: str | None = None
    output_csv: str | None = None


class PlotAblationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_json: str = "data/eval_outputs/ablation_summary_report.json"
    output_dir: str = "data/eval_outputs/figures"
