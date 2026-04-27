from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.core.models import TrustLabel
from app.mcp.protocol_models import (
    ElicitationContext,
    McpRequestEnvelope,
    McpResponseEnvelope,
    RequestLineage,
    RootsExposureContext,
    SamplingRequestContext,
)


def _lineage() -> RequestLineage:
    return RequestLineage(
        request_id="req-child",
        parent_request_id="req-root",
        root_user_request_id="req-root",
        feature="sampling",
        source_role="server",
        trust_label=TrustLabel.UNTRUSTED,
        server_origin="https://server.example",
    )


def test_mcp_request_envelope_constructs_and_dumps_json() -> None:
    envelope = McpRequestEnvelope(
        request_id="req-1",
        session_id="sess-1",
        feature="tools",
        source_role="client",
        payload={"user_query": "search docs"},
    )

    dumped = envelope.model_dump(mode="json")
    assert dumped["request_id"] == "req-1"
    assert dumped["session_id"] == "sess-1"
    assert dumped["feature"] == "tools"
    assert dumped["payload"]["user_query"] == "search docs"
    json.dumps(dumped)


def test_mcp_response_envelope_constructs_with_ok_and_payload() -> None:
    response = McpResponseEnvelope(
        request_id="req-1",
        session_id="sess-1",
        feature="tools",
        source_role="server",
        ok=True,
        payload={"result": "ok"},
    )

    dumped = response.model_dump(mode="json")
    assert dumped["request_id"] == "req-1"
    assert dumped["session_id"] == "sess-1"
    assert dumped["feature"] == "tools"
    assert dumped["ok"] is True
    assert dumped["payload"]["result"] == "ok"


def test_request_lineage_expresses_core_identifiers_and_trust() -> None:
    lineage = _lineage()

    assert lineage.request_id == "req-child"
    assert lineage.parent_request_id == "req-root"
    assert lineage.root_user_request_id == "req-root"
    assert lineage.feature == "sampling"
    assert lineage.source_role == "server"
    assert lineage.trust_label == TrustLabel.UNTRUSTED


def test_sampling_context_links_sampling_to_root_request() -> None:
    context = SamplingRequestContext(
        request_lineage=_lineage(),
        model_hint="test-model",
        allowed_tools=["docs_search"],
        user_approved=False,
    )

    assert context.request_id == "req-child"
    assert context.parent_request_id == "req-root"
    assert context.root_user_request_id == "req-root"
    assert context.model_hint == "test-model"
    assert context.allowed_tools == ["docs_search"]
    assert context.user_approved is False
    dumped = context.model_dump(mode="json")
    assert dumped["request_id"] == "req-child"
    assert dumped["root_user_request_id"] == "req-root"
    assert dumped["allowed_tools"] == ["docs_search"]
    json.dumps(dumped)


def test_roots_exposure_context_expresses_roots_and_approval() -> None:
    context = RootsExposureContext(
        request_lineage=_lineage(),
        exposed_roots=["/workspace/project"],
        exposure_reason="tool requested project files",
        user_approved=True,
    )

    assert context.request_id == "req-child"
    assert context.root_user_request_id == "req-root"
    assert context.exposed_roots == ["/workspace/project"]
    assert context.user_approved is True
    assert context.server_origin == "https://server.example"
    dumped = context.model_dump(mode="json")
    assert dumped["exposed_roots"] == ["/workspace/project"]
    assert dumped["user_approved"] is True
    assert dumped["server_origin"] == "https://server.example"
    json.dumps(dumped)


def test_elicitation_context_expresses_fields_and_approval() -> None:
    context = ElicitationContext(
        request_lineage=_lineage(),
        elicitation_prompt="Please provide email.",
        requested_fields=["email"],
        user_approved=True,
    )

    assert context.request_id == "req-child"
    assert context.root_user_request_id == "req-root"
    assert context.elicitation_prompt == "Please provide email."
    assert context.requested_fields == ["email"]
    assert context.user_approved is True
    assert context.server_origin == "https://server.example"
    dumped = context.model_dump(mode="json")
    assert dumped["elicitation_prompt"] == "Please provide email."
    assert dumped["requested_fields"] == ["email"]
    assert dumped["user_approved"] is True
    json.dumps(dumped)


def test_protocol_models_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError):
        McpRequestEnvelope(
            request_id="req-1",
            session_id="sess-1",
            feature="tools",
            source_role="client",
            unexpected=True,
        )
