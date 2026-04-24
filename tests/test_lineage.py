from __future__ import annotations

import json

from app.core.models import TrustLabel
from app.mcp.lineage import LineageEvent, RequestLineageGraph


def test_lineage_graph_adds_events_and_edges() -> None:
    graph = RequestLineageGraph(root_user_request_id="root")
    parent = graph.add_event(
        LineageEvent(
            request_id="root",
            root_user_request_id="root",
            event_type="mcp_request",
            feature="tools",
            source_role="client",
        )
    )
    child = graph.add_event(
        LineageEvent(
            request_id="child",
            parent_request_id="root",
            root_user_request_id="root",
            event_type="tool_invocation",
            feature="tools",
            source_role="server",
        )
    )
    edge = graph.add_edge(from_event_id=parent.event_id, to_event_id=child.event_id, relation="invokes")

    assert graph.events[parent.event_id] == parent
    assert graph.events[child.event_id] == child
    assert graph.edges == [edge]


def test_find_ancestors_and_untrusted_ancestor_detection() -> None:
    graph = RequestLineageGraph(root_user_request_id="root")
    parent = graph.add_event(
        LineageEvent(
            request_id="root",
            root_user_request_id="root",
            event_type="mcp_request",
            trust_label=TrustLabel.UNTRUSTED,
        )
    )
    child = graph.add_event(
        LineageEvent(
            request_id="sink",
            parent_request_id="root",
            root_user_request_id="root",
            event_type="sink_output",
        )
    )
    graph.add_edge(from_event_id=parent.event_id, to_event_id=child.event_id, relation="produces_sink_payload")

    ancestors = graph.find_ancestors(child.event_id)
    assert [item.event_id for item in ancestors] == [parent.event_id]
    assert graph.has_untrusted_ancestor(child.event_id) is True
    assert graph.sink_payload_from_untrusted_source(child.event_id) is True


def test_has_untrusted_ancestor_returns_false_without_untrusted_parent() -> None:
    graph = RequestLineageGraph(root_user_request_id="root")
    parent = graph.add_event(
        LineageEvent(
            request_id="root",
            root_user_request_id="root",
            event_type="mcp_request",
            trust_label=TrustLabel.TRUSTED,
        )
    )
    child = graph.add_event(
        LineageEvent(
            request_id="sample",
            parent_request_id="root",
            root_user_request_id="root",
            event_type="sampling_request",
        )
    )
    graph.add_edge(from_event_id=parent.event_id, to_event_id=child.event_id, relation="samples_from")

    assert graph.has_untrusted_ancestor(child.event_id) is False
    assert graph.sampling_traces_to_root(child.event_id) is True


def test_lineage_summary_is_json_serializable() -> None:
    graph = RequestLineageGraph(root_user_request_id="root")
    event = graph.add_event(
        LineageEvent(
            request_id="root",
            root_user_request_id="root",
            event_type="mcp_request",
        )
    )

    summary = graph.summarize()
    assert summary["root_user_request_id"] == "root"
    assert summary["event_count"] == 1
    assert summary["edge_count"] == 0
    assert summary["events"][0]["event_id"] == event.event_id
    assert summary["edges"] == []
    json.dumps(summary)
