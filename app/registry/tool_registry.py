"""Strict Tool Identity Registry for trust-boundary enforcement research and prototyping.

Phase-1 revision goals:
- preserve current benchmark behavior
- strengthen type discipline for change and observation categories
- keep JSON persistence backward-compatible
- make track/history state easier to consume downstream
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import IntegrityState, RiskLevel, ToolMetadata, ToolSnapshot, TrustLabel
from app.mcp.protocol_models import RequestLineage


class ChangeCategory(str, Enum):
    DESCRIPTIVE_CHANGE = "descriptive_change"
    SCHEMA_CHANGE = "schema_change"
    SERVER_RELOCATION = "server_relocation"
    NAMESPACE_CONFLICT = "namespace_conflict"
    ROLLBACK = "rollback"
    SUSPICIOUS_CAPABILITY_DRIFT = "suspicious_capability_drift"


class ObservationKind(str, Enum):
    FIRST_OBSERVATION = "first_observation"
    DUPLICATE_OBSERVATION = "duplicate_observation"
    MEANINGFUL_UPDATE = "meaningful_update"
    SUSPICIOUS_UPDATE = "suspicious_update"


class ChangeDetectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    changed: bool
    changed_fields: list[str] = Field(default_factory=list)
    change_categories: list[ChangeCategory] = Field(default_factory=list)
    severity: RiskLevel
    drift_summary: str
    suspicious: bool
    old_values: dict[str, str] = Field(default_factory=dict)
    new_values: dict[str, str] = Field(default_factory=dict)


class RegisterToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    tool_name: str
    server_origin: str
    tool_identity: str
    namespace: str
    is_new: bool
    is_duplicate: bool
    observation_kind: ObservationKind
    first_seen_at: datetime
    last_seen_at: datetime
    observation_count: int = Field(..., ge=1)
    snapshot: ToolSnapshot
    previous_snapshot: ToolSnapshot | None = None
    change_result: ChangeDetectionResult | None = None
    request_lineage: RequestLineage | None = None
    last_seen_request_id: str | None = None
    last_seen_session_id: str | None = None
    feature_scope: str | None = None
    lineage_root_request_id: str | None = None


class ToolIdentityTrack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_identity: str
    tool_name: str
    server_origin: str
    namespace: str
    provider_identity: str
    first_seen_at: datetime
    last_seen_at: datetime
    observation_count: int
    suspicious_update_count: int = 0
    last_seen_request_id: str | None = None
    last_seen_session_id: str | None = None
    feature_scope: str | None = None
    lineage_root_request_id: str | None = None
    drift_history_summary: dict[str, Any] = Field(
        default_factory=lambda: {
            "duplicate_observation_count": 0,
            "benign_update_count": 0,
            "suspicious_update_count": 0,
            "recent_change_categories": [],
            "last_observation_kind": ObservationKind.FIRST_OBSERVATION.value,
        }
    )
    snapshots: list[ToolSnapshot] = Field(default_factory=list)
    observation_history: list[str] = Field(default_factory=list)


class ToolRegistry:
    def __init__(self) -> None:
        self._tracks_by_identity_origin: dict[str, ToolIdentityTrack] = {}

    @staticmethod
    def _hash_payload(payload: Any) -> str:
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_server_origin(metadata: ToolMetadata) -> str:
        return metadata.server_origin or metadata.source_uri or "unknown"

    @staticmethod
    def _normalize_namespace(metadata: ToolMetadata) -> str:
        return metadata.namespace or metadata.provider_identity or metadata.provider

    @staticmethod
    def _normalize_provider_identity(metadata: ToolMetadata) -> str:
        return metadata.provider_identity or metadata.provider

    @staticmethod
    def _normalize_tool_identity(metadata: ToolMetadata) -> str:
        return metadata.tool_identity or metadata.tool_id

    @classmethod
    def _compute_description_hash(cls, metadata: ToolMetadata) -> str:
        return cls._hash_payload(metadata.description)

    @classmethod
    def _compute_input_schema_hash(cls, metadata: ToolMetadata) -> str:
        if metadata.input_schema is not None:
            return cls._hash_payload(metadata.input_schema)
        fallback = {
            "capabilities": sorted(cap.value for cap in metadata.capabilities),
            "tags": sorted(metadata.tags),
            "kind": "legacy_input_proxy",
        }
        return cls._hash_payload(fallback)

    @classmethod
    def _compute_output_schema_hash(cls, metadata: ToolMetadata) -> str:
        if metadata.output_schema is not None:
            return cls._hash_payload(metadata.output_schema)
        fallback = {
            "invocation_constraints": metadata.invocation_constraints or {},
            "kind": "legacy_output_proxy",
        }
        return cls._hash_payload(fallback)

    @classmethod
    def _compute_schema_hash(cls, metadata: ToolMetadata) -> str:
        return cls._hash_payload(
            {
                "input_schema_hash": cls._compute_input_schema_hash(metadata),
                "output_schema_hash": cls._compute_output_schema_hash(metadata),
            }
        )

    @staticmethod
    def _capability_signature(metadata: ToolMetadata) -> str:
        return ",".join(sorted(cap.value for cap in metadata.capabilities))

    @classmethod
    def _build_identity_record(cls, metadata: ToolMetadata) -> dict[str, str]:
        return {
            "description_hash": cls._compute_description_hash(metadata),
            "input_schema_hash": cls._compute_input_schema_hash(metadata),
            "output_schema_hash": cls._compute_output_schema_hash(metadata),
            "schema_hash": cls._compute_schema_hash(metadata),
            "server_origin": cls._normalize_server_origin(metadata),
            "namespace": cls._normalize_namespace(metadata),
            "provider_identity": cls._normalize_provider_identity(metadata),
            "version": metadata.version,
            "capabilities": cls._capability_signature(metadata),
            "tool_identity": cls._normalize_tool_identity(metadata),
            "tool_name": metadata.name,
        }

    @staticmethod
    def _identity_origin_key(tool_identity: str, server_origin: str) -> str:
        return f"{tool_identity}::{server_origin}"

    @staticmethod
    def _base_drift_history_summary() -> dict[str, Any]:
        return {
            "duplicate_observation_count": 0,
            "benign_update_count": 0,
            "suspicious_update_count": 0,
            "recent_change_categories": [],
            "last_observation_kind": ObservationKind.FIRST_OBSERVATION.value,
        }

    @classmethod
    def _update_drift_history_summary(
        cls,
        summary: dict[str, Any] | None,
        *,
        observation_kind: ObservationKind,
        change_categories: list[ChangeCategory] | None = None,
    ) -> dict[str, Any]:
        base = dict(cls._base_drift_history_summary())
        if isinstance(summary, dict):
            base.update(summary)
        if observation_kind == ObservationKind.DUPLICATE_OBSERVATION:
            base["duplicate_observation_count"] = int(base.get("duplicate_observation_count", 0)) + 1
        elif observation_kind == ObservationKind.MEANINGFUL_UPDATE:
            base["benign_update_count"] = int(base.get("benign_update_count", 0)) + 1
        elif observation_kind == ObservationKind.SUSPICIOUS_UPDATE:
            base["suspicious_update_count"] = int(base.get("suspicious_update_count", 0)) + 1
        recent = list(base.get("recent_change_categories", [])) if isinstance(base.get("recent_change_categories"), list) else []
        if change_categories:
            recent.extend(item.value for item in change_categories)
            recent = recent[-12:]
        base["recent_change_categories"] = recent
        base["last_observation_kind"] = observation_kind.value
        return base

    @classmethod
    def _build_snapshot(
        cls,
        metadata: ToolMetadata,
        request_lineage: RequestLineage | None = None,
        session_id: str | None = None,
    ) -> ToolSnapshot:
        identity = cls._build_identity_record(metadata)
        runtime_context: dict[str, str] = {"schema_hash": identity["schema_hash"]}
        if request_lineage is not None:
            runtime_context.update(
                {
                    "request_id": request_lineage.request_id,
                    "session_id": (session_id or request_lineage.session_id or ""),
                    "parent_request_id": request_lineage.parent_request_id or "",
                    "lineage_root_request_id": request_lineage.root_user_request_id,
                    "lineage_source_role": request_lineage.source_role,
                    "feature_scope": request_lineage.feature,
                    "lineage_trust_label": request_lineage.trust_label.value,
                }
            )
        elif session_id is not None:
            runtime_context["session_id"] = session_id
        return ToolSnapshot(
            snapshot_id=f"snap-{uuid4().hex}",
            tool=metadata,
            captured_at=datetime.now(UTC),
            description_hash=identity["description_hash"],
            input_schema_hash=identity["input_schema_hash"],
            output_schema_hash=identity["output_schema_hash"],
            server_origin=identity["server_origin"],
            observed_version=metadata.version,
            integrity_state=IntegrityState.UNKNOWN,
            trust_label=TrustLabel.UNKNOWN,
            runtime_context=runtime_context,
        )

    @staticmethod
    def _parse_semver(version: str) -> tuple[int, int, int] | None:
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version.strip())
        if not match:
            return None
        return int(match.group(1)), int(match.group(2)), int(match.group(3))

    @classmethod
    def _severity_from_categories(cls, categories: list[ChangeCategory]) -> RiskLevel:
        if not categories:
            return RiskLevel.LOW
        if ChangeCategory.ROLLBACK in categories or ChangeCategory.NAMESPACE_CONFLICT in categories:
            return RiskLevel.CRITICAL
        if (
            ChangeCategory.SERVER_RELOCATION in categories
            or ChangeCategory.SUSPICIOUS_CAPABILITY_DRIFT in categories
            or ChangeCategory.SCHEMA_CHANGE in categories
        ):
            return RiskLevel.HIGH
        if ChangeCategory.DESCRIPTIVE_CHANGE in categories:
            return RiskLevel.MEDIUM
        return RiskLevel.MEDIUM

    @staticmethod
    def _drift_summary(categories: list[ChangeCategory]) -> str:
        if not categories:
            return "No meaningful drift detected (duplicate observation)."
        return "Detected drift categories: " + ", ".join(item.value for item in categories) + "."

    def _detect_namespace_conflict_global(self, new_metadata: ToolMetadata) -> bool:
        new_name = new_metadata.name
        new_origin = self._normalize_server_origin(new_metadata)
        new_namespace = self._normalize_namespace(new_metadata)
        for track in self._tracks_by_identity_origin.values():
            if track.tool_name == new_name and track.server_origin == new_origin and track.namespace != new_namespace:
                return True
        return False

    def detect_changes(self, old_snapshot: ToolSnapshot, new_metadata: ToolMetadata) -> ChangeDetectionResult:
        old_values = {
            "description_hash": old_snapshot.description_hash or self._compute_description_hash(old_snapshot.tool),
            "input_schema_hash": old_snapshot.input_schema_hash or self._compute_input_schema_hash(old_snapshot.tool),
            "output_schema_hash": old_snapshot.output_schema_hash or self._compute_output_schema_hash(old_snapshot.tool),
            "schema_hash": self._hash_payload(
                {
                    "input_schema_hash": old_snapshot.input_schema_hash or self._compute_input_schema_hash(old_snapshot.tool),
                    "output_schema_hash": old_snapshot.output_schema_hash or self._compute_output_schema_hash(old_snapshot.tool),
                }
            ),
            "server_origin": old_snapshot.server_origin or self._normalize_server_origin(old_snapshot.tool),
            "namespace": old_snapshot.tool.namespace or self._normalize_namespace(old_snapshot.tool),
            "provider_identity": old_snapshot.tool.provider_identity or self._normalize_provider_identity(old_snapshot.tool),
            "version": old_snapshot.observed_version or old_snapshot.tool.version,
            "capabilities": self._capability_signature(old_snapshot.tool),
            "tool_identity": old_snapshot.tool.tool_identity or self._normalize_tool_identity(old_snapshot.tool),
            "tool_name": old_snapshot.tool.name,
        }
        new_values = self._build_identity_record(new_metadata)
        changed_fields = [key for key in old_values if old_values[key] != new_values[key]]
        categories: list[ChangeCategory] = []
        if "description_hash" in changed_fields:
            categories.append(ChangeCategory.DESCRIPTIVE_CHANGE)
        if {"input_schema_hash", "output_schema_hash", "schema_hash"}.intersection(changed_fields):
            categories.append(ChangeCategory.SCHEMA_CHANGE)
        if "server_origin" in changed_fields:
            categories.append(ChangeCategory.SERVER_RELOCATION)
        if "namespace" in changed_fields or "provider_identity" in changed_fields:
            categories.append(ChangeCategory.NAMESPACE_CONFLICT)
        old_semver = self._parse_semver(old_values["version"])
        new_semver = self._parse_semver(new_values["version"])
        if old_semver and new_semver and new_semver < old_semver:
            categories.append(ChangeCategory.ROLLBACK)
        if "capabilities" in changed_fields and old_values["version"] == new_values["version"]:
            categories.append(ChangeCategory.SUSPICIOUS_CAPABILITY_DRIFT)

        compat_changed_fields = sorted(
            {
                *(["description_hash"] if ChangeCategory.DESCRIPTIVE_CHANGE in categories else []),
                *(["schema_hash"] if ChangeCategory.SCHEMA_CHANGE in categories else []),
                *(["server_origin"] if ChangeCategory.SERVER_RELOCATION in categories else []),
                *(["version"] if ChangeCategory.ROLLBACK in categories else []),
                *(["namespace", "provider_identity"] if ChangeCategory.NAMESPACE_CONFLICT in categories else []),
                *(["capabilities"] if ChangeCategory.SUSPICIOUS_CAPABILITY_DRIFT in categories else []),
            }
        )
        severity = self._severity_from_categories(categories)
        suspicious = severity in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        return ChangeDetectionResult(
            changed=bool(categories),
            changed_fields=compat_changed_fields,
            change_categories=categories,
            severity=severity,
            drift_summary=self._drift_summary(categories),
            suspicious=suspicious,
            old_values=old_values,
            new_values=new_values,
        )

    def register_tool(
        self,
        metadata: ToolMetadata,
        *,
        request_lineage: RequestLineage | None = None,
        session_id: str | None = None,
    ) -> RegisterToolResult:
        now = datetime.now(UTC)
        tool_identity = self._normalize_tool_identity(metadata)
        server_origin = self._normalize_server_origin(metadata)
        namespace = self._normalize_namespace(metadata)
        track_key = self._identity_origin_key(tool_identity, server_origin)
        observed_request_id = request_lineage.request_id if request_lineage is not None else None
        observed_session_id = session_id or (request_lineage.session_id if request_lineage is not None else None)
        observed_feature_scope = request_lineage.feature if request_lineage is not None else None
        observed_lineage_root = request_lineage.root_user_request_id if request_lineage is not None else None

        new_snapshot = self._build_snapshot(
            metadata,
            request_lineage=request_lineage,
            session_id=observed_session_id,
        )
        track = self._tracks_by_identity_origin.get(track_key)

        if track is None:
            conflict = self._detect_namespace_conflict_global(metadata)
            observation_kind = ObservationKind.SUSPICIOUS_UPDATE if conflict else ObservationKind.FIRST_OBSERVATION
            initial_categories = [ChangeCategory.NAMESPACE_CONFLICT] if conflict else []
            track = ToolIdentityTrack(
                tool_identity=tool_identity,
                tool_name=metadata.name,
                server_origin=server_origin,
                namespace=namespace,
                provider_identity=self._normalize_provider_identity(metadata),
                first_seen_at=now,
                last_seen_at=now,
                observation_count=1,
                suspicious_update_count=1 if conflict else 0,
                last_seen_request_id=observed_request_id,
                last_seen_session_id=observed_session_id,
                feature_scope=observed_feature_scope,
                lineage_root_request_id=observed_lineage_root,
                drift_history_summary=self._update_drift_history_summary(None, observation_kind=observation_kind, change_categories=initial_categories),
                snapshots=[new_snapshot],
                observation_history=[observation_kind.value],
            )
            self._tracks_by_identity_origin[track_key] = track
            change_result = None
            if conflict:
                change_result = ChangeDetectionResult(
                    changed=True,
                    changed_fields=["namespace", "provider_identity"],
                    change_categories=[ChangeCategory.NAMESPACE_CONFLICT],
                    severity=RiskLevel.CRITICAL,
                    drift_summary="Detected namespace conflict for same tool name and server origin.",
                    suspicious=True,
                    old_values={},
                    new_values=self._build_identity_record(metadata),
                )
            return RegisterToolResult(
                status="registered_suspicious_update" if conflict else "registered_new",
                tool_name=metadata.name,
                server_origin=server_origin,
                tool_identity=tool_identity,
                namespace=namespace,
                is_new=True,
                is_duplicate=False,
                observation_kind=observation_kind,
                first_seen_at=track.first_seen_at,
                last_seen_at=track.last_seen_at,
                observation_count=track.observation_count,
                snapshot=new_snapshot,
                previous_snapshot=None,
                change_result=change_result,
                request_lineage=request_lineage,
                last_seen_request_id=track.last_seen_request_id,
                last_seen_session_id=track.last_seen_session_id,
                feature_scope=track.feature_scope,
                lineage_root_request_id=track.lineage_root_request_id,
            )

        previous_snapshot = track.snapshots[-1]
        change_result = self.detect_changes(previous_snapshot, metadata)
        track.last_seen_at = now
        track.observation_count += 1
        track.snapshots.append(new_snapshot)
        if request_lineage is not None:
            track.last_seen_request_id = observed_request_id
            track.last_seen_session_id = observed_session_id
            track.feature_scope = observed_feature_scope
            track.lineage_root_request_id = observed_lineage_root
        elif observed_session_id is not None:
            track.last_seen_session_id = observed_session_id

        if not change_result.changed:
            observation_kind = ObservationKind.DUPLICATE_OBSERVATION
            status = "registered_duplicate"
            is_duplicate = True
        elif change_result.suspicious:
            observation_kind = ObservationKind.SUSPICIOUS_UPDATE
            status = "registered_suspicious_update"
            is_duplicate = False
            track.suspicious_update_count += 1
        else:
            observation_kind = ObservationKind.MEANINGFUL_UPDATE
            status = "registered_update"
            is_duplicate = False

        track.observation_history.append(observation_kind.value)
        track.drift_history_summary = self._update_drift_history_summary(
            track.drift_history_summary,
            observation_kind=observation_kind,
            change_categories=change_result.change_categories,
        )

        return RegisterToolResult(
            status=status,
            tool_name=metadata.name,
            server_origin=server_origin,
            tool_identity=tool_identity,
            namespace=namespace,
            is_new=False,
            is_duplicate=is_duplicate,
            observation_kind=observation_kind,
            first_seen_at=track.first_seen_at,
            last_seen_at=track.last_seen_at,
            observation_count=track.observation_count,
            snapshot=new_snapshot,
            previous_snapshot=previous_snapshot,
            change_result=change_result,
            request_lineage=request_lineage,
            last_seen_request_id=track.last_seen_request_id,
            last_seen_session_id=track.last_seen_session_id,
            feature_scope=track.feature_scope,
            lineage_root_request_id=track.lineage_root_request_id,
        )

    def get_tool_snapshot(self, tool_name: str, server_origin: str) -> ToolSnapshot | None:
        latest_track: ToolIdentityTrack | None = None
        for track in self._tracks_by_identity_origin.values():
            if track.tool_name == tool_name and track.server_origin == server_origin:
                if latest_track is None or track.last_seen_at > latest_track.last_seen_at:
                    latest_track = track
        if latest_track is None or not latest_track.snapshots:
            return None
        return latest_track.snapshots[-1]

    def get_identity_track(self, tool_identity: str, server_origin: str) -> ToolIdentityTrack | None:
        return self._tracks_by_identity_origin.get(self._identity_origin_key(tool_identity, server_origin))

    def save_to_json(self, file_path: str | Path) -> Path:
        path = Path(file_path)
        payload = {
            "tracks_by_identity_origin": {
                key: track.model_dump(mode="json")
                for key, track in self._tracks_by_identity_origin.items()
            }
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    @classmethod
    def load_from_json(cls, file_path: str | Path) -> ToolRegistry:
        path = Path(file_path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        registry = cls()
        if "tracks_by_identity_origin" in payload:
            for key, raw_track in payload.get("tracks_by_identity_origin", {}).items():
                track = ToolIdentityTrack.model_validate(raw_track)
                registry._tracks_by_identity_origin[key] = track
            return registry

        # legacy loader
        for name_origin_key, raw_snapshots in payload.get("snapshots_by_key", {}).items():
            snapshots = [ToolSnapshot.model_validate(item) for item in raw_snapshots]
            if not snapshots:
                continue
            latest = snapshots[-1]
            tool_identity = latest.tool.tool_identity or latest.tool.tool_id
            server_origin = latest.server_origin or latest.tool.server_origin or latest.tool.source_uri or "unknown"
            track_key = registry._identity_origin_key(tool_identity, server_origin)
            track = ToolIdentityTrack(
                tool_identity=tool_identity,
                tool_name=latest.tool.name,
                server_origin=server_origin,
                namespace=latest.tool.namespace or latest.tool.provider_identity or latest.tool.provider,
                provider_identity=latest.tool.provider_identity or latest.tool.provider,
                first_seen_at=snapshots[0].captured_at,
                last_seen_at=latest.captured_at,
                observation_count=len(snapshots),
                suspicious_update_count=0,
                last_seen_request_id=None,
                last_seen_session_id=None,
                feature_scope=None,
                lineage_root_request_id=None,
                snapshots=snapshots,
                observation_history=[ObservationKind.FIRST_OBSERVATION.value] + [ObservationKind.MEANINGFUL_UPDATE.value] * (len(snapshots) - 1),
            )
            registry._tracks_by_identity_origin[track_key] = track
        return registry
