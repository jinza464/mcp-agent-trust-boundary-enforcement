"""Strict Tool Identity Registry for trust-boundary enforcement research and prototyping."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import IntegrityState, RiskLevel, ToolMetadata, ToolSnapshot, TrustLabel


class ChangeCategory(str):
    """Canonical change categories for identity and drift analysis."""

    DESCRIPTIVE_CHANGE = "descriptive_change"
    SCHEMA_CHANGE = "schema_change"
    SERVER_RELOCATION = "server_relocation"
    NAMESPACE_CONFLICT = "namespace_conflict"
    ROLLBACK = "rollback"
    SUSPICIOUS_CAPABILITY_DRIFT = "suspicious_capability_drift"


class ObservationKind(str):
    """Observation classification for historical traceability."""

    FIRST_OBSERVATION = "first_observation"
    DUPLICATE_OBSERVATION = "duplicate_observation"
    MEANINGFUL_UPDATE = "meaningful_update"
    SUSPICIOUS_UPDATE = "suspicious_update"


class ChangeDetectionResult(BaseModel):
    """Structured identity drift result with stronger change typing semantics."""

    model_config = ConfigDict(extra="forbid")

    changed: bool = Field(..., description="Whether any tracked identity field changed.")
    changed_fields: list[str] = Field(
        default_factory=list,
        description="Backward-compatible changed field names.",
    )
    change_categories: list[str] = Field(
        default_factory=list,
        description="Typed change categories (descriptive/schema/rollback/etc.).",
    )
    severity: RiskLevel = Field(..., description="Severity level derived from change categories.")
    drift_summary: str = Field(..., description="Human-readable drift summary.")
    suspicious: bool = Field(..., description="Whether drift is considered suspicious.")
    old_values: dict[str, str] = Field(default_factory=dict, description="Previous identity values.")
    new_values: dict[str, str] = Field(default_factory=dict, description="New identity values.")


class RegisterToolResult(BaseModel):
    """Structured registration outcome with observation-class and persistence metadata."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(
        ...,
        description=(
            "One of: registered_new, registered_duplicate, registered_update, "
            "registered_suspicious_update."
        ),
    )
    tool_name: str = Field(..., description="Tool name.")
    server_origin: str = Field(..., description="Server origin used for namespacing.")
    tool_identity: str = Field(..., description="Logical tool identity.")
    namespace: str = Field(..., description="Resolved namespace/provider scope.")

    is_new: bool = Field(..., description="Whether this is the first registration for this identity+origin.")
    is_duplicate: bool = Field(..., description="Whether identity fields are unchanged from previous snapshot.")
    observation_kind: str = Field(..., description="Observation kind for this registration event.")

    first_seen_at: datetime = Field(..., description="First observation timestamp for this identity+origin.")
    last_seen_at: datetime = Field(..., description="Last observation timestamp for this identity+origin.")
    observation_count: int = Field(..., ge=1, description="Total observations for this identity+origin.")

    snapshot: ToolSnapshot = Field(..., description="Persisted snapshot after registration.")
    previous_snapshot: ToolSnapshot | None = Field(
        default=None,
        description="Previous latest snapshot for this identity+origin.",
    )
    change_result: ChangeDetectionResult | None = Field(
        default=None,
        description="Typed drift result against previous snapshot when available.",
    )


class ToolIdentityTrack(BaseModel):
    """Persistent history state for one (tool_identity, server_origin) pair."""

    model_config = ConfigDict(extra="forbid")

    tool_identity: str
    tool_name: str
    server_origin: str
    namespace: str
    provider_identity: str
    first_seen_at: datetime
    last_seen_at: datetime
    observation_count: int
    snapshots: list[ToolSnapshot] = Field(default_factory=list)
    observation_history: list[str] = Field(default_factory=list)


class ToolRegistry:
    """Tool Identity Registry with strict drift semantics and compatibility APIs."""

    def __init__(self) -> None:
        self._tracks_by_identity_origin: dict[str, ToolIdentityTrack] = {}

    @staticmethod
    def _hash_payload(payload: Any) -> str:
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
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
        # Compatibility fallback for legacy metadata without formal schema fields.
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
        payload = {
            "input_schema_hash": cls._compute_input_schema_hash(metadata),
            "output_schema_hash": cls._compute_output_schema_hash(metadata),
        }
        return cls._hash_payload(payload)

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
    def _name_origin_key(tool_name: str, server_origin: str) -> str:
        return f"{tool_name}::{server_origin}"

    @classmethod
    def _build_snapshot(cls, metadata: ToolMetadata) -> ToolSnapshot:
        identity = cls._build_identity_record(metadata)
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
            runtime_context={},
        )

    @staticmethod
    def _parse_semver(version: str) -> tuple[int, int, int] | None:
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version.strip())
        if not match:
            return None
        return int(match.group(1)), int(match.group(2)), int(match.group(3))

    @classmethod
    def _severity_from_categories(cls, categories: list[str]) -> RiskLevel:
        if not categories:
            return RiskLevel.LOW
        if any(cat in categories for cat in [ChangeCategory.ROLLBACK, ChangeCategory.NAMESPACE_CONFLICT]):
            return RiskLevel.CRITICAL
        if any(cat in categories for cat in [ChangeCategory.SERVER_RELOCATION, ChangeCategory.SUSPICIOUS_CAPABILITY_DRIFT]):
            return RiskLevel.HIGH
        if any(cat in categories for cat in [ChangeCategory.SCHEMA_CHANGE]):
            return RiskLevel.HIGH
        if any(cat in categories for cat in [ChangeCategory.DESCRIPTIVE_CHANGE]):
            return RiskLevel.MEDIUM
        return RiskLevel.MEDIUM

    @classmethod
    def _drift_summary(cls, categories: list[str]) -> str:
        if not categories:
            return "No meaningful drift detected (duplicate observation)."
        return "Detected drift categories: " + ", ".join(categories) + "."

    def _detect_namespace_conflict_global(self, new_metadata: ToolMetadata) -> bool:
        """Detect if same tool name appears under same origin with different namespace/provider."""
        new_name = new_metadata.name
        new_origin = self._normalize_server_origin(new_metadata)
        new_namespace = self._normalize_namespace(new_metadata)
        for track in self._tracks_by_identity_origin.values():
            if track.tool_name == new_name and track.server_origin == new_origin and track.namespace != new_namespace:
                return True
        return False

    def detect_changes(self, old_snapshot: ToolSnapshot, new_metadata: ToolMetadata) -> ChangeDetectionResult:
        """Compare identity fields and emit typed drift categories with severity."""
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
        categories: list[str] = []

        if "description_hash" in changed_fields:
            categories.append(ChangeCategory.DESCRIPTIVE_CHANGE)

        if "input_schema_hash" in changed_fields or "output_schema_hash" in changed_fields or "schema_hash" in changed_fields:
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

        # Backward compatibility: keep old public changed_fields names.
        compat_changed_fields = sorted(
            {
                *(
                    ["description_hash"] if ChangeCategory.DESCRIPTIVE_CHANGE in categories else []
                ),
                *(
                    ["schema_hash"] if ChangeCategory.SCHEMA_CHANGE in categories else []
                ),
                *(
                    ["server_origin"] if ChangeCategory.SERVER_RELOCATION in categories else []
                ),
                *(
                    ["version"] if ChangeCategory.ROLLBACK in categories else []
                ),
                *(
                    ["namespace", "provider_identity"]
                    if ChangeCategory.NAMESPACE_CONFLICT in categories
                    else []
                ),
                *(
                    ["capabilities"] if ChangeCategory.SUSPICIOUS_CAPABILITY_DRIFT in categories else []
                ),
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

    def register_tool(self, metadata: ToolMetadata) -> RegisterToolResult:
        """Register metadata observation with strict identity/drift semantics."""
        now = datetime.now(UTC)
        tool_identity = self._normalize_tool_identity(metadata)
        server_origin = self._normalize_server_origin(metadata)
        namespace = self._normalize_namespace(metadata)

        track_key = self._identity_origin_key(tool_identity, server_origin)
        new_snapshot = self._build_snapshot(metadata)

        track = self._tracks_by_identity_origin.get(track_key)

        if track is None:
            conflict = self._detect_namespace_conflict_global(metadata)
            track = ToolIdentityTrack(
                tool_identity=tool_identity,
                tool_name=metadata.name,
                server_origin=server_origin,
                namespace=namespace,
                provider_identity=self._normalize_provider_identity(metadata),
                first_seen_at=now,
                last_seen_at=now,
                observation_count=1,
                snapshots=[new_snapshot],
                observation_history=[
                    ObservationKind.SUSPICIOUS_UPDATE if conflict else ObservationKind.FIRST_OBSERVATION
                ],
            )
            self._tracks_by_identity_origin[track_key] = track

            if conflict:
                conflict_result = ChangeDetectionResult(
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
                    status="registered_suspicious_update",
                    tool_name=metadata.name,
                    server_origin=server_origin,
                    tool_identity=tool_identity,
                    namespace=namespace,
                    is_new=True,
                    is_duplicate=False,
                    observation_kind=ObservationKind.SUSPICIOUS_UPDATE,
                    first_seen_at=track.first_seen_at,
                    last_seen_at=track.last_seen_at,
                    observation_count=track.observation_count,
                    snapshot=new_snapshot,
                    previous_snapshot=None,
                    change_result=conflict_result,
                )

            return RegisterToolResult(
                status="registered_new",
                tool_name=metadata.name,
                server_origin=server_origin,
                tool_identity=tool_identity,
                namespace=namespace,
                is_new=True,
                is_duplicate=False,
                observation_kind=ObservationKind.FIRST_OBSERVATION,
                first_seen_at=track.first_seen_at,
                last_seen_at=track.last_seen_at,
                observation_count=track.observation_count,
                snapshot=new_snapshot,
                previous_snapshot=None,
                change_result=None,
            )

        previous_snapshot = track.snapshots[-1]
        change_result = self.detect_changes(previous_snapshot, metadata)

        track.last_seen_at = now
        track.observation_count += 1
        track.snapshots.append(new_snapshot)

        if not change_result.changed:
            observation_kind = ObservationKind.DUPLICATE_OBSERVATION
            status = "registered_duplicate"
            is_duplicate = True
        elif change_result.suspicious:
            observation_kind = ObservationKind.SUSPICIOUS_UPDATE
            status = "registered_suspicious_update"
            is_duplicate = False
        else:
            observation_kind = ObservationKind.MEANINGFUL_UPDATE
            status = "registered_update"
            is_duplicate = False

        track.observation_history.append(observation_kind)

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
        )

    def get_tool_snapshot(self, tool_name: str, server_origin: str) -> ToolSnapshot | None:
        """Get latest snapshot for a tool name and server origin (compatibility API)."""
        latest_track: ToolIdentityTrack | None = None
        for track in self._tracks_by_identity_origin.values():
            if track.tool_name == tool_name and track.server_origin == server_origin:
                if latest_track is None or track.last_seen_at > latest_track.last_seen_at:
                    latest_track = track
        if latest_track is None or not latest_track.snapshots:
            return None
        return latest_track.snapshots[-1]

    def get_identity_track(self, tool_identity: str, server_origin: str) -> ToolIdentityTrack | None:
        """Get full identity track for advanced analysis interfaces."""
        return self._tracks_by_identity_origin.get(self._identity_origin_key(tool_identity, server_origin))

    def save_to_json(self, file_path: str | Path) -> Path:
        """Persist full registry state with industrial traceability metadata."""
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
        """Load registry state; supports both new track format and legacy snapshot map."""
        path = Path(file_path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        registry = cls()

        if "tracks_by_identity_origin" in payload:
            for key, raw_track in payload.get("tracks_by_identity_origin", {}).items():
                registry._tracks_by_identity_origin[key] = ToolIdentityTrack.model_validate(raw_track)
            return registry

        # Legacy compatibility loader for old format: {"snapshots_by_key": {"name::origin": [snapshots...]}}
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
                snapshots=snapshots,
                observation_history=[ObservationKind.FIRST_OBSERVATION]
                + [ObservationKind.MEANINGFUL_UPDATE] * (len(snapshots) - 1),
            )
            registry._tracks_by_identity_origin[track_key] = track

        return registry
