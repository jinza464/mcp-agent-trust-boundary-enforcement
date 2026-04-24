from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, TypedDict, TypeAlias

from pydantic import JsonValue

ErrorDetails: TypeAlias = dict[str, JsonValue]


class ErrorPayload(TypedDict):
    """Stable API-facing error payload contract."""

    code: str
    message: str
    details: ErrorDetails


def _normalize_details(details: Mapping[str, JsonValue] | None) -> ErrorDetails:
    if details is None:
        return {}
    return {str(key): value for key, value in details.items()}


@dataclass(slots=True)
class PlatformError(Exception):
    """Base platform exception with a stable envelope consumed by API handlers."""

    code: str
    message: str
    status_code: int = 400
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_code = self.code.strip() if isinstance(self.code, str) else ""
        normalized_message = self.message.strip() if isinstance(self.message, str) else ""
        normalized_details = _normalize_details(self.details)

        self.code = normalized_code or "platform_error"
        self.message = normalized_message or "Platform error."
        self.details = normalized_details

        try:
            normalized_status_code = int(self.status_code)
        except (TypeError, ValueError):
            normalized_status_code = 400
        if not (100 <= normalized_status_code <= 599):
            normalized_status_code = 400
        self.status_code = normalized_status_code

        # Keep Exception string/introspection friendly.
        super().__init__(self.message)

    def to_dict(self) -> ErrorPayload:
        """Return the API-compatible error body."""
        return {
            "code": self.code,
            "message": self.message,
            "details": dict(self.details),
        }


class NotFoundError(PlatformError):
    """404 resource-not-found boundary error."""

    def __init__(self, message: str, *, details: ErrorDetails | None = None) -> None:
        super().__init__(code="not_found", message=message, status_code=404, details=details or {})


class ValidationError(PlatformError):
    """422 input/validation boundary error."""

    def __init__(self, message: str, *, details: ErrorDetails | None = None) -> None:
        super().__init__(code="validation_error", message=message, status_code=422, details=details or {})


class ServiceError(PlatformError):
    """500 internal service/runtime boundary error."""

    def __init__(self, message: str, *, details: ErrorDetails | None = None) -> None:
        super().__init__(code="service_error", message=message, status_code=500, details=details or {})
