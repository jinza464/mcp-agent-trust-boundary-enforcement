from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

DEFAULT_APP_NAME: Final[str] = "trust-boundary-enforcement-platform"
DEFAULT_APP_VERSION: Final[str] = "0.5.0"
DEFAULT_ENVIRONMENT: Final[str] = "research"
DEFAULT_API_PREFIX: Final[str] = "/api/v1"
DEFAULT_OUTPUT_ROOT: Final[str] = "data/eval_outputs"
DEFAULT_CASE_PACK: Final[str] = "default_attack_cases"

ALLOWED_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"dev", "research", "service", "prod"})
TRUTHY_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
FALSY_VALUES: Final[frozenset[str]] = frozenset({"0", "false", "no", "off"})


def _read_env_raw(name: str) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    normalized = raw.strip()
    return normalized or None


def _read_env_str(name: str, default: str) -> str:
    return _read_env_raw(name) or default


def _parse_bool(raw: str, *, env_name: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in TRUTHY_VALUES:
        return True
    if normalized in FALSY_VALUES:
        return False
    accepted = sorted(TRUTHY_VALUES | FALSY_VALUES)
    raise ValueError(f"{env_name} must be one of {accepted} when provided.")


def _read_env_bool(name: str, default: bool) -> bool:
    raw = _read_env_raw(name)
    if raw is None:
        return default
    return _parse_bool(raw, env_name=name)


def _normalize_path_text(value: str) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(value.strip()))
    return Path(expanded)


def _read_env_path(name: str, default: str) -> Path:
    return _normalize_path_text(_read_env_str(name, default))


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    app_name: str = Field(default=DEFAULT_APP_NAME, min_length=1)
    app_version: str = Field(default=DEFAULT_APP_VERSION, min_length=1)
    environment: str = Field(default=DEFAULT_ENVIRONMENT)
    api_prefix: str = Field(default=DEFAULT_API_PREFIX)
    default_output_root: Path = Field(default=Path(DEFAULT_OUTPUT_ROOT))
    default_case_pack: str = Field(default=DEFAULT_CASE_PACK, min_length=1)
    enable_failure_report_export: bool = Field(default=True)
    enable_execution_figure_export: bool = Field(default=True)
    enable_audit_artifacts: bool = Field(default=True)

    @field_validator("app_name", "app_version", "default_case_pack")
    @classmethod
    def _validate_non_empty_strings(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("string field must be non-empty")
        return normalized

    @field_validator("environment")
    @classmethod
    def _validate_environment(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in ALLOWED_ENVIRONMENTS:
            raise ValueError(f"environment must be one of {sorted(ALLOWED_ENVIRONMENTS)}")
        return normalized

    @field_validator("api_prefix")
    @classmethod
    def _validate_api_prefix(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        return normalized.rstrip("/") or DEFAULT_API_PREFIX

    @field_validator("default_output_root", mode="before")
    @classmethod
    def _coerce_output_root_input(cls, value: object) -> object:
        if isinstance(value, str):
            return _normalize_path_text(value)
        return value

    @field_validator("default_output_root")
    @classmethod
    def _validate_output_root(cls, value: Path) -> Path:
        normalized = _normalize_path_text(str(value))
        if not str(normalized):
            raise ValueError("default_output_root must be a valid path")
        return normalized

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            app_name=_read_env_str("TBE_APP_NAME", DEFAULT_APP_NAME),
            app_version=_read_env_str("TBE_APP_VERSION", DEFAULT_APP_VERSION),
            environment=_read_env_str("TBE_ENV", DEFAULT_ENVIRONMENT),
            api_prefix=_read_env_str("TBE_API_PREFIX", DEFAULT_API_PREFIX),
            default_output_root=_read_env_path("TBE_OUTPUT_ROOT", DEFAULT_OUTPUT_ROOT),
            default_case_pack=_read_env_str("TBE_CASE_PACK", DEFAULT_CASE_PACK),
            enable_failure_report_export=_read_env_bool("TBE_ENABLE_FAILURE_REPORT", True),
            enable_execution_figure_export=_read_env_bool("TBE_ENABLE_EXECUTION_FIGURE", True),
            enable_audit_artifacts=_read_env_bool("TBE_ENABLE_AUDIT_ARTIFACTS", True),
        )


settings = Settings.from_env()
