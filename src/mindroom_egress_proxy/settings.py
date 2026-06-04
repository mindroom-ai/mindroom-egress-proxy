"""Environment-backed runtime settings."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mindroom_egress_proxy.constants import (
    DEFAULT_MAX_TTL_SECONDS,
    DEFAULT_NAMESPACE,
    DEFAULT_POLICY_API_PORT,
    DEFAULT_PROXY_PORT,
    DEFAULT_SQUID_CONFIG_PATH,
    MAX_PORT,
)


class RuntimeSettings(BaseSettings):
    """Environment-backed runtime settings."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    proxy_port: int = Field(
        default=DEFAULT_PROXY_PORT, alias="MINDROOM_EGRESS_PROXY_LISTEN_PORT"
    )
    api_port: int = Field(
        default=DEFAULT_POLICY_API_PORT, alias="MINDROOM_APPROVED_EGRESS_API_PORT"
    )
    max_ttl_seconds: int = Field(
        default=DEFAULT_MAX_TTL_SECONDS,
        alias="MINDROOM_APPROVED_EGRESS_MAX_TTL_SECONDS",
    )
    pod_namespace: str | None = Field(default=None, alias="POD_NAMESPACE")
    egress_namespace: str = Field(
        default=DEFAULT_NAMESPACE, alias="MINDROOM_EGRESS_NAMESPACE"
    )
    allowlist_path: Path = Field(
        default=Path("/etc/mindroom-egress/allowed-domains.txt"),
        alias="MINDROOM_EGRESS_ALLOWLIST_PATH",
    )
    db_path: Path = Field(
        default=Path("/var/lib/mindroom-egress/grants.sqlite3"),
        alias="MINDROOM_EGRESS_DB_PATH",
    )
    bearer_token: SecretStr = Field(alias="MINDROOM_APPROVED_EGRESS_TOKEN")
    log_level: str = Field(default="info", alias="MINDROOM_APPROVED_EGRESS_LOG_LEVEL")
    squid_config_path: str = Field(
        default=DEFAULT_SQUID_CONFIG_PATH, alias="MINDROOM_EGRESS_SQUID_CONFIG_PATH"
    )

    @field_validator("proxy_port", "api_port")
    @classmethod
    def _validate_port(cls, value: int) -> int:
        if value <= 0 or value > MAX_PORT:
            raise ValueError("port must be between 1 and 65535")
        return value

    @field_validator("max_ttl_seconds")
    @classmethod
    def _validate_max_ttl(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("max TTL must be positive")
        return value

    @property
    def namespace(self) -> str:
        """Return the namespace used for worker metadata lookups."""
        return self.pod_namespace or self.egress_namespace
