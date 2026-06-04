"""SQLite-backed temporary egress grants."""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mindroom_egress_proxy.hostnames import canonical_hostname, normalize_reason

if TYPE_CHECKING:
    from collections.abc import Iterator


def _now() -> int:
    return int(time.time())


class GrantSubjectType(StrEnum):
    """Supported dynamic-grant subject scopes."""

    worker_key = "worker_key"
    agent = "agent"


class GrantCreateRequest(BaseModel):
    """Validated grant-create payload accepted by the policy API."""

    model_config = ConfigDict(extra="forbid")

    hostname: str
    subject_type: GrantSubjectType
    subject: str
    ttl_seconds: int = Field(gt=0)
    agent_name: str | None = None
    requester_id: str | None = None
    room_id: str | None = None
    thread_id: str | None = None
    approved_by: str | None = None
    reason: str | None = None

    @field_validator("hostname")
    @classmethod
    def _normalize_hostname(cls, value: str) -> str:
        return canonical_hostname(value)

    @field_validator("subject")
    @classmethod
    def _normalize_subject(cls, value: str) -> str:
        normalized = value.strip() if isinstance(value, str) else ""
        if not normalized:
            raise ValueError("subject must not be empty")
        return normalized

    @field_validator(
        "agent_name",
        "requester_id",
        "room_id",
        "thread_id",
        "approved_by",
    )
    @classmethod
    def _normalize_optional_string(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("reason")
    @classmethod
    def _normalize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_reason(value)


class GrantStore:
    """SQLite-backed temporary egress grant store."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS grants (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    subject_type TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    agent_name TEXT,
                    requester_id TEXT,
                    room_id TEXT,
                    thread_id TEXT,
                    requested_ttl_seconds INTEGER NOT NULL,
                    effective_ttl_seconds INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    approved_by TEXT,
                    reason TEXT,
                    status TEXT NOT NULL
                )
                """,
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_grants_check
                ON grants(hostname, status, expires_at)
                """,
            )

    def expire_old_grants(self, *, now: int | None = None) -> None:
        timestamp = _now() if now is None else int(now)
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE grants
                SET status = 'expired'
                WHERE status = 'active' AND expires_at <= ?
                """,
                (timestamp,),
            )

    def create_grant(
        self,
        *,
        hostname: str,
        subject_type: str,
        subject: str,
        agent_name: str | None,
        requester_id: str | None,
        room_id: str | None,
        thread_id: str | None,
        ttl_seconds: int,
        approved_by: str | None,
        reason: str | None,
        now: int | None = None,
    ) -> dict[str, Any]:
        host = canonical_hostname(hostname)
        if subject_type not in {"worker_key", "agent"}:
            raise ValueError("subject_type must be 'worker_key' or 'agent'")
        normalized_subject = subject.strip() if isinstance(subject, str) else ""
        if not normalized_subject:
            raise ValueError("subject must not be empty")
        requested_ttl = int(ttl_seconds)
        if requested_ttl <= 0:
            raise ValueError("ttl_seconds must be positive")
        created_at = _now() if now is None else int(now)
        normalized_reason = normalize_reason(reason) if reason is not None else None
        grant = {
            "id": uuid.uuid4().hex,
            "hostname": host,
            "subject_type": subject_type,
            "subject": normalized_subject,
            "agent_name": agent_name,
            "requester_id": requester_id,
            "room_id": room_id,
            "thread_id": thread_id,
            "requested_ttl_seconds": requested_ttl,
            "effective_ttl_seconds": requested_ttl,
            "created_at": created_at,
            "expires_at": created_at + requested_ttl,
            "approved_by": approved_by,
            "reason": normalized_reason,
            "status": "active",
        }
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO grants (
                    id,
                    hostname,
                    subject_type,
                    subject,
                    agent_name,
                    requester_id,
                    room_id,
                    thread_id,
                    requested_ttl_seconds,
                    effective_ttl_seconds,
                    created_at,
                    expires_at,
                    approved_by,
                    reason,
                    status
                )
                VALUES (
                    :id,
                    :hostname,
                    :subject_type,
                    :subject,
                    :agent_name,
                    :requester_id,
                    :room_id,
                    :thread_id,
                    :requested_ttl_seconds,
                    :effective_ttl_seconds,
                    :created_at,
                    :expires_at,
                    :approved_by,
                    :reason,
                    :status
                )
                """,
                grant,
            )
        return grant

    def has_grant(
        self,
        hostname: str,
        *,
        worker_key: str | None,
        agent_name: str | None,
        now: int | None = None,
    ) -> bool:
        host = canonical_hostname(hostname)
        timestamp = _now() if now is None else int(now)
        self.expire_old_grants(now=timestamp)
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT subject_type, subject
                FROM grants
                WHERE hostname = ? AND status = 'active' AND expires_at > ?
                """,
                (host, timestamp),
            ).fetchall()
        for row in rows:
            subject_type = row["subject_type"]
            subject = row["subject"]
            if (
                subject_type == "worker_key"
                and worker_key is not None
                and subject == worker_key
            ):
                return True
            if (
                subject_type == "agent"
                and agent_name is not None
                and subject == agent_name
            ):
                return True
        return False

    def list_active_grants(self, *, now: int | None = None) -> list[dict[str, Any]]:
        timestamp = _now() if now is None else int(now)
        self.expire_old_grants(now=timestamp)
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM grants
                WHERE status = 'active' AND expires_at > ?
                ORDER BY expires_at ASC
                """,
                (timestamp,),
            ).fetchall()
        return [dict(row) for row in rows]
