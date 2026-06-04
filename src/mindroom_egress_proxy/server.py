"""Approved MindRoom worker egress policy service.

The container runs Squid as the HTTP/CONNECT forward proxy and this Python
process as the local grant API. Squid invokes this same script in helper mode
for dynamic hostname decisions through external_acl_type.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sqlite3
import subprocess
import sys
import threading
import time
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

import dns.exception
import dns.resolver
import idna
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from kubernetes import client, config
from kubernetes.client import ApiException
from kubernetes.config.config_exception import ConfigException
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

DEFAULT_PROXY_PORT = 3128
DEFAULT_POLICY_API_PORT = 8080
DEFAULT_NAMESPACE = "default"
DEFAULT_MAX_TTL_SECONDS = 6 * 60 * 60
DEFAULT_WORKER_CACHE_SECONDS = 30
DEFAULT_SQUID_CONFIG_PATH = "/etc/squid/squid.conf"
MAX_PORT = 65535
MAX_DNS_NAME_LENGTH = 253
MAX_DNS_LABEL_LENGTH = 63
MIN_DNS_LABELS = 2
MAX_REASON_CHARS = 500
WORKER_KEY_MIN_PARTS = 4
USER_AGENT_WORKER_KEY_MIN_PARTS = 5
SAFE_PORTS = {80, 443}
FORBIDDEN_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
}
FORBIDDEN_HOST_SUFFIXES = (
    ".localhost",
    ".svc",
    ".svc.cluster.local",
    ".cluster.local",
)
WORKER_ID_LABEL = "mindroom.ai/worker-id"
WORKER_KEY_ANNOTATION = "mindroom.ai/worker-key"


class RuntimeSettings(BaseSettings):
    """Environment-backed runtime settings."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    proxy_port: int = Field(
        default=DEFAULT_PROXY_PORT,
        alias="MINDROOM_EGRESS_PROXY_LISTEN_PORT",
    )
    api_port: int = Field(
        default=DEFAULT_POLICY_API_PORT,
        alias="MINDROOM_APPROVED_EGRESS_API_PORT",
    )
    max_ttl_seconds: int = Field(
        default=DEFAULT_MAX_TTL_SECONDS,
        alias="MINDROOM_APPROVED_EGRESS_MAX_TTL_SECONDS",
    )
    pod_namespace: str | None = Field(default=None, alias="POD_NAMESPACE")
    egress_namespace: str = Field(
        default=DEFAULT_NAMESPACE,
        alias="MINDROOM_EGRESS_NAMESPACE",
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
        default=DEFAULT_SQUID_CONFIG_PATH,
        alias="MINDROOM_EGRESS_SQUID_CONFIG_PATH",
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


class PolicyError(RuntimeError):
    """One expected policy denial reason."""


def _now() -> int:
    return int(time.time())


def _raw_hostname(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("hostname must be a string")
    raw = value.strip().rstrip(".")
    if not raw:
        raise ValueError("hostname must not be empty")
    if "://" in raw or any(part in raw for part in ("/", "?", "#", "@")):
        raise ValueError(
            "hostname must not include a scheme, path, query, or credentials",
        )
    if "*" in raw:
        raise ValueError("hostname wildcards are not supported")
    if ":" in raw:
        raise ValueError("hostname must not include a port")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValueError("IP literals are not valid dynamic egress hostnames")
    return raw


def _idna_hostname(raw: str) -> str:
    try:
        return idna.encode(raw, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise ValueError("hostname is not valid IDNA") from exc


def _validate_external_hostname(normalized: str) -> None:
    if len(normalized) > MAX_DNS_NAME_LENGTH:
        raise ValueError("hostname is too long")
    labels = normalized.split(".")
    if len(labels) < MIN_DNS_LABELS:
        raise ValueError("hostname must be a fully-qualified external DNS name")
    if any(not label for label in labels):
        raise ValueError("hostname contains an empty label")
    for label in labels:
        if len(label) > MAX_DNS_LABEL_LENGTH:
            raise ValueError("hostname label is too long")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("hostname labels must not start or end with '-'")
        if not all(char.isalnum() or char == "-" for char in label):
            raise ValueError("hostname contains unsupported characters")
    if normalized in FORBIDDEN_HOSTNAMES or normalized.endswith(
        FORBIDDEN_HOST_SUFFIXES,
    ):
        raise ValueError("hostname points at an internal name")


def canonical_hostname(value: str) -> str:
    """Return a normalized exact hostname or raise ValueError."""
    normalized = _idna_hostname(_raw_hostname(value))
    _validate_external_hostname(normalized)
    return normalized


def is_forbidden_resolved_address(value: str) -> bool:
    """Return whether a resolved address is forbidden for dynamic grants."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _resolved_addresses(hostname: str) -> set[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 5.0
    try:
        answers = resolver.resolve_name(hostname)
    except dns.resolver.NXDOMAIN as exc:
        raise OSError("hostname did not resolve") from exc
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ) as exc:
        raise OSError("hostname did not resolve") from exc
    canonical_name = str(answers.canonical_name()).rstrip(".")
    if canonical_name:
        canonical_hostname(canonical_name)
    addresses = set(answers.addresses())
    if not addresses:
        raise OSError("hostname did not resolve")
    return addresses


def _public_resolved_addresses(hostname: str) -> list[str]:
    addresses = _resolved_addresses(hostname)
    if not addresses:
        raise PolicyError("hostname did not resolve")
    forbidden = sorted(
        address for address in addresses if is_forbidden_resolved_address(address)
    )
    if forbidden:
        raise PolicyError("hostname resolved to a forbidden address range")
    return sorted(addresses)


def normalize_reason(value: str) -> str:
    """Return a log- and approval-safe reason string."""
    if not isinstance(value, str):
        raise ValueError("reason must be a string")
    cleaned = "".join(
        " " if char.isspace() or unicodedata.category(char)[0] == "C" else char
        for char in value
    )
    normalized = " ".join(cleaned.split())
    if not normalized:
        raise ValueError("reason must not be empty")
    return normalized[:MAX_REASON_CHARS]


def _valid_port(value: int | str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer") from exc
    if port <= 0 or port > MAX_PORT:
        raise ValueError("port is out of range")
    return port


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


def worker_key_agent_name(worker_key: str) -> str | None:
    """Return encoded agent name for shared, user_agent, or unscoped worker keys."""
    parts = worker_key.split(":")
    if len(parts) < WORKER_KEY_MIN_PARTS or parts[0] != "v1":
        return None
    scope = parts[2]
    if scope in {"shared", "unscoped"}:
        return parts[3]
    if scope == "user_agent" and len(parts) >= USER_AGENT_WORKER_KEY_MIN_PARTS:
        return parts[-1]
    return None


@dataclass(frozen=True, slots=True)
class StaticAllowlist:
    """Static domain allowlist compatible with the existing Squid dstdomain file."""

    exact: frozenset[str]
    suffix: frozenset[str]

    @classmethod
    def from_file(cls, path: Path) -> StaticAllowlist:
        if not path.exists():
            return cls(exact=frozenset(), suffix=frozenset())
        return cls.from_lines(path.read_text(encoding="utf-8").splitlines())

    @classmethod
    def from_lines(cls, lines: list[str]) -> StaticAllowlist:
        exact: set[str] = set()
        suffix: set[str] = set()
        for line in lines:
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            if stripped.startswith("."):
                suffix.add(canonical_hostname(stripped[1:]))
            else:
                exact.add(canonical_hostname(stripped))
        return cls(exact=frozenset(exact), suffix=frozenset(suffix))

    def allows(self, hostname: str) -> bool:
        host = canonical_hostname(hostname)
        if host in self.exact:
            return True
        return any(host == base or host.endswith(f".{base}") for base in self.suffix)


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


@dataclass(frozen=True, slots=True)
class WorkerIdentity:
    """Worker identity resolved from a proxy source IP."""

    worker_key: str
    agent_name: str | None


class KubernetesWorkerResolver:
    """Resolve worker source pod IPs to worker keys through Kubernetes metadata."""

    def __init__(
        self,
        *,
        namespace: str,
        cache_seconds: int = DEFAULT_WORKER_CACHE_SECONDS,
        core_api: client.CoreV1Api | None = None,
        apps_api: client.AppsV1Api | None = None,
    ) -> None:
        self.namespace = namespace
        self.cache_seconds = cache_seconds
        self.core_api = core_api
        self.apps_api = apps_api
        if self.core_api is None or self.apps_api is None:
            try:
                config.load_incluster_config()
            except ConfigException:
                logger.warning("kubernetes_incluster_config_unavailable")
            else:
                self.core_api = self.core_api or client.CoreV1Api()
                self.apps_api = self.apps_api or client.AppsV1Api()
        self._cache: dict[str, tuple[float, WorkerIdentity | None]] = {}
        self._lock = threading.RLock()

    def resolve(self, source_ip: str) -> WorkerIdentity | None:
        if self.core_api is None or self.apps_api is None:
            return None
        now_monotonic = time.monotonic()
        with self._lock:
            cached = self._cache.get(source_ip)
            if cached is not None and cached[0] > now_monotonic:
                return cached[1]
        try:
            identity = self._resolve_uncached(source_ip)
        except ApiException as exc:
            logger.warning(
                "worker_resolver_kubernetes_error source_ip=%s status=%s",
                source_ip,
                exc.status,
            )
            identity = None
        except Exception:
            logger.exception("worker_resolver_error source_ip=%s", source_ip)
            identity = None
        with self._lock:
            self._cache[source_ip] = (now_monotonic + self.cache_seconds, identity)
        return identity

    def _resolve_uncached(self, source_ip: str) -> WorkerIdentity | None:
        if self.core_api is None or self.apps_api is None:
            return None
        pods = self.core_api.list_namespaced_pod(
            namespace=self.namespace,
            field_selector=f"status.podIP={source_ip}",
        )
        if not pods.items:
            return None
        labels = pods.items[0].metadata.labels or {}
        worker_id = labels.get(WORKER_ID_LABEL)
        if not worker_id:
            return None
        deployment = self.apps_api.read_namespaced_deployment(
            name=worker_id,
            namespace=self.namespace,
        )
        annotations = deployment.metadata.annotations or {}
        worker_key = annotations.get(WORKER_KEY_ANNOTATION)
        if not worker_key:
            return None
        return WorkerIdentity(
            worker_key=worker_key,
            agent_name=worker_key_agent_name(worker_key),
        )


class EgressPolicy:
    """Shared policy used by the proxy handler."""

    def __init__(
        self,
        *,
        static_allowlist: StaticAllowlist,
        grant_store: GrantStore,
        worker_resolver: KubernetesWorkerResolver,
    ) -> None:
        self.static_allowlist = static_allowlist
        self.grant_store = grant_store
        self.worker_resolver = worker_resolver

    def is_allowed(
        self,
        *,
        source_ip: str,
        hostname: str,
        port: int,
    ) -> tuple[bool, str, str | None]:
        if port not in SAFE_PORTS:
            return False, "port is not allowed", None
        try:
            host = canonical_hostname(hostname)
            addresses = _public_resolved_addresses(host)
        except (OSError, ValueError, PolicyError) as exc:
            return False, str(exc), None
        try:
            if self.static_allowlist.allows(host):
                return True, "static allowlist", addresses[0]
        except ValueError as exc:
            return False, str(exc), None
        identity = self.worker_resolver.resolve(source_ip)
        if identity is None:
            return False, "worker identity could not be resolved", None
        if self.grant_store.has_grant(
            host,
            worker_key=identity.worker_key,
            agent_name=identity.agent_name,
        ):
            return True, "dynamic grant", addresses[0]
        return False, "hostname is not approved for this worker", None


def _squid_quote(value: str) -> str:
    cleaned = "".join(
        " " if char.isspace() or unicodedata.category(char)[0] == "C" else char
        for char in str(value)
    )
    normalized = " ".join(cleaned.split()) or "egress denied"
    escaped = normalized.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def evaluate_squid_acl_request(line: str, policy: EgressPolicy) -> str:
    """Evaluate one Squid external_acl_type helper request line."""
    try:
        source_ip, hostname, raw_port, _method = line.strip().split(maxsplit=3)
        port = _valid_port(unquote(raw_port))
        allowed, reason, _connect_address = policy.is_allowed(
            source_ip=unquote(source_ip),
            hostname=unquote(hostname),
            port=port,
        )
    except Exception as exc:  # noqa: BLE001
        # Squid helpers must fail closed on malformed input or policy errors.
        return f"ERR message={_squid_quote(str(exc))}"
    if allowed:
        return f"OK log={_squid_quote(reason)}"
    return f"ERR message={_squid_quote(reason)}"


def run_squid_acl_helper(policy: EgressPolicy) -> None:
    """Run Squid's line-oriented external ACL helper protocol on stdin/stdout."""
    for line in sys.stdin:
        sys.stdout.write(f"{evaluate_squid_acl_request(line, policy)}\n")
        sys.stdout.flush()


def _error_response(status_code: int, error: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"ok": False, "error": error})


def _validation_error_message(exc: RequestValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "invalid request"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", []) if part != "body")
    message = str(first.get("msg", "invalid request"))
    return f"{location}: {message}" if location else message


def create_policy_api_app(
    *,
    grant_store: GrantStore,
    bearer_token: str,
    max_ttl_seconds: int,
) -> FastAPI:
    """Create the FastAPI policy API used by the MindRoom control plane."""
    app = FastAPI(
        title="MindRoom Approved Egress Policy API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return _error_response(
            HTTPStatus.BAD_REQUEST.value,
            _validation_error_message(exc),
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        _request: Request,
        exc: HTTPException,
    ) -> JSONResponse:
        return _error_response(exc.status_code, str(exc.detail))

    def require_authorization(authorization: str | None = Header(default=None)) -> None:
        expected = f"Bearer {bearer_token}"
        if not bearer_token or authorization != expected:
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED.value,
                detail="unauthorized",
            )

    @app.get("/healthz")
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/grants")
    def list_grants(
        _authorized: None = Depends(require_authorization),
    ) -> dict[str, Any]:
        return {"grants": grant_store.list_active_grants()}

    @app.post("/grants", status_code=HTTPStatus.CREATED.value)
    def create_grant(
        payload: GrantCreateRequest,
        _authorized: None = Depends(require_authorization),
    ) -> dict[str, Any]:
        try:
            ttl_seconds = min(payload.ttl_seconds, max_ttl_seconds)
            grant = grant_store.create_grant(
                hostname=payload.hostname,
                subject_type=payload.subject_type.value,
                subject=payload.subject,
                agent_name=payload.agent_name,
                requester_id=payload.requester_id,
                room_id=payload.room_id,
                thread_id=payload.thread_id,
                ttl_seconds=ttl_seconds,
                approved_by=payload.approved_by,
                reason=payload.reason,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST.value,
                detail=str(exc),
            ) from exc
        return {"ok": True, "grant": grant}

    return app


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def create_runtime_policy(settings: RuntimeSettings) -> EgressPolicy:
    return EgressPolicy(
        static_allowlist=StaticAllowlist.from_file(settings.allowlist_path),
        grant_store=GrantStore(settings.db_path),
        worker_resolver=KubernetesWorkerResolver(namespace=settings.namespace),
    )


def squid_command(settings: RuntimeSettings) -> list[str]:
    return ["squid", "-N", "-f", settings.squid_config_path]


def run_service(settings: RuntimeSettings) -> None:
    store = GrantStore(settings.db_path)
    api_app = create_policy_api_app(
        grant_store=store,
        bearer_token=settings.bearer_token.get_secret_value(),
        max_ttl_seconds=settings.max_ttl_seconds,
    )
    api_config = uvicorn.Config(
        api_app,
        host="0.0.0.0",  # noqa: S104
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        access_log=True,
    )
    api_server = uvicorn.Server(api_config)

    logger.info(
        "approved_egress_proxy starting squid_proxy_port=%s api_port=%s namespace=%s",
        settings.proxy_port,
        settings.api_port,
        settings.namespace,
    )
    squid = subprocess.Popen(squid_command(settings))  # noqa: S603
    stopping = threading.Event()

    def monitor_squid() -> None:
        return_code = squid.wait()
        if not stopping.is_set():
            logger.error("squid exited unexpectedly return_code=%s", return_code)
            api_server.should_exit = True

    monitor_thread = threading.Thread(
        target=monitor_squid,
        name="squid-monitor",
        daemon=True,
    )
    monitor_thread.start()
    try:
        api_server.run()
    finally:
        stopping.set()
        if squid.poll() is None:
            squid.terminate()
            try:
                squid.wait(timeout=10)
            except subprocess.TimeoutExpired:
                squid.kill()
                squid.wait(timeout=10)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MindRoom approved egress policy service",
    )
    parser.add_argument("mode", nargs="?", choices=("serve", "helper"), default="serve")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    settings = RuntimeSettings()
    configure_logging(settings.log_level)
    if args.mode == "helper":
        run_squid_acl_helper(create_runtime_policy(settings))
        return
    run_service(settings)


if __name__ == "__main__":
    main()
