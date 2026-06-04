"""MindRoom plugin tool for approved temporary worker egress grants."""

from __future__ import annotations

import ipaddress
import json
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib import parse, request

import idna
from agno.tools import Toolkit
from mindroom.tool_system.metadata import (
    SetupType,
    ToolCategory,
    ToolStatus,
    register_tool_with_metadata,
)
from mindroom.tool_system.runtime_context import (
    build_execution_identity_from_runtime_context,
    get_tool_runtime_context,
)
from mindroom.tool_system.worker_routing import resolve_worker_key

DEFAULT_MAX_TTL_SECONDS = 6 * 60 * 60
DEFAULT_POLICY_API_URL = "http://mindroom-egress-proxy:8080"
DEFAULT_ALLOWLIST_PATH = "/etc/mindroom-egress/allowed-domains.txt"
MAX_ALLOWLIST_ENTRIES_IN_TOOL_DESCRIPTION = 80
MAX_REASON_CHARS = 500
MAX_DNS_NAME_LENGTH = 253
MAX_DNS_LABEL_LENGTH = 63
MIN_DNS_LABELS = 2
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


@dataclass(frozen=True, slots=True)
class _GrantSubject:
    subject_type: str
    subject: str


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _static_allowlist_entries() -> list[str]:
    inline = os.environ.get("MINDROOM_APPROVED_EGRESS_ALLOWLIST", "").strip()
    text = inline.replace(",", "\n") if inline else ""
    if not text:
        allowlist_path = (
            os.environ.get("MINDROOM_APPROVED_EGRESS_ALLOWLIST_PATH")
            or os.environ.get("MINDROOM_EGRESS_ALLOWLIST_PATH")
            or DEFAULT_ALLOWLIST_PATH
        ).strip()
        if allowlist_path:
            try:
                text = Path(allowlist_path).read_text(encoding="utf-8")
            except OSError:
                text = ""
    entries = (
        line for raw in text.splitlines() if (line := raw.split("#", 1)[0].strip())
    )
    return list(dict.fromkeys(entries))


def _static_allowlist_description() -> str:
    entries = _static_allowlist_entries()
    if not entries:
        return (
            "Static egress allowlist: unavailable when this tool loaded. "
            "Only request access for external hostnames that are blocked by "
            "worker egress."
        )

    visible_entries = entries[:MAX_ALLOWLIST_ENTRIES_IN_TOOL_DESCRIPTION]
    remaining = len(entries) - len(visible_entries)
    suffix = f"; plus {remaining} more entries" if remaining > 0 else ""
    return (
        "Static egress allowlist (do not request access for hostnames matching "
        "these patterns): "
        f"{', '.join(visible_entries)}{suffix}."
    )


def _request_network_access_description() -> str:
    return (
        "Request temporary worker egress to one exact external hostname. "
        "Use this only when the worker needs a hostname that is not already "
        "allowed.\n\n"
        f"{_static_allowlist_description()}"
    )


def _canonical_hostname(value: str) -> str:
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
        raise ValueError("IP literals are not valid egress hostnames")
    if len(raw) > MAX_DNS_NAME_LENGTH:
        raise ValueError("hostname is too long")
    try:
        normalized = (
            idna.encode(raw, uts46=True, std3_rules=True)
            .decode(
                "ascii",
            )
            .lower()
        )
    except idna.IDNAError as exc:
        raise ValueError("hostname is not valid IDNA") from exc
    labels = normalized.split(".")
    if len(labels) < MIN_DNS_LABELS:
        raise ValueError("hostname must be a fully-qualified external DNS name")
    if len(normalized) > MAX_DNS_NAME_LENGTH or any(not label for label in labels):
        raise ValueError("hostname is not a valid DNS name")
    for label in labels:
        if (
            len(label) > MAX_DNS_LABEL_LENGTH
            or label.startswith("-")
            or label.endswith("-")
        ):
            raise ValueError("hostname is not a valid DNS name")
        if not all(char.isalnum() or char == "-" for char in label):
            raise ValueError("hostname contains unsupported characters")
    if normalized in FORBIDDEN_HOSTNAMES or normalized.endswith(
        FORBIDDEN_HOST_SUFFIXES,
    ):
        raise ValueError("hostname points at an internal name")
    return normalized


def _static_allowlist_allows(hostname: str) -> bool:
    host = _canonical_hostname(hostname)
    for entry in _static_allowlist_entries():
        try:
            if entry.startswith("."):
                base = _canonical_hostname(entry[1:])
                if host == base or host.endswith(f".{base}"):
                    return True
            elif host == _canonical_hostname(entry):
                return True
        except ValueError:
            continue
    return False


def _is_plain_http_api_host_allowed(hostname: str) -> bool:
    host = hostname.lower().rstrip(".")
    if host in {"localhost", "mindroom-egress-proxy"}:
        return True
    if host.endswith((".svc", ".svc.cluster.local")):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _policy_api_url() -> str:
    url = (
        (os.environ.get("MINDROOM_APPROVED_EGRESS_API_URL") or DEFAULT_POLICY_API_URL)
        .strip()
        .rstrip("/")
    )
    parsed = parse.urlsplit(url)
    try:
        hostname = parsed.hostname or ""
        _port = parsed.port
    except ValueError as exc:
        raise RuntimeError(
            "MINDROOM_APPROVED_EGRESS_API_URL has an invalid port",
        ) from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError(
            "MINDROOM_APPROVED_EGRESS_API_URL must be an http or https URL",
        )
    if (
        parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(
            "MINDROOM_APPROVED_EGRESS_API_URL must not include userinfo, path, "
            "query, or fragment",
        )
    if parsed.scheme == "http" and not _is_plain_http_api_host_allowed(hostname):
        raise RuntimeError(
            "plain HTTP approved egress policy API URLs must use loopback or an "
            "in-cluster service name",
        )
    return url


def _policy_token() -> str:
    token = (os.environ.get("MINDROOM_APPROVED_EGRESS_TOKEN") or "").strip()
    if not token:
        raise RuntimeError("MINDROOM_APPROVED_EGRESS_TOKEN is not configured")
    return token


def _normalize_reason(value: str) -> str:
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


def _effective_ttl_seconds(ttl_minutes: int) -> int:
    requested = int(ttl_minutes) * 60
    if requested <= 0:
        raise ValueError("ttl_minutes must be positive")
    max_ttl = _env_int(
        "MINDROOM_APPROVED_EGRESS_MAX_TTL_SECONDS",
        DEFAULT_MAX_TTL_SECONDS,
    )
    return max(1, min(requested, max_ttl))


def _grant_subject(agent_name: str) -> _GrantSubject:
    context = get_tool_runtime_context()
    if context is None:
        raise RuntimeError(
            "request_network_access requires a live MindRoom Matrix tool context",
        )
    scope = context.config.get_agent_execution_scope(agent_name)
    if scope == "user_agent":
        identity = build_execution_identity_from_runtime_context(context)
        worker_key = resolve_worker_key("user_agent", identity, agent_name=agent_name)
        if worker_key is None:
            raise RuntimeError(
                "could not resolve the user-agent worker key for this request",
            )
        return _GrantSubject(subject_type="worker_key", subject=worker_key)
    if scope == "user":
        raise RuntimeError("approved egress is not supported for worker_scope=user")
    if scope == "shared" or scope is None:
        return _GrantSubject(subject_type="agent", subject=agent_name)
    raise RuntimeError(f"approved egress is not supported for worker scope {scope!r}")


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(
        self,
        _req: request.Request,
        _fp: object,
        _code: int,
        _msg: str,
        _headers: object,
        _newurl: str,
    ) -> None:
        return None


_NO_REDIRECT_OPENER = request.build_opener(_NoRedirectHandler)


def _post_grant(payload: dict[str, object]) -> dict[str, object]:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    req = request.Request(  # noqa: S310 - _policy_api_url validates scheme and host.
        f"{_policy_api_url()}/grants",
        data=body,
        headers={
            "authorization": f"Bearer {_policy_token()}",
            "content-type": "application/json",
        },
        method="POST",
    )
    with _NO_REDIRECT_OPENER.open(req, timeout=10) as response:
        response_body = response.read(256 * 1024)
    parsed = json.loads(response_body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(
            "approved egress policy service returned a non-object response",
        )
    if parsed.get("ok") is not True:
        raise RuntimeError(
            str(
                parsed.get("error")
                or "approved egress policy service rejected the grant",
            ),
        )
    grant = parsed.get("grant")
    if not isinstance(grant, dict):
        raise RuntimeError(
            "approved egress policy service response is missing the grant",
        )
    return grant


class ApprovedEgressTools(Toolkit):
    """Request temporary hostname egress access for MindRoom workers."""

    def __init__(self) -> None:
        request_description = _request_network_access_description()
        super().__init__(
            name="approved_egress",
            instructions=(
                "Use this tool when a worker needs temporary access to an external "
                "hostname that the egress proxy blocks. Request one exact hostname, "
                "a TTL in minutes, and a concise reason. The request_network_access "
                "tool definition lists static allowlist patterns that do not need "
                "an approval request."
            ),
            tools=[self.request_network_access],
        )
        for registered in (
            self.functions.get("request_network_access"),
            self.async_functions.get("request_network_access"),
        ):
            if registered is not None:
                registered.description = request_description

    async def request_network_access(
        self,
        hostname: str,
        ttl_minutes: int,
        reason: str,
    ) -> str:
        """Request temporary worker egress to one exact external hostname.

        Args:
            hostname: Exact external DNS hostname, without scheme, path, port, or
                wildcard.
            ttl_minutes: Requested access duration in minutes. Deployment policy
                may cap it.
            reason: Short reason shown to the human approver.

        Returns:
            Human-readable result describing the grant decision.

        """
        host = _canonical_hostname(hostname)
        if _static_allowlist_allows(host):
            return (
                f"{host} is already allowed by the static egress allowlist. "
                "No temporary grant was created."
            )
        normalized_reason = _normalize_reason(reason)
        requested_ttl_seconds = int(ttl_minutes) * 60
        effective_ttl_seconds = _effective_ttl_seconds(ttl_minutes)

        context = get_tool_runtime_context()
        if context is None:
            raise RuntimeError(
                "request_network_access requires a live MindRoom Matrix tool context",
            )
        subject = _grant_subject(context.agent_name)
        grant = _post_grant(
            {
                "hostname": host,
                "subject_type": subject.subject_type,
                "subject": subject.subject,
                "agent_name": context.agent_name,
                "requester_id": context.requester_id,
                "room_id": context.room_id,
                "thread_id": context.resolved_thread_id or context.thread_id,
                "ttl_seconds": effective_ttl_seconds,
                "approved_by": context.requester_id,
                "reason": normalized_reason,
            },
        )
        expiry = grant.get("expires_at")
        capped = (
            " Deployment policy capped the requested TTL."
            if effective_ttl_seconds < requested_ttl_seconds
            else ""
        )
        return (
            f"Approved temporary network access to {host} for "
            f"{effective_ttl_seconds // 60} minutes. "
            f"Expires at Unix time {expiry}.{capped}"
        )


@register_tool_with_metadata(
    name="approved_egress",
    display_name="Approved Worker Egress",
    description=(
        "Request human-approved temporary worker access to blocked external hostnames"
    ),
    category=ToolCategory.INTEGRATIONS,
    status=ToolStatus.AVAILABLE,
    setup_type=SetupType.SPECIAL,
    icon="FiShield",
    icon_color="text-emerald-600",
    function_names=("request_network_access",),
)
def approved_egress_tools() -> type[Toolkit]:
    return ApprovedEgressTools
