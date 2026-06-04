"""Egress allow/deny policy decisions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from mindroom_egress_proxy.constants import SAFE_PORTS
from mindroom_egress_proxy.grants import GrantStore
from mindroom_egress_proxy.hostnames import (
    PolicyError,
    _public_resolved_addresses,
    canonical_hostname,
)
from mindroom_egress_proxy.workers import KubernetesWorkerResolver, WorkerIdentity


class WorkerResolver(Protocol):
    """Resolve a source IP to a worker identity."""

    def resolve(self, source_ip: str) -> WorkerIdentity | None: ...


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
            allow_agent_grants=identity.worker_scope in {"shared", "unscoped"},
        ):
            return True, "dynamic grant", addresses[0]
        return False, "hostname is not approved for this worker", None
