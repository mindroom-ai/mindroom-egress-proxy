from __future__ import annotations

import time

import mindroom_egress_proxy.server as egress
from mindroom_egress_proxy import hostnames


class NoWorkerResolver:
    def resolve(self, source_ip: str) -> None:
        return None


class StaticWorkerResolver:
    def __init__(self, identity: egress.WorkerIdentity) -> None:
        self.identity = identity

    def resolve(self, source_ip: str) -> egress.WorkerIdentity:
        return self.identity


def test_policy_allows_static_allowlist_without_worker_identity(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        hostnames,
        "_resolved_addresses",
        lambda _hostname: {"93.184.216.34"},
    )
    policy = egress.EgressPolicy(
        static_allowlist=egress.StaticAllowlist.from_lines([".example.com"]),
        grant_store=egress.GrantStore(tmp_path / "grants.sqlite3"),
        worker_resolver=NoWorkerResolver(),
    )

    allowed, reason, connect_address = policy.is_allowed(
        source_ip="10.0.0.12",
        hostname="docs.example.com",
        port=443,
    )

    assert allowed
    assert reason == "static allowlist"
    assert connect_address == "93.184.216.34"


def test_policy_allows_dynamic_grant_for_resolved_worker(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        hostnames,
        "_resolved_addresses",
        lambda _hostname: {"93.184.216.34"},
    )
    worker_key = "v1:default:user_agent:@user:server:assistant"
    store = egress.GrantStore(tmp_path / "grants.sqlite3")
    store.create_grant(
        hostname="docs.example.com",
        subject_type="worker_key",
        subject=worker_key,
        agent_name="assistant",
        requester_id="@user:server",
        room_id="!room:server",
        thread_id=None,
        ttl_seconds=300,
        approved_by="@user:server",
        reason="Need docs",
        now=int(time.time()),
    )
    policy = egress.EgressPolicy(
        static_allowlist=egress.StaticAllowlist.from_lines([]),
        grant_store=store,
        worker_resolver=StaticWorkerResolver(
            egress.WorkerIdentity(worker_key=worker_key, agent_name="assistant"),
        ),
    )

    allowed, reason, connect_address = policy.is_allowed(
        source_ip="10.0.0.12",
        hostname="docs.example.com",
        port=443,
    )

    assert allowed
    assert reason == "dynamic grant"
    assert connect_address == "93.184.216.34"


def test_policy_denies_dynamic_hostname_when_worker_identity_is_missing(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        hostnames,
        "_resolved_addresses",
        lambda _hostname: {"93.184.216.34"},
    )
    policy = egress.EgressPolicy(
        static_allowlist=egress.StaticAllowlist.from_lines([]),
        grant_store=egress.GrantStore(tmp_path / "grants.sqlite3"),
        worker_resolver=NoWorkerResolver(),
    )

    allowed, reason, connect_address = policy.is_allowed(
        source_ip="10.0.0.12",
        hostname="docs.example.com",
        port=443,
    )

    assert not allowed
    assert reason == "worker identity could not be resolved"
    assert connect_address is None
