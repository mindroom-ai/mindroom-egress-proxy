"""Unit tests for the approved MindRoom egress proxy runtime."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from mindroom_egress_proxy import api, grants, hostnames, settings, squid, workers
from mindroom_egress_proxy.constants import (
    DEFAULT_PROXY_PORT,
    MAX_REASON_CHARS,
    WORKER_ID_LABEL,
    WORKER_KEY_ANNOTATION,
)
from mindroom_egress_proxy.policy import StaticAllowlist


class TestHostnameValidation:
    def test_canonical_hostname_accepts_exact_dns_names(self) -> None:
        assert hostnames.canonical_hostname("GitHub.COM") == "github.com"
        assert hostnames.canonical_hostname("api.github.com.") == "api.github.com"

    def test_canonical_hostname_uses_idna2008_uts46_normalization(self) -> None:
        assert hostnames.canonical_hostname("faß.de") == "xn--fa-hia.de"
        assert hostnames.canonical_hostname("Ｆｏｏ.example") == "foo.example"
        with pytest.raises(ValueError):
            hostnames.canonical_hostname("☃.example")

    def test_canonical_hostname_rejects_urls_ports_wildcards_and_internal_names(
        self,
    ) -> None:
        rejected = [
            "https://github.com",
            "github.com/path",
            "github.com:443",
            "*.github.com",
            "db",
            "127.0.0.1",
            "localhost",
            "metadata.google.internal",
            "service.default.svc.cluster.local",
        ]
        for value in rejected:
            with pytest.raises(ValueError):
                hostnames.canonical_hostname(value)

    def test_canonical_hostname_rejects_overlong_raw_name_before_idna(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fail_idna_encode(*_args, **_kwargs):
            raise AssertionError("IDNA encoding should not run for overlong input")

        monkeypatch.setattr(hostnames.idna, "encode", fail_idna_encode)

        with pytest.raises(ValueError, match="hostname is too long"):
            hostnames.canonical_hostname(("a" * 254) + ".example")

    def test_forbidden_resolved_addresses_include_private_and_metadata_ranges(
        self,
    ) -> None:
        for value in (
            "127.0.0.1",
            "10.1.2.3",
            "172.20.1.5",
            "192.168.1.1",
            "169.254.169.254",
        ):
            assert hostnames.is_forbidden_resolved_address(value)
        assert not hostnames.is_forbidden_resolved_address("8.8.8.8")

    def test_public_resolved_addresses_rejects_mixed_private_results(self) -> None:
        original = hostnames._resolved_addresses
        try:
            hostnames._resolved_addresses = lambda hostname: {"8.8.8.8", "10.0.0.5"}
            with pytest.raises(hostnames.PolicyError):
                hostnames._public_resolved_addresses("example.com")
        finally:
            hostnames._resolved_addresses = original

    def test_reason_values_are_normalized_and_limited(self) -> None:
        reason = "  Need\n\tAPI docs\x00for validation  " + ("x" * 600)

        normalized = hostnames.normalize_reason(reason)

        assert len(normalized) <= MAX_REASON_CHARS
        assert "\n" not in normalized
        assert "\t" not in normalized
        assert "\x00" not in normalized
        assert normalized.startswith("Need API docs for validation")

    def test_runtime_settings_use_only_dedicated_bearer_token(self) -> None:
        old_environ = os.environ.copy()
        try:
            os.environ.pop("MINDROOM_APPROVED_EGRESS_TOKEN", None)
            os.environ["MINDROOM_SANDBOX_PROXY_TOKEN"] = "fallback-token"

            with pytest.raises(ValueError):
                settings.RuntimeSettings()

            os.environ["MINDROOM_APPROVED_EGRESS_TOKEN"] = "approved-token"
            assert (
                settings.RuntimeSettings().bearer_token.get_secret_value()
                == "approved-token"
            )
        finally:
            os.environ.clear()
            os.environ.update(old_environ)


class TestStaticAllowlist:
    def test_leading_dot_allows_domain_and_subdomains(self) -> None:
        allowlist = StaticAllowlist.from_lines(
            [".github.com", "exact.example.com"],
        )

        assert allowlist.allows("github.com")
        assert allowlist.allows("api.github.com")
        assert allowlist.allows("exact.example.com")
        assert not allowlist.allows("notgithub.com")
        assert not allowlist.allows("child.exact.example.com")


class TestSquidAclHelper:
    def test_squid_command_runs_with_config_in_foreground(self) -> None:
        settings = SimpleNamespace(squid_config_path="/tmp/squid.conf")

        assert squid.squid_command(settings) == [
            "squid",
            "-N",
            "-f",
            "/tmp/squid.conf",
        ]

    def test_squid_acl_request_uses_source_host_and_port_for_policy(self) -> None:
        class Policy:
            def is_allowed(self, *, source_ip: str, hostname: str, port: int):
                self.request = (source_ip, hostname, port)
                return True, "dynamic grant", "93.184.216.34"

        policy = Policy()

        result = squid.evaluate_squid_acl_request(
            "10.4.0.12 Example.COM 443 CONNECT",
            policy,
        )

        assert result == 'OK log="dynamic grant"'
        assert policy.request == ("10.4.0.12", "Example.COM", 443)

    def test_squid_acl_request_denies_when_policy_denies(self) -> None:
        class Policy:
            def is_allowed(self, *, source_ip: str, hostname: str, port: int):
                return False, "hostname is not approved for this worker", None

        result = squid.evaluate_squid_acl_request(
            "10.4.0.12 example.com 443 CONNECT",
            Policy(),
        )

        assert result == 'ERR message="hostname is not approved for this worker"'

    def test_squid_acl_request_fails_closed_on_malformed_input(self) -> None:
        class Policy:
            def is_allowed(self, *, source_ip: str, hostname: str, port: int):
                raise AssertionError("policy should not be called")

        for value in (
            "",
            "10.4.0.12 example.com",
            "10.4.0.12 example.com not-a-port CONNECT",
        ):
            result = squid.evaluate_squid_acl_request(value, Policy())
            assert result.startswith("ERR message=")


class TestGrantRequestValidation:
    def test_grant_create_request_normalizes_strings_and_hostname(self) -> None:
        payload = grants.GrantCreateRequest.model_validate(
            {
                "hostname": "FAß.DE.",
                "subject_type": "worker_key",
                "subject": "  v1:default:user_agent:@user:server:mind  ",
                "ttl_seconds": 300,
                "reason": "  Need\nexternal docs\x00now  ",
            },
        )

        assert payload.hostname == "xn--fa-hia.de"
        assert payload.subject == "v1:default:user_agent:@user:server:mind"
        assert payload.reason == "Need external docs now"

    def test_grant_create_request_rejects_bad_subject_type_and_ttl(self) -> None:
        base = {
            "hostname": "github.com",
            "subject_type": "worker_key",
            "subject": "worker",
            "ttl_seconds": 300,
        }
        with pytest.raises(ValueError):
            grants.GrantCreateRequest.model_validate({**base, "subject_type": "user"})
        with pytest.raises(ValueError):
            grants.GrantCreateRequest.model_validate({**base, "ttl_seconds": 0})


class TestRuntimeSettings:
    def test_runtime_settings_use_egress_namespace_when_pod_namespace_is_absent(
        self,
    ) -> None:
        old_environ = os.environ.copy()
        try:
            os.environ.clear()
            os.environ["MINDROOM_APPROVED_EGRESS_TOKEN"] = "token"
            os.environ["MINDROOM_EGRESS_NAMESPACE"] = "custom"

            runtime_settings = settings.RuntimeSettings()

            assert runtime_settings.namespace == "custom"
            assert runtime_settings.bearer_token.get_secret_value() == "token"
        finally:
            os.environ.clear()
            os.environ.update(old_environ)

    def test_runtime_settings_ignore_kubernetes_service_link_port_env(self) -> None:
        old_environ = os.environ.copy()
        try:
            os.environ.clear()
            os.environ["MINDROOM_APPROVED_EGRESS_TOKEN"] = "token"
            os.environ["MINDROOM_EGRESS_PROXY_PORT"] = "tcp://34.118.227.158:3128"

            runtime_settings = settings.RuntimeSettings()

            assert runtime_settings.proxy_port == DEFAULT_PROXY_PORT
        finally:
            os.environ.clear()
            os.environ.update(old_environ)


class TestGrantStore:
    def test_worker_key_grants_are_exact_host_and_subject_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = grants.GrantStore(Path(tmpdir) / "grants.sqlite3")
            now = int(time.time())
            grant = store.create_grant(
                hostname="api.github.com",
                subject_type="worker_key",
                subject="v1:default:user_agent:@user:server:assistant",
                agent_name="assistant",
                requester_id="@user:server",
                room_id="!room:server",
                thread_id="$thread",
                ttl_seconds=300,
                approved_by="@user:server",
                reason="Need API docs",
                now=now,
            )

            assert grant["hostname"] == "api.github.com"
            assert store.has_grant(
                "api.github.com",
                worker_key="v1:default:user_agent:@user:server:assistant",
                agent_name="assistant",
                now=now + 1,
            )
            assert not store.has_grant(
                "github.com",
                worker_key="v1:default:user_agent:@user:server:assistant",
                agent_name="assistant",
                now=now + 1,
            )
            assert not store.has_grant(
                "api.github.com",
                worker_key="v1:default:user_agent:@other:server:assistant",
                agent_name="assistant",
                now=now + 1,
            )

    def test_agent_grants_match_agent_name_until_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = grants.GrantStore(Path(tmpdir) / "grants.sqlite3")
            now = int(time.time())
            store.create_grant(
                hostname="python.org",
                subject_type="agent",
                subject="assistant",
                agent_name="assistant",
                requester_id="@user:server",
                room_id="!room:server",
                thread_id=None,
                ttl_seconds=10,
                approved_by="@user:server",
                reason="Need docs",
                now=now,
            )

            assert store.has_grant(
                "python.org",
                worker_key="worker",
                agent_name="assistant",
                allow_agent_grants=True,
                now=now + 1,
            )
            assert not store.has_grant(
                "python.org",
                worker_key="worker",
                agent_name="other",
                allow_agent_grants=True,
                now=now + 1,
            )
            assert not store.has_grant(
                "python.org",
                worker_key="worker",
                agent_name="assistant",
                allow_agent_grants=True,
                now=now + 11,
            )


class TestWorkerKeyParsing:
    def test_worker_key_agent_name_parses_shared_and_user_agent_scopes(self) -> None:
        assert (
            workers.worker_key_agent_name("v1:default:shared:assistant") == "assistant"
        )
        assert (
            workers.worker_key_agent_name(
                "v1:default:user_agent:@user:server:assistant",
            )
            == "assistant"
        )
        assert workers.worker_key_agent_name("v1:default:user:@user:server") is None


class TestKubernetesWorkerResolver:
    def test_resolver_uses_kubernetes_clients_for_worker_identity(self) -> None:
        class CoreApi:
            def list_namespaced_pod(self, *, namespace: str, field_selector: str):
                self.namespace = namespace
                self.field_selector = field_selector
                return SimpleNamespace(
                    items=[
                        SimpleNamespace(
                            metadata=SimpleNamespace(
                                labels={WORKER_ID_LABEL: "worker-deployment"},
                            ),
                        ),
                    ],
                )

        class AppsApi:
            def read_namespaced_deployment(self, *, name: str, namespace: str):
                self.name = name
                self.namespace = namespace
                return SimpleNamespace(
                    metadata=SimpleNamespace(
                        annotations={
                            WORKER_KEY_ANNOTATION: (
                                "v1:default:user_agent:@user:server:assistant"
                            ),
                        },
                    ),
                )

        core_api = CoreApi()
        apps_api = AppsApi()
        resolver = workers.KubernetesWorkerResolver(
            namespace="default",
            core_api=core_api,
            apps_api=apps_api,
        )

        identity = resolver.resolve("10.0.0.10")

        assert identity is not None
        assert identity.worker_key == "v1:default:user_agent:@user:server:assistant"
        assert identity.agent_name == "assistant"
        assert core_api.field_selector == "status.podIP=10.0.0.10"
        assert apps_api.name == "worker-deployment"

    def test_resolver_default_does_not_reuse_source_ip_identity(self) -> None:
        class CoreApi:
            worker_id = "worker-one"

            def list_namespaced_pod(self, *, namespace: str, field_selector: str):
                return SimpleNamespace(
                    items=[
                        SimpleNamespace(
                            metadata=SimpleNamespace(
                                labels={WORKER_ID_LABEL: self.worker_id},
                            ),
                        ),
                    ],
                )

        class AppsApi:
            def read_namespaced_deployment(self, *, name: str, namespace: str):
                worker_keys = {
                    "worker-one": "v1:default:user_agent:@alice:server:assistant",
                    "worker-two": "v1:default:user_agent:@bob:server:assistant",
                }
                return SimpleNamespace(
                    metadata=SimpleNamespace(
                        annotations={WORKER_KEY_ANNOTATION: worker_keys[name]},
                    ),
                )

        core_api = CoreApi()
        resolver = workers.KubernetesWorkerResolver(
            namespace="default",
            core_api=core_api,
            apps_api=AppsApi(),
        )

        first = resolver.resolve("10.0.0.10")
        core_api.worker_id = "worker-two"
        second = resolver.resolve("10.0.0.10")

        assert first is not None
        assert second is not None
        assert first.worker_key == "v1:default:user_agent:@alice:server:assistant"
        assert second.worker_key == "v1:default:user_agent:@bob:server:assistant"


class TestPolicyApi:
    def test_fastapi_policy_api_creates_grants_with_pydantic_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = grants.GrantStore(Path(tmpdir) / "grants.sqlite3")
            app = api.create_policy_api_app(
                grant_store=store,
                bearer_token="token",
                max_ttl_seconds=60,
            )
            client = TestClient(app)

            unauthorized = client.post("/grants", json={})
            assert unauthorized.status_code == 401
            assert unauthorized.json()["ok"] is False

            response = client.post(
                "/grants",
                headers={"authorization": "Bearer token"},
                json={
                    "hostname": "GitHub.COM",
                    "subject_type": "agent",
                    "subject": "assistant",
                    "ttl_seconds": 600,
                    "reason": "Need docs",
                },
            )

            assert response.status_code == 201
            body = response.json()
            assert body["grant"]["hostname"] == "github.com"
            assert body["grant"]["effective_ttl_seconds"] == 60

            invalid = client.post(
                "/grants",
                headers={"authorization": "Bearer token"},
                json={
                    "hostname": "db",
                    "subject_type": "agent",
                    "subject": "assistant",
                    "ttl_seconds": 60,
                },
            )
            assert invalid.status_code == 400
            assert invalid.json()["ok"] is False
