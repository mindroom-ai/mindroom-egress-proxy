"""Unit tests for the approved MindRoom egress proxy runtime."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import mindroom_egress_proxy.server as egress


class TestHostnameValidation:
    def test_canonical_hostname_accepts_exact_dns_names(self) -> None:
        assert egress.canonical_hostname("GitHub.COM") == "github.com"
        assert egress.canonical_hostname("api.github.com.") == "api.github.com"

    def test_canonical_hostname_uses_idna2008_uts46_normalization(self) -> None:
        assert egress.canonical_hostname("faß.de") == "xn--fa-hia.de"
        assert egress.canonical_hostname("Ｆｏｏ.example") == "foo.example"
        with pytest.raises(ValueError):
            egress.canonical_hostname("☃.example")

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
                egress.canonical_hostname(value)

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
            assert egress.is_forbidden_resolved_address(value)
        assert not egress.is_forbidden_resolved_address("8.8.8.8")

    def test_public_resolved_addresses_rejects_mixed_private_results(self) -> None:
        original = egress._resolved_addresses
        try:
            egress._resolved_addresses = lambda hostname: {"8.8.8.8", "10.0.0.5"}
            with pytest.raises(egress.PolicyError):
                egress._public_resolved_addresses("example.com")
        finally:
            egress._resolved_addresses = original

    def test_reason_values_are_normalized_and_limited(self) -> None:
        reason = "  Need\n\tAPI docs\x00for validation  " + ("x" * 600)

        normalized = egress.normalize_reason(reason)

        assert len(normalized) <= egress.MAX_REASON_CHARS
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
                egress.RuntimeSettings()

            os.environ["MINDROOM_APPROVED_EGRESS_TOKEN"] = "approved-token"
            assert (
                egress.RuntimeSettings().bearer_token.get_secret_value()
                == "approved-token"
            )
        finally:
            os.environ.clear()
            os.environ.update(old_environ)


class TestStaticAllowlist:
    def test_leading_dot_allows_domain_and_subdomains(self) -> None:
        allowlist = egress.StaticAllowlist.from_lines(
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

        assert egress.squid_command(settings) == [
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

        result = egress.evaluate_squid_acl_request(
            "10.4.0.12 Example.COM 443 CONNECT",
            policy,
        )

        assert result == 'OK log="dynamic grant"'
        assert policy.request == ("10.4.0.12", "Example.COM", 443)

    def test_squid_acl_request_denies_when_policy_denies(self) -> None:
        class Policy:
            def is_allowed(self, *, source_ip: str, hostname: str, port: int):
                return False, "hostname is not approved for this worker", None

        result = egress.evaluate_squid_acl_request(
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
            result = egress.evaluate_squid_acl_request(value, Policy())
            assert result.startswith("ERR message=")


class TestGrantRequestValidation:
    def test_grant_create_request_normalizes_strings_and_hostname(self) -> None:
        payload = egress.GrantCreateRequest.model_validate(
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
            egress.GrantCreateRequest.model_validate({**base, "subject_type": "user"})
        with pytest.raises(ValueError):
            egress.GrantCreateRequest.model_validate({**base, "ttl_seconds": 0})


class TestRuntimeSettings:
    def test_runtime_settings_use_egress_namespace_when_pod_namespace_is_absent(
        self,
    ) -> None:
        old_environ = os.environ.copy()
        try:
            os.environ.clear()
            os.environ["MINDROOM_APPROVED_EGRESS_TOKEN"] = "token"
            os.environ["MINDROOM_EGRESS_NAMESPACE"] = "custom"

            settings = egress.RuntimeSettings()

            assert settings.namespace == "custom"
            assert settings.bearer_token.get_secret_value() == "token"
        finally:
            os.environ.clear()
            os.environ.update(old_environ)

    def test_runtime_settings_ignore_kubernetes_service_link_port_env(self) -> None:
        old_environ = os.environ.copy()
        try:
            os.environ.clear()
            os.environ["MINDROOM_APPROVED_EGRESS_TOKEN"] = "token"
            os.environ["MINDROOM_EGRESS_PROXY_PORT"] = "tcp://34.118.227.158:3128"

            settings = egress.RuntimeSettings()

            assert settings.proxy_port == egress.DEFAULT_PROXY_PORT
        finally:
            os.environ.clear()
            os.environ.update(old_environ)


class TestGrantStore:
    def test_worker_key_grants_are_exact_host_and_subject_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = egress.GrantStore(Path(tmpdir) / "grants.sqlite3")
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
            store = egress.GrantStore(Path(tmpdir) / "grants.sqlite3")
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
                now=now + 1,
            )
            assert not store.has_grant(
                "python.org",
                worker_key="worker",
                agent_name="other",
                now=now + 1,
            )
            assert not store.has_grant(
                "python.org",
                worker_key="worker",
                agent_name="assistant",
                now=now + 11,
            )


class TestWorkerKeyParsing:
    def test_worker_key_agent_name_parses_shared_and_user_agent_scopes(self) -> None:
        assert (
            egress.worker_key_agent_name("v1:default:shared:assistant") == "assistant"
        )
        assert (
            egress.worker_key_agent_name(
                "v1:default:user_agent:@user:server:assistant",
            )
            == "assistant"
        )
        assert egress.worker_key_agent_name("v1:default:user:@user:server") is None


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
                                labels={egress.WORKER_ID_LABEL: "worker-deployment"},
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
                            egress.WORKER_KEY_ANNOTATION: (
                                "v1:default:user_agent:@user:server:assistant"
                            ),
                        },
                    ),
                )

        core_api = CoreApi()
        apps_api = AppsApi()
        resolver = egress.KubernetesWorkerResolver(
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


class TestPolicyApi:
    def test_fastapi_policy_api_creates_grants_with_pydantic_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = egress.GrantStore(Path(tmpdir) / "grants.sqlite3")
            app = egress.create_policy_api_app(
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
