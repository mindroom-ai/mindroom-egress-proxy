"""Unit tests for the approved MindRoom egress proxy runtime."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

MODULE_PATH = Path(__file__).with_name("approved_egress_proxy.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("approved_egress_proxy", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


egress = _load_module()


class HostnameValidationTests(unittest.TestCase):
    def test_canonical_hostname_accepts_exact_dns_names(self) -> None:
        self.assertEqual(egress.canonical_hostname("GitHub.COM"), "github.com")
        self.assertEqual(egress.canonical_hostname("api.github.com."), "api.github.com")

    def test_canonical_hostname_uses_idna2008_uts46_normalization(self) -> None:
        self.assertEqual(egress.canonical_hostname("faß.de"), "xn--fa-hia.de")
        self.assertEqual(egress.canonical_hostname("Ｆｏｏ.example"), "foo.example")
        with self.assertRaises(ValueError):
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
            with self.subTest(value=value), self.assertRaises(ValueError):
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
            with self.subTest(value=value):
                self.assertTrue(egress.is_forbidden_resolved_address(value))
        self.assertFalse(egress.is_forbidden_resolved_address("8.8.8.8"))

    def test_public_resolved_addresses_rejects_mixed_private_results(self) -> None:
        original = egress._resolved_addresses
        try:
            egress._resolved_addresses = lambda hostname: {"8.8.8.8", "10.0.0.5"}
            with self.assertRaises(egress.PolicyError):
                egress._public_resolved_addresses("example.com")
        finally:
            egress._resolved_addresses = original

    def test_reason_values_are_normalized_and_limited(self) -> None:
        reason = "  Need\n\tAPI docs\x00for validation  " + ("x" * 600)

        normalized = egress.normalize_reason(reason)

        self.assertLessEqual(len(normalized), egress.MAX_REASON_CHARS)
        self.assertNotIn("\n", normalized)
        self.assertNotIn("\t", normalized)
        self.assertNotIn("\x00", normalized)
        self.assertTrue(normalized.startswith("Need API docs for validation"))

    def test_runtime_settings_use_only_dedicated_bearer_token(self) -> None:
        old_environ = os.environ.copy()
        try:
            os.environ.pop("MINDROOM_APPROVED_EGRESS_TOKEN", None)
            os.environ["MINDROOM_SANDBOX_PROXY_TOKEN"] = "fallback-token"

            with self.assertRaises(ValueError):
                egress.RuntimeSettings()

            os.environ["MINDROOM_APPROVED_EGRESS_TOKEN"] = "approved-token"
            self.assertEqual(
                egress.RuntimeSettings().bearer_token.get_secret_value(),
                "approved-token",
            )
        finally:
            os.environ.clear()
            os.environ.update(old_environ)


class StaticAllowlistTests(unittest.TestCase):
    def test_leading_dot_allows_domain_and_subdomains(self) -> None:
        allowlist = egress.StaticAllowlist.from_lines(
            [".github.com", "exact.example.com"],
        )

        self.assertTrue(allowlist.allows("github.com"))
        self.assertTrue(allowlist.allows("api.github.com"))
        self.assertTrue(allowlist.allows("exact.example.com"))
        self.assertFalse(allowlist.allows("notgithub.com"))
        self.assertFalse(allowlist.allows("child.exact.example.com"))


class SquidAclHelperTests(unittest.TestCase):
    def test_squid_command_runs_with_config_in_foreground(self) -> None:
        settings = SimpleNamespace(squid_config_path="/tmp/squid.conf")

        self.assertEqual(
            egress.squid_command(settings),
            ["squid", "-N", "-f", "/tmp/squid.conf"],
        )

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

        self.assertEqual(result, 'OK log="dynamic grant"')
        self.assertEqual(policy.request, ("10.4.0.12", "Example.COM", 443))

    def test_squid_acl_request_denies_when_policy_denies(self) -> None:
        class Policy:
            def is_allowed(self, *, source_ip: str, hostname: str, port: int):
                return False, "hostname is not approved for this worker", None

        result = egress.evaluate_squid_acl_request(
            "10.4.0.12 example.com 443 CONNECT",
            Policy(),
        )

        self.assertEqual(
            result,
            'ERR message="hostname is not approved for this worker"',
        )

    def test_squid_acl_request_fails_closed_on_malformed_input(self) -> None:
        class Policy:
            def is_allowed(self, *, source_ip: str, hostname: str, port: int):
                raise AssertionError("policy should not be called")

        for value in (
            "",
            "10.4.0.12 example.com",
            "10.4.0.12 example.com not-a-port CONNECT",
        ):
            with self.subTest(value=value):
                result = egress.evaluate_squid_acl_request(value, Policy())
                self.assertTrue(result.startswith("ERR message="))


class GrantRequestValidationTests(unittest.TestCase):
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

        self.assertEqual(payload.hostname, "xn--fa-hia.de")
        self.assertEqual(payload.subject, "v1:default:user_agent:@user:server:mind")
        self.assertEqual(payload.reason, "Need external docs now")

    def test_grant_create_request_rejects_bad_subject_type_and_ttl(self) -> None:
        base = {
            "hostname": "github.com",
            "subject_type": "worker_key",
            "subject": "worker",
            "ttl_seconds": 300,
        }
        with self.assertRaises(ValueError):
            egress.GrantCreateRequest.model_validate({**base, "subject_type": "user"})
        with self.assertRaises(ValueError):
            egress.GrantCreateRequest.model_validate({**base, "ttl_seconds": 0})


class RuntimeSettingsTests(unittest.TestCase):
    def test_runtime_settings_use_egress_namespace_when_pod_namespace_is_absent(
        self,
    ) -> None:
        old_environ = os.environ.copy()
        try:
            os.environ.clear()
            os.environ["MINDROOM_APPROVED_EGRESS_TOKEN"] = "token"
            os.environ["MINDROOM_EGRESS_NAMESPACE"] = "custom"

            settings = egress.RuntimeSettings()

            self.assertEqual(settings.namespace, "custom")
            self.assertEqual(settings.bearer_token.get_secret_value(), "token")
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

            self.assertEqual(settings.proxy_port, egress.DEFAULT_PROXY_PORT)
        finally:
            os.environ.clear()
            os.environ.update(old_environ)


class GrantStoreTests(unittest.TestCase):
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

            self.assertEqual(grant["hostname"], "api.github.com")
            self.assertTrue(
                store.has_grant(
                    "api.github.com",
                    worker_key="v1:default:user_agent:@user:server:assistant",
                    agent_name="assistant",
                    now=now + 1,
                ),
            )
            self.assertFalse(
                store.has_grant(
                    "github.com",
                    worker_key="v1:default:user_agent:@user:server:assistant",
                    agent_name="assistant",
                    now=now + 1,
                ),
            )
            self.assertFalse(
                store.has_grant(
                    "api.github.com",
                    worker_key="v1:default:user_agent:@other:server:assistant",
                    agent_name="assistant",
                    now=now + 1,
                ),
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

            self.assertTrue(
                store.has_grant(
                    "python.org",
                    worker_key="worker",
                    agent_name="assistant",
                    now=now + 1,
                ),
            )
            self.assertFalse(
                store.has_grant(
                    "python.org",
                    worker_key="worker",
                    agent_name="other",
                    now=now + 1,
                ),
            )
            self.assertFalse(
                store.has_grant(
                    "python.org",
                    worker_key="worker",
                    agent_name="assistant",
                    now=now + 11,
                ),
            )


class WorkerKeyParsingTests(unittest.TestCase):
    def test_worker_key_agent_name_parses_shared_and_user_agent_scopes(self) -> None:
        self.assertEqual(
            egress.worker_key_agent_name("v1:default:shared:assistant"),
            "assistant",
        )
        self.assertEqual(
            egress.worker_key_agent_name("v1:default:user_agent:@user:server:assistant"),
            "assistant",
        )
        self.assertIsNone(egress.worker_key_agent_name("v1:default:user:@user:server"))


class KubernetesWorkerResolverTests(unittest.TestCase):
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

        self.assertIsNotNone(identity)
        self.assertEqual(
            identity.worker_key,
            "v1:default:user_agent:@user:server:assistant",
        )
        self.assertEqual(identity.agent_name, "assistant")
        self.assertEqual(core_api.field_selector, "status.podIP=10.0.0.10")
        self.assertEqual(apps_api.name, "worker-deployment")


class PolicyApiTests(unittest.TestCase):
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
            self.assertEqual(unauthorized.status_code, 401)
            self.assertEqual(unauthorized.json()["ok"], False)

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

            self.assertEqual(response.status_code, 201)
            body = response.json()
            self.assertEqual(body["grant"]["hostname"], "github.com")
            self.assertEqual(body["grant"]["effective_ttl_seconds"], 60)

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
            self.assertEqual(invalid.status_code, 400)
            self.assertEqual(invalid.json()["ok"], False)


if __name__ == "__main__":
    unittest.main()
