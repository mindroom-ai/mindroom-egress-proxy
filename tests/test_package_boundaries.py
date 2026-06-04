from __future__ import annotations

from mindroom_egress_proxy import (
    api,
    cli,
    grants,
    hostnames,
    policy,
    service,
    settings,
    squid,
    workers,
)


def test_package_has_real_module_boundaries() -> None:
    assert api.create_policy_api_app is not None
    assert cli.main is not None
    assert grants.GrantStore is not None
    assert hostnames.canonical_hostname is not None
    assert policy.EgressPolicy is not None
    assert service.run_service is not None
    assert settings.RuntimeSettings is not None
    assert squid.evaluate_squid_acl_request is not None
    assert workers.KubernetesWorkerResolver is not None
