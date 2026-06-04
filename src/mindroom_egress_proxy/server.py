"""Compatibility facade for older imports.

Prefer importing from focused modules such as ``hostnames``, ``grants``,
``workers``, ``policy``, ``api``, ``squid``, ``service``, and ``cli``.
"""

from mindroom_egress_proxy.api import create_policy_api_app
from mindroom_egress_proxy.cli import main, parse_args
from mindroom_egress_proxy.constants import (
    DEFAULT_PROXY_PORT,
    MAX_REASON_CHARS,
    WORKER_ID_LABEL,
    WORKER_KEY_ANNOTATION,
)
from mindroom_egress_proxy.grants import (
    GrantCreateRequest,
    GrantStore,
    GrantSubjectType,
)
from mindroom_egress_proxy.hostnames import (
    PolicyError,
    _public_resolved_addresses,
    _resolved_addresses,
    canonical_hostname,
    is_forbidden_resolved_address,
    normalize_reason,
)
from mindroom_egress_proxy.policy import EgressPolicy, StaticAllowlist
from mindroom_egress_proxy.service import (
    configure_logging,
    create_runtime_policy,
    run_service,
)
from mindroom_egress_proxy.settings import RuntimeSettings
from mindroom_egress_proxy.squid import (
    evaluate_squid_acl_request,
    run_squid_acl_helper,
    squid_command,
)
from mindroom_egress_proxy.workers import (
    KubernetesWorkerResolver,
    WorkerIdentity,
    worker_key_agent_name,
)

__all__ = [
    "DEFAULT_PROXY_PORT",
    "MAX_REASON_CHARS",
    "WORKER_ID_LABEL",
    "WORKER_KEY_ANNOTATION",
    "EgressPolicy",
    "GrantCreateRequest",
    "GrantStore",
    "GrantSubjectType",
    "KubernetesWorkerResolver",
    "PolicyError",
    "RuntimeSettings",
    "StaticAllowlist",
    "WorkerIdentity",
    "_public_resolved_addresses",
    "_resolved_addresses",
    "canonical_hostname",
    "configure_logging",
    "create_policy_api_app",
    "create_runtime_policy",
    "evaluate_squid_acl_request",
    "is_forbidden_resolved_address",
    "main",
    "normalize_reason",
    "parse_args",
    "run_service",
    "run_squid_acl_helper",
    "squid_command",
    "worker_key_agent_name",
]
