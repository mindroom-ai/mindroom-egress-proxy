"""Kubernetes worker identity resolution."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from kubernetes import client, config
from kubernetes.client import ApiException
from kubernetes.config.config_exception import ConfigException

from mindroom_egress_proxy.constants import (
    DEFAULT_WORKER_CACHE_SECONDS,
    USER_AGENT_WORKER_KEY_MIN_PARTS,
    WORKER_ID_LABEL,
    WORKER_KEY_ANNOTATION,
    WORKER_KEY_MIN_PARTS,
)

logger = logging.getLogger(__name__)


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
