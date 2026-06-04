"""Service assembly for the policy API and Squid proxy."""

from __future__ import annotations

import logging
import subprocess
import threading

import uvicorn

from mindroom_egress_proxy.api import create_policy_api_app
from mindroom_egress_proxy.grants import GrantStore
from mindroom_egress_proxy.policy import EgressPolicy, StaticAllowlist
from mindroom_egress_proxy.settings import RuntimeSettings
from mindroom_egress_proxy.squid import squid_command
from mindroom_egress_proxy.workers import KubernetesWorkerResolver

logger = logging.getLogger(__name__)


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
