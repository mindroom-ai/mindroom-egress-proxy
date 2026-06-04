"""Command-line entrypoint for the egress proxy service."""

from __future__ import annotations

import argparse

from mindroom_egress_proxy.service import (
    configure_logging,
    create_runtime_policy,
    run_service,
)
from mindroom_egress_proxy.settings import RuntimeSettings
from mindroom_egress_proxy.squid import run_squid_acl_helper


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MindRoom approved egress policy service",
    )
    parser.add_argument("mode", nargs="?", choices=("serve", "helper"), default="serve")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    settings = RuntimeSettings()
    configure_logging(settings.log_level)
    if args.mode == "helper":
        run_squid_acl_helper(create_runtime_policy(settings))
        return
    run_service(settings)
