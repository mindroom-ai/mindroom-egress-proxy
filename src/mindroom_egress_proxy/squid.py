"""Squid helper protocol and process command helpers."""

from __future__ import annotations

import sys
import unicodedata
from urllib.parse import unquote

from mindroom_egress_proxy.constants import MAX_PORT
from mindroom_egress_proxy.policy import EgressPolicy
from mindroom_egress_proxy.settings import RuntimeSettings


def _valid_port(value: int | str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer") from exc
    if port <= 0 or port > MAX_PORT:
        raise ValueError("port is out of range")
    return port


def _squid_quote(value: str) -> str:
    cleaned = "".join(
        " " if char.isspace() or unicodedata.category(char)[0] == "C" else char
        for char in str(value)
    )
    normalized = " ".join(cleaned.split()) or "egress denied"
    escaped = normalized.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def evaluate_squid_acl_request(line: str, policy: EgressPolicy) -> str:
    """Evaluate one Squid external_acl_type helper request line."""
    try:
        source_ip, hostname, raw_port, _method = line.strip().split(maxsplit=3)
        port = _valid_port(unquote(raw_port))
        allowed, reason, _connect_address = policy.is_allowed(
            source_ip=unquote(source_ip), hostname=unquote(hostname), port=port
        )
    except Exception as exc:  # noqa: BLE001
        # Squid helpers must fail closed on malformed input or policy errors.
        return f"ERR message={_squid_quote(str(exc))}"
    if allowed:
        return f"OK log={_squid_quote(reason)}"
    return f"ERR message={_squid_quote(reason)}"


def run_squid_acl_helper(policy: EgressPolicy) -> None:
    """Run Squid's line-oriented external ACL helper protocol on stdin/stdout."""
    for line in sys.stdin:
        sys.stdout.write(f"{evaluate_squid_acl_request(line, policy)}\n")
        sys.stdout.flush()


def squid_command(settings: RuntimeSettings) -> list[str]:
    return ["squid", "-N", "-f", settings.squid_config_path]
