"""Hostname, DNS, and approval-text validation."""

from __future__ import annotations

import ipaddress
import unicodedata

import dns.exception
import dns.resolver
import idna

from mindroom_egress_proxy.constants import (
    FORBIDDEN_HOST_SUFFIXES,
    FORBIDDEN_HOSTNAMES,
    MAX_DNS_LABEL_LENGTH,
    MAX_DNS_NAME_LENGTH,
    MAX_REASON_CHARS,
    MIN_DNS_LABELS,
)


class PolicyError(RuntimeError):
    """One expected policy denial reason."""


def _raw_hostname(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("hostname must be a string")
    raw = value.strip().rstrip(".")
    if not raw:
        raise ValueError("hostname must not be empty")
    if "://" in raw or any(part in raw for part in ("/", "?", "#", "@")):
        raise ValueError(
            "hostname must not include a scheme, path, query, or credentials",
        )
    if "*" in raw:
        raise ValueError("hostname wildcards are not supported")
    if ":" in raw:
        raise ValueError("hostname must not include a port")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValueError("IP literals are not valid dynamic egress hostnames")
    return raw


def _idna_hostname(raw: str) -> str:
    try:
        return idna.encode(raw, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise ValueError("hostname is not valid IDNA") from exc


def _validate_external_hostname(normalized: str) -> None:
    if len(normalized) > MAX_DNS_NAME_LENGTH:
        raise ValueError("hostname is too long")
    labels = normalized.split(".")
    if len(labels) < MIN_DNS_LABELS:
        raise ValueError("hostname must be a fully-qualified external DNS name")
    if any(not label for label in labels):
        raise ValueError("hostname contains an empty label")
    for label in labels:
        if len(label) > MAX_DNS_LABEL_LENGTH:
            raise ValueError("hostname label is too long")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("hostname labels must not start or end with '-'")
        if not all(char.isalnum() or char == "-" for char in label):
            raise ValueError("hostname contains unsupported characters")
    if normalized in FORBIDDEN_HOSTNAMES or normalized.endswith(
        FORBIDDEN_HOST_SUFFIXES,
    ):
        raise ValueError("hostname points at an internal name")


def canonical_hostname(value: str) -> str:
    """Return a normalized exact hostname or raise ValueError."""
    normalized = _idna_hostname(_raw_hostname(value))
    _validate_external_hostname(normalized)
    return normalized


def is_forbidden_resolved_address(value: str) -> bool:
    """Return whether a resolved address is forbidden for dynamic grants."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _resolved_addresses(hostname: str) -> set[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 5.0
    try:
        answers = resolver.resolve_name(hostname)
    except dns.resolver.NXDOMAIN as exc:
        raise OSError("hostname did not resolve") from exc
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ) as exc:
        raise OSError("hostname did not resolve") from exc
    canonical_name = str(answers.canonical_name()).rstrip(".")
    if canonical_name:
        canonical_hostname(canonical_name)
    addresses = set(answers.addresses())
    if not addresses:
        raise OSError("hostname did not resolve")
    return addresses


def _public_resolved_addresses(hostname: str) -> list[str]:
    addresses = _resolved_addresses(hostname)
    if not addresses:
        raise PolicyError("hostname did not resolve")
    forbidden = sorted(
        address for address in addresses if is_forbidden_resolved_address(address)
    )
    if forbidden:
        raise PolicyError("hostname resolved to a forbidden address range")
    return sorted(addresses)


def normalize_reason(value: str) -> str:
    """Return a log- and approval-safe reason string."""
    if not isinstance(value, str):
        raise ValueError("reason must be a string")
    cleaned = "".join(
        " " if char.isspace() or unicodedata.category(char)[0] == "C" else char
        for char in value
    )
    normalized = " ".join(cleaned.split())
    if not normalized:
        raise ValueError("reason must not be empty")
    return normalized[:MAX_REASON_CHARS]
