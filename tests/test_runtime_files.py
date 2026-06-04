from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_squid_config_invokes_packaged_helper_directly() -> None:
    squid_config = (PROJECT_ROOT / "squid.conf").read_text()

    assert "/app/.venv/bin/mindroom-egress-proxy helper" in squid_config
    assert "squid-acl-helper" not in squid_config


def test_dockerfile_does_not_install_helper_wrapper() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text()

    assert "squid-acl-helper" not in dockerfile
