from __future__ import annotations

import shutil

import mindroom_egress_proxy


def test_package_exposes_cli_entrypoint() -> None:
    assert mindroom_egress_proxy.main is not None
    assert shutil.which("mindroom-egress-proxy") is not None
