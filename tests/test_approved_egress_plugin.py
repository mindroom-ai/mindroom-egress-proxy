from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
import os
import sys
import tempfile
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).parents[1] / "plugins" / "approved-egress"
MANIFEST_PATH = PLUGIN_DIR / "mindroom.plugin.json"
MODULE_PATH = PLUGIN_DIR / "tools.py"


def _install_stub_modules() -> None:
    agno = types.ModuleType("agno")
    agno_tools = types.ModuleType("agno.tools")

    class Function:
        def __init__(
            self,
            *,
            name: str,
            entrypoint: object,
            description: str | None = None,
        ) -> None:
            self.name = name
            self.entrypoint = entrypoint
            self.description = (
                description if description is not None else inspect.getdoc(entrypoint)
            )

    class Toolkit:
        def __init__(self, **kwargs: object) -> None:
            self.name = kwargs.get("name")
            self.instructions = kwargs.get("instructions")
            self.functions: dict[str, Function] = {}
            self.async_functions: dict[str, Function] = {}
            for tool in kwargs.get("tools") or []:
                name = tool.__name__
                function = Function(name=name, entrypoint=tool)
                if inspect.iscoroutinefunction(tool):
                    self.async_functions[name] = function
                else:
                    self.functions[name] = function

    agno_tools.Toolkit = Toolkit
    agno.tools = agno_tools
    sys.modules["agno"] = agno
    sys.modules["agno.tools"] = agno_tools

    metadata = types.ModuleType("mindroom.tool_system.metadata")
    metadata.SetupType = types.SimpleNamespace(SPECIAL="special")
    metadata.ToolCategory = types.SimpleNamespace(INTEGRATIONS="integrations")
    metadata.ToolStatus = types.SimpleNamespace(AVAILABLE="available")
    metadata.register_tool_with_metadata = lambda **_kwargs: lambda func: func
    sys.modules["mindroom.tool_system.metadata"] = metadata

    runtime_context = types.ModuleType("mindroom.tool_system.runtime_context")
    runtime_context.get_tool_runtime_context = lambda: None
    runtime_context.build_execution_identity_from_runtime_context = lambda _context: (
        None
    )
    sys.modules["mindroom.tool_system.runtime_context"] = runtime_context

    worker_routing = types.ModuleType("mindroom.tool_system.worker_routing")
    worker_routing.resolve_worker_key = lambda *_args, **_kwargs: None
    sys.modules["mindroom.tool_system.worker_routing"] = worker_routing


def _load_tools_module():
    _install_stub_modules()
    spec = importlib.util.spec_from_file_location("approved_egress_tools", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _restore_environment() -> Any:
    old_environ = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(old_environ)


def test_plugin_artifact_has_mindroom_manifest() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest == {"name": "approved-egress", "tools_module": "tools.py"}
    assert MODULE_PATH.exists()
    assert (PLUGIN_DIR / "README.md").exists()


def test_request_network_access_skips_grant_when_static_allowed() -> None:
    tools = _load_tools_module()
    posted = False

    with tempfile.TemporaryDirectory() as temp_dir:
        allowlist_path = Path(temp_dir) / "allowed-domains.txt"
        allowlist_path.write_text(".example.com\n", encoding="utf-8")
        os.environ["MINDROOM_APPROVED_EGRESS_ALLOWLIST_PATH"] = str(allowlist_path)

        def post_grant(_payload: dict[str, object]) -> dict[str, object]:
            nonlocal posted
            posted = True
            return {"expires_at": 123}

        old_post_grant = tools._post_grant
        try:
            tools._post_grant = post_grant
            result = asyncio.run(
                tools.ApprovedEgressTools().request_network_access(
                    "docs.example.com",
                    5,
                    "Need docs",
                ),
            )
        finally:
            tools._post_grant = old_post_grant

    assert posted is False
    assert "already allowed" in result
    assert "No temporary grant was created" in result


def test_request_network_access_posts_grant_to_fake_policy_api() -> None:
    tools = _load_tools_module()
    captured: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["content-length"]))
            captured["path"] = self.path
            captured["authorization"] = self.headers["authorization"]
            captured["payload"] = json.loads(body.decode("utf-8"))
            response = json.dumps({"ok": True, "grant": {"expires_at": 123}}).encode()
            self.send_response(201)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    os.environ["MINDROOM_APPROVED_EGRESS_API_URL"] = (
        f"http://127.0.0.1:{server.server_port}"
    )
    os.environ["MINDROOM_APPROVED_EGRESS_TOKEN"] = "token"

    class Config:
        def get_agent_execution_scope(self, agent_name: str) -> str:
            self.agent_name = agent_name
            return "user_agent"

    context = types.SimpleNamespace(
        agent_name="assistant",
        room_id="!room:server",
        resolved_thread_id=None,
        thread_id="$thread",
        requester_id="@user:server",
        config=Config(),
        runtime_paths=object(),
    )
    old_context = tools.get_tool_runtime_context
    old_identity = tools.build_execution_identity_from_runtime_context
    old_resolve_worker_key = tools.resolve_worker_key
    try:
        tools.get_tool_runtime_context = lambda: context
        tools.build_execution_identity_from_runtime_context = lambda _context: object()
        tools.resolve_worker_key = lambda *_args, **_kwargs: (
            "v1:default:user_agent:@user:server:assistant"
        )

        result = asyncio.run(
            tools.ApprovedEgressTools().request_network_access(
                "docs.example.com",
                5,
                "Need docs",
            ),
        )
    finally:
        tools.get_tool_runtime_context = old_context
        tools.build_execution_identity_from_runtime_context = old_identity
        tools.resolve_worker_key = old_resolve_worker_key
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert result.startswith("Approved temporary network access to docs.example.com")
    assert captured["path"] == "/grants"
    assert captured["authorization"] == "Bearer token"
    assert captured["payload"] == {
        "agent_name": "assistant",
        "approved_by": "@user:server",
        "hostname": "docs.example.com",
        "reason": "Need docs",
        "requester_id": "@user:server",
        "room_id": "!room:server",
        "subject": "v1:default:user_agent:@user:server:assistant",
        "subject_type": "worker_key",
        "thread_id": "$thread",
        "ttl_seconds": 300,
    }


def test_shared_agent_requests_agent_scoped_grant() -> None:
    tools = _load_tools_module()
    captured: dict[str, object] = {}

    class Config:
        def get_agent_execution_scope(self, agent_name: str) -> str:
            self.agent_name = agent_name
            return "shared"

    context = types.SimpleNamespace(
        agent_name="shared_assistant",
        room_id="!room:server",
        resolved_thread_id=None,
        thread_id="$thread",
        requester_id="@user:server",
        config=Config(),
        runtime_paths=object(),
    )
    old_context = tools.get_tool_runtime_context
    old_post_grant = tools._post_grant
    try:
        tools.get_tool_runtime_context = lambda: context
        tools._post_grant = lambda payload: (
            captured.setdefault(
                "payload",
                payload,
            )
            or {"expires_at": 123}
        )

        asyncio.run(
            tools.ApprovedEgressTools().request_network_access(
                "docs.example.com",
                5,
                "Need docs",
            ),
        )
    finally:
        tools.get_tool_runtime_context = old_context
        tools._post_grant = old_post_grant

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["subject_type"] == "agent"
    assert payload["subject"] == "shared_assistant"
