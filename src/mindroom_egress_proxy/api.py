"""FastAPI policy API for dynamic egress grants."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from mindroom_egress_proxy.grants import GrantCreateRequest, GrantStore


def _error_response(status_code: int, error: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"ok": False, "error": error})


def _validation_error_message(exc: RequestValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "invalid request"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", []) if part != "body")
    message = str(first.get("msg", "invalid request"))
    return f"{location}: {message}" if location else message


def create_policy_api_app(
    *,
    grant_store: GrantStore,
    bearer_token: str,
    max_ttl_seconds: int,
) -> FastAPI:
    """Create the FastAPI policy API used by the MindRoom control plane."""
    app = FastAPI(
        title="MindRoom Approved Egress Policy API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return _error_response(
            HTTPStatus.BAD_REQUEST.value,
            _validation_error_message(exc),
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        _request: Request,
        exc: HTTPException,
    ) -> JSONResponse:
        return _error_response(exc.status_code, str(exc.detail))

    def require_authorization(authorization: str | None = Header(default=None)) -> None:
        expected = f"Bearer {bearer_token}"
        if not bearer_token or authorization != expected:
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED.value,
                detail="unauthorized",
            )

    @app.get("/healthz")
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/grants")
    def list_grants(
        _authorized: None = Depends(require_authorization),
    ) -> dict[str, Any]:
        return {"grants": grant_store.list_active_grants()}

    @app.post("/grants", status_code=HTTPStatus.CREATED.value)
    def create_grant(
        payload: GrantCreateRequest,
        _authorized: None = Depends(require_authorization),
    ) -> dict[str, Any]:
        try:
            ttl_seconds = min(payload.ttl_seconds, max_ttl_seconds)
            grant = grant_store.create_grant(
                hostname=payload.hostname,
                subject_type=payload.subject_type.value,
                subject=payload.subject,
                agent_name=payload.agent_name,
                requester_id=payload.requester_id,
                room_id=payload.room_id,
                thread_id=payload.thread_id,
                ttl_seconds=ttl_seconds,
                approved_by=payload.approved_by,
                reason=payload.reason,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST.value,
                detail=str(exc),
            ) from exc
        return {"ok": True, "grant": grant}

    return app
