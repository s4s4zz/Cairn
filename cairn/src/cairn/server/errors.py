from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from cairn.server.schemas.common import ErrorResponse


class DomainError(Exception):
    def __init__(self, error_code: str, message: str, http_status: int) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.http_status = http_status


class NotFoundError(DomainError):
    def __init__(self, resource: str, identifier: object) -> None:
        super().__init__(
            f"{resource}_not_found",
            f"{resource} {identifier} was not found",
            404,
        )


class ConflictError(DomainError):
    def __init__(self, message: str, *, error_code: str = "conflict") -> None:
        super().__init__(error_code, message, 409)


class InvalidStateError(DomainError):
    def __init__(self, message: str, *, error_code: str = "invalid_state") -> None:
        super().__init__(error_code, message, 409)


class IngestionError(DomainError):
    def __init__(
        self,
        error_code: str,
        message: str,
        *,
        http_status: int = 422,
    ) -> None:
        super().__init__(error_code, message, http_status)


def ensure_request_id(request: Request) -> str:
    """The stable per-request identifier every error body and audit row carries.

    Assigned on first use and cached on ``request.state`` so an error response
    and the audit-log row written by the same request name the same id.
    """

    existing = getattr(request.state, "request_id", None)
    if existing:
        return str(existing)
    supplied = request.headers.get("X-Request-ID", "").strip()
    request_id = supplied[:128] if supplied else uuid4().hex
    request.state.request_id = request_id
    return request_id


def _error_response(
    request: Request,
    *,
    error_code: str,
    message: str,
    status_code: int,
) -> JSONResponse:
    request_id = ensure_request_id(request)
    body = ErrorResponse(
        error_code=error_code,
        message=message,
        request_id=request_id,
    )
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json"),
        headers={"X-Request-ID": request_id},
    )


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def handle_domain_error(
        request: Request,
        exc: DomainError,
    ) -> JSONResponse:
        return _error_response(
            request,
            error_code=exc.error_code,
            message=exc.message,
            status_code=exc.http_status,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return _error_response(
            request,
            error_code="invalid_request",
            message="request validation failed",
            status_code=422,
        )
