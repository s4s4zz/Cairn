from __future__ import annotations

from cairn.server.errors import DomainError


class GatewayError(DomainError):
    """Policy rejection raised by the LLM Gateway."""

    def __init__(
        self,
        error_code: str,
        message: str,
        *,
        http_status: int = 422,
    ) -> None:
        super().__init__(error_code, message, http_status)


def grant_invalid(message: str = "Model grant is invalid") -> GatewayError:
    return GatewayError("LLM_GRANT_INVALID", message, http_status=401)


def grant_expired() -> GatewayError:
    return GatewayError(
        "LLM_GRANT_EXPIRED",
        "Model grant has expired",
        http_status=401,
    )


def model_not_allowed() -> GatewayError:
    return GatewayError(
        "LLM_MODEL_NOT_ALLOWED",
        "Requested model is not permitted for this grant",
        http_status=403,
    )


def request_too_large() -> GatewayError:
    return GatewayError(
        "LLM_REQUEST_TOO_LARGE",
        "Request body exceeds the configured limit",
        http_status=413,
    )


def budget_exhausted() -> GatewayError:
    return GatewayError(
        "LLM_BUDGET_EXHAUSTED",
        "Model grant budget is exhausted",
        http_status=429,
    )


def upstream_timeout() -> GatewayError:
    return GatewayError(
        "LLM_UPSTREAM_TIMEOUT",
        "Upstream model API timed out",
        http_status=504,
    )


def upstream_unavailable() -> GatewayError:
    return GatewayError(
        "LLM_UPSTREAM_UNAVAILABLE",
        "Upstream model API is unavailable",
        http_status=502,
    )


def circuit_open() -> GatewayError:
    return GatewayError(
        "LLM_CIRCUIT_OPEN",
        "Upstream model API circuit is open",
        http_status=503,
    )


def request_invalid(message: str = "Request body is not a valid Messages call") -> GatewayError:
    return GatewayError("LLM_REQUEST_INVALID", message, http_status=422)


def tool_not_allowed(
    message: str = "Only custom tools may be declared through the Gateway",
) -> GatewayError:
    return GatewayError("LLM_TOOL_NOT_ALLOWED", message, http_status=403)
