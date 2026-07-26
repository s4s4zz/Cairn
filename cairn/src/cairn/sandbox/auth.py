from __future__ import annotations

import hmac

from fastapi import Request

from cairn.sandbox.errors import SandboxError


def require_internal_auth(request: Request) -> None:
    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied = authorization.partition(" ")
    expected: bytes = request.app.state.auth_token
    if (
        separator != " "
        or scheme.lower() != "bearer"
        or not supplied
        or not hmac.compare_digest(supplied.encode("utf-8"), expected)
    ):
        raise SandboxError(
            "SANDBOX_UNAUTHORIZED",
            "Sandbox API authentication failed",
            http_status=401,
        )
