"""Session cookie shape (§9.8).

Two cookies, deliberately asymmetric:

- ``cairn_session`` is HttpOnly — JavaScript must never be able to read it, so
  an XSS anywhere in the workbench cannot exfiltrate a usable session.
- ``cairn_csrf`` is readable by design; the client echoes it back in
  ``X-CSRF-Token`` and the server compares that against the session row. A
  cross-site request can cause the session cookie to be sent, but cannot read
  the CSRF cookie to construct the header.

Both are ``SameSite=Strict`` and ``Secure`` by default; the deployment has to
opt out of ``Secure`` explicitly to run plain HTTP on localhost.
"""

from __future__ import annotations

from fastapi import Response

from cairn.server.auth.sessions import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    IssuedSession,
)


def set_session_cookies(
    response: Response,
    issued: IssuedSession,
    *,
    secure: bool,
    samesite: str,
    ttl_seconds: int,
) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        issued.token,
        max_age=ttl_seconds,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        issued.csrf_token,
        max_age=ttl_seconds,
        httponly=False,
        secure=secure,
        samesite=samesite,
        path="/",
    )


def clear_session_cookies(
    response: Response,
    *,
    secure: bool,
    samesite: str,
) -> None:
    for name in (SESSION_COOKIE_NAME, CSRF_COOKIE_NAME):
        response.delete_cookie(
            name,
            path="/",
            secure=secure,
            samesite=samesite,
            httponly=name == SESSION_COOKIE_NAME,
        )
