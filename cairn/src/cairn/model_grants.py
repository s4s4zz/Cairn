"""Dependency-light model grant claims shared with sandbox workers.

Sandbox workers only need the model name carried by a short-lived grant so
they can shape a request for the LLM Gateway.  They do not verify or authorize
the grant: the Gateway still owns that responsibility and the signing key.

Keeping claim parsing here avoids making the hardened semantic image import
the Gateway's FastAPI-facing error and server modules.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
import json

from pydantic import Field, ValidationError, field_validator

from cairn.analysis.contracts import StrictModel

MAX_TOKEN_CHARS = 4096


class ModelGrant(StrictModel):
    """Claims carried by a short-lived, Gateway-enforced model capability."""

    audit_run_id: str = Field(min_length=1, max_length=255)
    task_id: str = Field(min_length=1, max_length=255)
    worker: str = Field(min_length=1, max_length=255)
    model: str = Field(min_length=1, max_length=255)
    expires_at: datetime
    max_requests: int = Field(ge=1, le=100_000)
    max_output_tokens: int = Field(ge=1, le=100_000_000)

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("audit_run_id", "task_id", "worker", "model")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("grant identifiers must not be blank")
        return stripped


_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(segment: str) -> bytes:
    if not segment or any(
        character not in _B64_ALPHABET for character in segment
    ):
        raise ValueError("segment is not unpadded base64url")
    padding = "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(segment + padding)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("segment is not valid base64url") from exc
    if b64url_encode(decoded) != segment:
        raise ValueError("segment is not canonically encoded")
    return decoded


def unverified_grant_model(token: str) -> str:
    """Read a model hint without authorizing the bearer grant.

    The worker uses this value only to construct its request.  The Gateway
    verifies the MAC, expiry, budget and exact model binding before egress.
    """

    if not token or len(token) > MAX_TOKEN_CHARS or not token.isascii():
        raise ValueError("model grant is malformed")
    encoded_payload, separator, _encoded_mac = token.partition(".")
    if separator != ".":
        raise ValueError("model grant is malformed")
    try:
        payload = json.loads(b64url_decode(encoded_payload))
        grant = ModelGrant.model_validate(payload)
    except (
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
    ) as exc:
        raise ValueError("model grant is malformed") from exc
    return grant.model
