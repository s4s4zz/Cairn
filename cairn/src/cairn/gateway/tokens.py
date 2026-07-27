from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
import hashlib
import hmac
import json

from pydantic import Field, ValidationError, field_validator

from cairn.analysis.contracts import StrictModel
from cairn.gateway.errors import grant_expired, grant_invalid

GRANT_CONTEXT = b"cairn-model-grant-v1"
MAX_TOKEN_CHARS = 4096


class ModelGrant(StrictModel):
    """A short-lived capability bound to one AuditRun, task and worker.

    The budget ceiling travels inside the signed payload so the Gateway can
    enforce it without reaching the control plane (design spec §5.1 / §9.5).
    """

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


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(segment: str) -> bytes:
    if not segment or any(character not in _B64_ALPHABET for character in segment):
        raise ValueError("segment is not unpadded base64url")
    padding = "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(segment + padding)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("segment is not valid base64url") from exc
    if _b64encode(decoded) != segment:
        # Reject non-canonical encodings: a malleable token would otherwise
        # let one grant occupy more than one budget counter.
        raise ValueError("segment is not canonically encoded")
    return decoded


def _canonical_payload(grant: ModelGrant) -> bytes:
    return json.dumps(
        grant.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _mac(payload: bytes, key: bytes) -> bytes:
    return hmac.new(key, GRANT_CONTEXT + b"\0" + payload, hashlib.sha256).digest()


def mint_grant(grant: ModelGrant, key: bytes) -> str:
    """Serialize and sign a grant as ``base64url(payload).base64url(mac)``."""
    if not key:
        raise ValueError("grant signing key must not be empty")
    payload = _canonical_payload(grant)
    return f"{_b64encode(payload)}.{_b64encode(_mac(payload, key))}"


def verify_grant(
    token: str,
    key: bytes,
    *,
    now: datetime | None = None,
    max_lifetime_seconds: float | None = None,
) -> ModelGrant:
    """Verify a grant token and return its payload.

    The MAC is checked in constant time *before* the payload is parsed, so a
    forged token never reaches the JSON or Pydantic layer. Structural problems
    all collapse to ``LLM_GRANT_INVALID`` so the caller learns nothing about
    which part of the token was wrong; only expiry is reported distinctly.
    """
    if not key:
        raise grant_invalid()
    if not token or len(token) > MAX_TOKEN_CHARS or not token.isascii():
        raise grant_invalid()
    encoded_payload, separator, encoded_mac = token.partition(".")
    if separator != "." or not encoded_payload or not encoded_mac:
        raise grant_invalid()
    try:
        payload = _b64decode(encoded_payload)
        supplied_mac = _b64decode(encoded_mac)
    except ValueError:
        raise grant_invalid() from None
    if not hmac.compare_digest(supplied_mac, _mac(payload, key)):
        raise grant_invalid()
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise grant_invalid() from None
    if not isinstance(decoded, dict):
        raise grant_invalid()
    try:
        grant = ModelGrant.model_validate(decoded)
    except ValidationError:
        raise grant_invalid() from None
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    if grant.expires_at <= moment:
        raise grant_expired()
    if max_lifetime_seconds is not None:
        # A grant whose expiry is further out than the Gateway is willing to
        # honour is not short-lived, whatever the minter intended. §9.5 puts
        # that judgement at the verifier, so a buggy or misconfigured issuer
        # cannot mint what amounts to a permanent bearer credential.
        if (grant.expires_at - moment).total_seconds() > max_lifetime_seconds:
            raise grant_invalid("Model grant lifetime exceeds the permitted maximum")
    return grant


def grant_counter_key(token: str) -> str:
    """Stable per-grant budget key derived from the token's MAC segment.

    Hashing the *decoded* MAC bytes keeps the key stable under any base64
    spelling of the same signature, and keeps the credential material itself
    out of in-memory dictionary keys.
    """
    _, separator, encoded_mac = token.rpartition(".")
    segment = encoded_mac if separator == "." and encoded_mac else token
    try:
        material = _b64decode(segment)
    except ValueError:
        material = segment.encode("utf-8", errors="replace")
    return hashlib.sha256(b"cairn-grant-counter-v1\0" + material).hexdigest()
