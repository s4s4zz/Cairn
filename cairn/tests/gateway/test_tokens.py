from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
import json

from pydantic import ValidationError
import pytest

from cairn.gateway.errors import GatewayError
from cairn.gateway.tokens import (
    ModelGrant,
    grant_counter_key,
    mint_grant,
    verify_grant,
)
from cairn.gateway.tokens import _mac as compute_mac

SIGNING_KEY = b"grant-signing-key-0123456789abcdef"
OTHER_KEY = b"a-different-grant-key-0123456789ab"


def sample_grant(**overrides: object) -> ModelGrant:
    defaults: dict[str, object] = {
        "audit_run_id": "run-7f3a",
        "task_id": "task-19",
        "worker": "semantic-reviewer-2",
        "model": "claude-opus-5",
        "expires_at": datetime(2026, 7, 26, 12, 0, 0, 123456, tzinfo=UTC),
        "max_requests": 12,
        "max_output_tokens": 64_000,
    }
    defaults.update(overrides)
    return ModelGrant(**defaults)  # type: ignore[arg-type]


def before_expiry(grant: ModelGrant) -> datetime:
    return grant.expires_at - timedelta(seconds=1)


def forge(payload: bytes, key: bytes = SIGNING_KEY) -> str:
    """Build a token whose MAC is genuine for arbitrary payload bytes.

    Without this the payload-layer defences are unreachable: the constant-time
    MAC check rejects the token long before the JSON or Pydantic layer runs.
    """
    encode = lambda raw: base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{encode(payload)}.{encode(compute_mac(payload, key))}"


def test_minted_grant_round_trips_with_every_field_intact() -> None:
    grant = sample_grant()

    verified = verify_grant(
        mint_grant(grant, SIGNING_KEY),
        SIGNING_KEY,
        now=before_expiry(grant),
    )

    assert verified == grant
    assert verified.audit_run_id == "run-7f3a"
    assert verified.task_id == "task-19"
    assert verified.worker == "semantic-reviewer-2"
    assert verified.model == "claude-opus-5"
    assert verified.expires_at == grant.expires_at
    assert verified.max_requests == 12
    assert verified.max_output_tokens == 64_000


def test_minted_token_is_two_unpadded_base64url_segments() -> None:
    token = mint_grant(sample_grant(), SIGNING_KEY)

    payload_segment, separator, mac_segment = token.partition(".")

    assert separator == "."
    assert "=" not in token
    assert token.isascii()
    assert json.loads(base64.urlsafe_b64decode(payload_segment + "=="))["model"] == (
        "claude-opus-5"
    )
    assert len(base64.urlsafe_b64decode(mac_segment + "=")) == 32


def test_tampered_mac_is_rejected_as_grant_invalid() -> None:
    grant = sample_grant()
    payload_segment, _, mac_segment = mint_grant(grant, SIGNING_KEY).partition(".")
    flipped = ("B" if mac_segment[0] != "B" else "C") + mac_segment[1:]

    with pytest.raises(GatewayError) as excinfo:
        verify_grant(f"{payload_segment}.{flipped}", SIGNING_KEY, now=before_expiry(grant))

    assert excinfo.value.error_code == "LLM_GRANT_INVALID"
    assert excinfo.value.http_status == 401


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model", "attacker-controlled-model"),
        ("max_requests", 100_000),
        ("max_output_tokens", 100_000_000),
        ("audit_run_id", "some-other-run"),
    ],
)
def test_tampered_payload_with_untouched_mac_is_rejected(
    field: str,
    value: object,
) -> None:
    grant = sample_grant()
    token = mint_grant(grant, SIGNING_KEY)
    payload_segment, _, mac_segment = token.partition(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload_segment + "=="))
    decoded[field] = value
    re_encoded = (
        base64.urlsafe_b64encode(
            json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )

    with pytest.raises(GatewayError) as excinfo:
        verify_grant(f"{re_encoded}.{mac_segment}", SIGNING_KEY, now=before_expiry(grant))

    assert excinfo.value.error_code == "LLM_GRANT_INVALID"


def test_extending_expiry_in_the_payload_does_not_extend_the_grant() -> None:
    grant = sample_grant()
    token = mint_grant(grant, SIGNING_KEY)
    payload_segment, _, mac_segment = token.partition(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload_segment + "=="))
    decoded["expires_at"] = (grant.expires_at + timedelta(days=365)).isoformat()
    re_encoded = (
        base64.urlsafe_b64encode(
            json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )

    with pytest.raises(GatewayError) as excinfo:
        verify_grant(
            f"{re_encoded}.{mac_segment}",
            SIGNING_KEY,
            now=grant.expires_at + timedelta(days=1),
        )

    assert excinfo.value.error_code == "LLM_GRANT_INVALID"


def test_expired_grant_is_reported_distinctly_from_invalid() -> None:
    grant = sample_grant()
    token = mint_grant(grant, SIGNING_KEY)

    with pytest.raises(GatewayError) as excinfo:
        verify_grant(token, SIGNING_KEY, now=grant.expires_at + timedelta(seconds=1))

    assert excinfo.value.error_code == "LLM_GRANT_EXPIRED"
    assert excinfo.value.http_status == 401


def test_grant_expires_exactly_at_its_expiry_instant() -> None:
    grant = sample_grant()
    token = mint_grant(grant, SIGNING_KEY)

    with pytest.raises(GatewayError) as excinfo:
        verify_grant(token, SIGNING_KEY, now=grant.expires_at)

    assert excinfo.value.error_code == "LLM_GRANT_EXPIRED"


def test_naive_now_is_interpreted_as_utc() -> None:
    grant = sample_grant()
    token = mint_grant(grant, SIGNING_KEY)

    verified = verify_grant(
        token,
        SIGNING_KEY,
        now=grant.expires_at.replace(tzinfo=None) - timedelta(minutes=1),
    )

    assert verified == grant


def test_grant_signed_with_a_different_key_is_rejected() -> None:
    grant = sample_grant()
    token = mint_grant(grant, OTHER_KEY)

    with pytest.raises(GatewayError) as excinfo:
        verify_grant(token, SIGNING_KEY, now=before_expiry(grant))

    assert excinfo.value.error_code == "LLM_GRANT_INVALID"


def test_verification_without_a_key_is_rejected_rather_than_trusting_the_token() -> None:
    grant = sample_grant()

    with pytest.raises(GatewayError) as excinfo:
        verify_grant(mint_grant(grant, SIGNING_KEY), b"", now=before_expiry(grant))

    assert excinfo.value.error_code == "LLM_GRANT_INVALID"


def test_minting_without_a_key_is_refused() -> None:
    with pytest.raises(ValueError):
        mint_grant(sample_grant(), b"")


@pytest.mark.parametrize(
    ("token", "label"),
    [
        ("", "empty string"),
        ("   ", "whitespace only"),
        ("no-separator-at-all", "no dot"),
        (".", "bare separator"),
        (".onlymac", "empty payload segment"),
        ("onlypayload.", "empty mac segment"),
        ("!!!!.####", "characters outside base64url"),
        ("a b.c d", "embedded spaces"),
        ("eyJhIjoxfQ.$$$$", "bad base64 in the mac segment"),
        ("payloadé.mac", "non-ascii"),
        ("x" * 5000 + ".y", "absurdly long token"),
    ],
)
def test_malformed_tokens_are_rejected_without_a_traceback(
    token: str,
    label: str,
) -> None:
    with pytest.raises(GatewayError) as excinfo:
        verify_grant(token, SIGNING_KEY)

    assert excinfo.value.error_code == "LLM_GRANT_INVALID", label


@pytest.mark.parametrize(
    ("payload", "label"),
    [
        (b"[1, 2, 3]", "json list"),
        (b'"a bare string"', "json string"),
        (b"null", "json null"),
        (b"1234", "json number"),
        (b"not json at all", "not json"),
        (b"{}", "empty object"),
        (b'{"model": "claude-opus-5"}', "missing required fields"),
        (b"\xff\xfe\x00", "not utf-8"),
    ],
)
def test_genuinely_signed_but_structurally_wrong_payloads_are_rejected(
    payload: bytes,
    label: str,
) -> None:
    with pytest.raises(GatewayError) as excinfo:
        verify_grant(forge(payload), SIGNING_KEY)

    assert excinfo.value.error_code == "LLM_GRANT_INVALID", label


def test_signed_payload_with_unknown_extra_field_is_rejected() -> None:
    grant = sample_grant()
    decoded = json.loads(json.dumps(grant.model_dump(mode="json")))
    decoded["scope"] = "admin"
    payload = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")

    with pytest.raises(GatewayError) as excinfo:
        verify_grant(forge(payload), SIGNING_KEY, now=before_expiry(grant))

    assert excinfo.value.error_code == "LLM_GRANT_INVALID"


def test_non_canonical_base64_spelling_of_a_valid_token_is_rejected() -> None:
    grant = sample_grant()
    token = mint_grant(grant, SIGNING_KEY)
    payload_segment, _, mac_segment = token.partition(".")

    with pytest.raises(GatewayError) as excinfo:
        verify_grant(
            f"{payload_segment}=.{mac_segment}",
            SIGNING_KEY,
            now=before_expiry(grant),
        )

    assert excinfo.value.error_code == "LLM_GRANT_INVALID"


def test_grant_contract_rejects_blank_and_out_of_range_fields() -> None:
    with pytest.raises(ValidationError):
        sample_grant(worker="   ")
    with pytest.raises(ValidationError):
        sample_grant(max_requests=0)
    with pytest.raises(ValidationError):
        sample_grant(max_output_tokens=0)
    with pytest.raises(ValidationError):
        ModelGrant.model_validate(
            {**sample_grant().model_dump(mode="json"), "scope": "admin"}
        )


def test_naive_expiry_is_normalized_to_utc() -> None:
    grant = sample_grant(expires_at=datetime(2026, 7, 26, 12, 0, 0))

    assert grant.expires_at.tzinfo is not None
    assert grant.expires_at == datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)


def test_counter_key_is_stable_for_one_token_and_hides_the_signature() -> None:
    token = mint_grant(sample_grant(), SIGNING_KEY)

    key = grant_counter_key(token)

    assert key == grant_counter_key(token)
    assert len(key) == 64
    assert token not in key
    assert token.partition(".")[2] not in key


def test_counter_key_differs_for_grants_differing_only_in_expiry() -> None:
    first = sample_grant()
    second = sample_grant(expires_at=first.expires_at + timedelta(seconds=1))

    assert first.model_dump(exclude={"expires_at"}) == second.model_dump(
        exclude={"expires_at"}
    )
    assert grant_counter_key(mint_grant(first, SIGNING_KEY)) != grant_counter_key(
        mint_grant(second, SIGNING_KEY)
    )


def test_counter_key_differs_for_grants_differing_only_in_worker() -> None:
    first = mint_grant(sample_grant(worker="worker-a"), SIGNING_KEY)
    second = mint_grant(sample_grant(worker="worker-b"), SIGNING_KEY)

    assert grant_counter_key(first) != grant_counter_key(second)


def test_counter_key_survives_a_malformed_token_without_raising() -> None:
    assert len(grant_counter_key("not-a-token")) == 64
    assert len(grant_counter_key("")) == 64
