import base64
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidKey
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.auth.passwords import (
    Argon2Parameters,
    hash_password,
    needs_rehash,
    verify_password,
)
from cairn.server.auth.sessions import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
from cairn.server.domain.enums import UserRole
from cairn.server.persistence.models.identity import AuditLogEntry, User, UserSession

from .conftest import TEST_ARGON2, TEST_PASSWORD, create_account, login


def _phc(
    *,
    memory_kib: int = 64,
    iterations: int = 1,
    lanes: int = 1,
    salt: bytes = b"s" * 16,
    digest: bytes = b"d" * 32,
) -> str:
    def encode(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii").rstrip("=")

    return (
        "$argon2id$v=19"
        f"$m={memory_kib},t={iterations},p={lanes}"
        f"${encode(salt)}${encode(digest)}"
    )


def test_password_hash_is_salted_and_verifiable() -> None:
    first = hash_password(TEST_PASSWORD, TEST_ARGON2)
    second = hash_password(TEST_PASSWORD, TEST_ARGON2)

    assert first != second, "identical passwords must not produce identical hashes"
    assert first.startswith("$argon2id$v=19$")
    assert TEST_PASSWORD not in first
    assert verify_password(TEST_PASSWORD, first)
    assert not verify_password(TEST_PASSWORD + "x", first)


def test_malformed_hash_fails_verification_without_raising() -> None:
    assert not verify_password(TEST_PASSWORD, "not-a-phc-string")
    assert needs_rehash("not-a-phc-string")


@pytest.mark.parametrize(
    "encoded",
    [
        _phc(salt=b"s" * 15),
        _phc(salt=b"s" * 17),
        _phc(digest=b"d" * 31),
        _phc(digest=b"d" * 33),
        _phc(memory_kib=7),
        _phc(memory_kib=4_194_305),
        _phc(iterations=0),
        _phc(iterations=65),
        _phc(lanes=0),
        _phc(memory_kib=1024, lanes=65),
        _phc(memory_kib=64, lanes=9),
    ],
)
def test_invalid_phc_lengths_and_parameters_fail_closed(encoded: str) -> None:
    assert not verify_password(TEST_PASSWORD, encoded)
    assert needs_rehash(encoded, TEST_ARGON2)


def test_argon2_constructor_errors_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import cairn.server.auth.passwords as password_module

    encoded = hash_password(TEST_PASSWORD, TEST_ARGON2)

    def fail_constructor(**_kwargs: object) -> object:
        raise ValueError("invalid argon2 parameters")

    monkeypatch.setattr(password_module, "Argon2id", fail_constructor)

    assert not verify_password(TEST_PASSWORD, encoded)
    assert needs_rehash(encoded, TEST_ARGON2)


def test_argon2_verify_errors_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import cairn.server.auth.passwords as password_module

    encoded = hash_password(TEST_PASSWORD, TEST_ARGON2)

    class FailingVerifier:
        def verify(self, _password: bytes, _expected: bytes) -> None:
            raise InvalidKey

    monkeypatch.setattr(
        password_module,
        "Argon2id",
        lambda **_kwargs: FailingVerifier(),
    )

    assert not verify_password(TEST_PASSWORD, encoded)


def test_weaker_stored_parameters_are_flagged_for_rehash() -> None:
    weak = hash_password(TEST_PASSWORD, Argon2Parameters(memory_kib=64, iterations=1, lanes=1))

    assert needs_rehash(weak, Argon2Parameters(memory_kib=128, iterations=2, lanes=1))
    assert not needs_rehash(weak, Argon2Parameters(memory_kib=64, iterations=1, lanes=1))


def test_login_sets_httponly_session_and_readable_csrf_cookie(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "auditor-one", UserRole.AUDITOR)

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "auditor-one", "password": TEST_PASSWORD},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["username"] == "auditor-one"
    assert body["user"]["role"] == "auditor"
    assert body["csrf_token"]
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith(f"{SESSION_COOKIE_NAME}="))
    csrf_cookie = next(c for c in cookies if c.startswith(f"{CSRF_COOKIE_NAME}="))
    assert "HttpOnly" in session_cookie
    assert "SameSite=strict" in session_cookie.replace("Strict", "strict")
    assert "HttpOnly" not in csrf_cookie


def test_session_token_is_never_stored_in_plaintext(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "auditor-two", UserRole.AUDITOR)
    csrf_token = login(client, "auditor-two")
    session_token = client.cookies[SESSION_COOKIE_NAME]

    session = session_factory()
    try:
        record = session.scalars(select(UserSession)).one()
        assert record.token_sha256 != session_token.encode()
        assert len(record.token_sha256) == 32
        assert record.csrf_sha256 != csrf_token.encode()
    finally:
        session.close()


def test_unknown_user_and_wrong_password_are_indistinguishable(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "auditor-three", UserRole.AUDITOR)

    wrong_password = client.post(
        "/api/v1/auth/login",
        json={"username": "auditor-three", "password": "wrong-password-here"},
    )
    unknown_user = client.post(
        "/api/v1/auth/login",
        json={"username": "nobody", "password": "wrong-password-here"},
    )

    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["error_code"] == unknown_user.json()["error_code"]
    assert wrong_password.json()["error_code"] == "invalid_credentials"


def test_malformed_stored_hash_is_an_invalid_login_not_a_server_error(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    user = create_account(session_factory, "corrupt-password", UserRole.AUDITOR)
    session = session_factory()
    try:
        session.get(User, user.id).password_hash = _phc(digest=b"short")
        session.commit()
    finally:
        session.close()

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "corrupt-password", "password": TEST_PASSWORD},
    )

    assert response.status_code == 401
    assert response.json()["error_code"] == "invalid_credentials"


def test_failed_login_is_audited_and_survives_the_error(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "auditor-four", UserRole.AUDITOR)

    client.post(
        "/api/v1/auth/login",
        json={"username": "auditor-four", "password": "wrong-password-here"},
    )

    session = session_factory()
    try:
        entry = session.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == "login_failed")
        ).one()
        assert entry.actor_username == "auditor-four"
        assert entry.outcome == "denied"
        assert entry.http_status == 401
        assert "wrong-password-here" not in str(entry.detail)
    finally:
        session.close()


def test_disabled_account_cannot_log_in(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "retired", UserRole.AUDITOR, is_active=False)

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "retired", "password": TEST_PASSWORD},
    )

    assert response.status_code == 401


def test_disabling_an_account_ends_its_live_session(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    user = create_account(session_factory, "soon-gone", UserRole.AUDITOR)
    login(client, "soon-gone")
    assert client.get("/api/v1/repositories").status_code == 200

    session = session_factory()
    try:
        session.get(User, user.id).is_active = False
        session.commit()
    finally:
        session.close()

    assert client.get("/api/v1/repositories").status_code == 401


def test_expired_session_is_refused(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "expiring", UserRole.AUDITOR)
    login(client, "expiring")

    session = session_factory()
    try:
        record = session.scalars(select(UserSession)).one()
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    finally:
        session.close()

    assert client.get("/api/v1/repositories").status_code == 401


def test_logout_revokes_the_session(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "leaving", UserRole.AUDITOR)
    login(client, "leaving")

    assert client.post("/api/v1/auth/logout").status_code == 204
    assert client.get("/api/v1/repositories").status_code == 401


def test_unauthenticated_requests_are_refused(client: TestClient) -> None:
    for method, path in (
        ("get", "/api/v1/repositories"),
        ("get", "/api/v1/findings"),
        ("get", "/api/v1/audit-runs"),
        ("post", "/api/v1/repositories"),
    ):
        response = client.request(method, path, json={})
        assert response.status_code == 401, path
        assert response.json()["error_code"] == "authentication_required"


@pytest.mark.parametrize("header", [None, "not-the-right-token"])
def test_writes_require_a_matching_csrf_header(
    client: TestClient,
    session_factory: sessionmaker[Session],
    header: str | None,
) -> None:
    create_account(session_factory, "csrf-user", UserRole.ADMIN)
    login(client, "csrf-user")
    if header is None:
        del client.headers[CSRF_HEADER_NAME]
    else:
        client.headers[CSRF_HEADER_NAME] = header

    response = client.post("/api/v1/audit-policies", json={"name": "p"})

    assert response.status_code == 403
    assert response.json()["error_code"] == "csrf_token_invalid"


def test_reads_do_not_require_the_csrf_header(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "reader", UserRole.VIEWER)
    login(client, "reader")
    del client.headers[CSRF_HEADER_NAME]

    assert client.get("/api/v1/findings").status_code == 200


def test_me_returns_the_current_account(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "who-am-i", UserRole.REVIEWER)
    login(client, "who-am-i")

    response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert response.json()["username"] == "who-am-i"
    assert response.json()["role"] == "reviewer"


def test_self_service_password_change_revokes_every_session(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "rotating", UserRole.AUDITOR)
    login(client, "rotating")

    response = client.post(
        "/api/v1/auth/password",
        json={
            "current_password": TEST_PASSWORD,
            "new_password": "a-brand-new-passphrase",
        },
    )

    assert response.status_code == 204
    assert client.get("/api/v1/repositories").status_code == 401
    login(client, "rotating", "a-brand-new-passphrase")
    assert client.get("/api/v1/repositories").status_code == 200
