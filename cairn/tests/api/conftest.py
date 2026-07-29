from collections.abc import Callable, Generator
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from cairn.server.auth.passwords import Argon2Parameters, hash_password
from cairn.server.auth.sessions import CSRF_HEADER_NAME
from cairn.server.config import ServerSettings
from cairn.server.domain.enums import UserRole
from cairn.server.persistence.base import Base
from cairn.server.persistence.models.identity import User
from cairn.server.persistence.session import get_db_session


# Argon2id at production cost is ~100 ms per hash; the API suite logs in on
# nearly every test. These parameters keep the algorithm and the stored PHC
# format identical while making the suite runnable.
TEST_ARGON2 = Argon2Parameters(memory_kib=64, iterations=1, lanes=1)
TEST_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def session_factory() -> Generator[sessionmaker[Session], None, None]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record) -> None:  # noqa: ANN001
        del connection_record
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )
    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture
def client(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Generator[TestClient, None, None]:
    database_url = "sqlite+pysqlite:///:memory:"
    monkeypatch.setenv("CAIRN_DATABASE_URL", database_url)
    from cairn.server.app import create_app

    secret_key_file = tmp_path / "secret.key"
    secret_key_file.write_bytes(b"k" * 32)
    app = create_app(
        ServerSettings(
            database_url=database_url,
            artifact_root=tmp_path / "artifacts",
            ingestion_work_root=tmp_path / "ingestion",
            secret_key_file=secret_key_file,
            llm_provider_config_file=tmp_path / "llm" / "provider.json",
            git_allowed_hosts=["example.invalid"],
            # TestClient speaks plain HTTP, and a Secure cookie would never be
            # sent back — the whole suite would look unauthenticated.
            session_cookie_secure=False,
            password_hash_memory_kib=TEST_ARGON2.memory_kib,
            password_hash_iterations=TEST_ARGON2.iterations,
            password_hash_lanes=TEST_ARGON2.lanes,
        )
    )

    def override_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_db_session] = override_session
    with TestClient(app) as test_client:
        yield test_client


def create_account(
    session_factory: sessionmaker[Session],
    username: str,
    role: UserRole,
    *,
    password: str = TEST_PASSWORD,
    is_active: bool = True,
) -> User:
    session = session_factory()
    try:
        user = User(
            username=username,
            password_hash=hash_password(password, TEST_ARGON2),
            role=role.value,
            is_active=is_active,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
    finally:
        session.close()


def login(
    test_client: TestClient,
    username: str,
    password: str = TEST_PASSWORD,
) -> str:
    """Log in and arm the client with the CSRF header.

    Returns the CSRF token so a test can deliberately send a wrong one; the
    cookie jar of ``test_client`` carries the session from here on.
    """

    response = test_client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    csrf_token = response.json()["csrf_token"]
    test_client.headers[CSRF_HEADER_NAME] = csrf_token
    return csrf_token


@pytest.fixture
def login_as(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> Callable[[UserRole], TestClient]:
    """Create an account with the given role and log the shared client in."""

    def _login(role: UserRole, username: str | None = None) -> TestClient:
        name = username or f"{role.value}-user"
        create_account(session_factory, name, role)
        login(client, name)
        return client

    return _login


@pytest.fixture
def admin_client(login_as: Callable[[UserRole], TestClient]) -> TestClient:
    """The default client for tests about something other than authorisation.

    Every existing API test predates authentication; giving them an admin
    session keeps them testing what they were written to test.
    """

    return login_as(UserRole.ADMIN)
