from collections.abc import Generator
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from cairn.server.config import ServerSettings
from cairn.server.persistence.base import Base
from cairn.server.persistence.session import get_db_session


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
            git_allowed_hosts=["example.invalid"],
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
