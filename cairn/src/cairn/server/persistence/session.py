from collections.abc import Generator, Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def configure_engine(database_url: str, sql_echo: bool = False) -> Engine:
    """Configure the process-wide engine, disposing any previous pool."""
    global _engine, _session_factory

    dispose_engine()
    _engine = create_engine(
        database_url,
        echo=sql_echo,
        pool_pre_ping=True,
    )
    _session_factory = sessionmaker(
        bind=_engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )
    return _engine


def dispose_engine() -> None:
    global _engine, _session_factory

    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


def _new_session() -> Session:
    if _session_factory is None:
        raise RuntimeError("database engine is not configured")
    return _session_factory()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = _new_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db_session() -> Generator[Session, None, None]:
    with session_scope() as session:
        yield session
