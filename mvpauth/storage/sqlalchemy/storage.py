from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from mvpauth.storage.sqlalchemy.models import Base
from mvpauth.storage.sqlalchemy.session_repo import SQLAlchemySessionRepository
from mvpauth.storage.sqlalchemy.token_repo import SQLAlchemyTokenBlocklistRepository
from mvpauth.storage.sqlalchemy.user_repo import SQLAlchemyUserRepository


class SQLAlchemyRequestStorage:
    """Per-request storage that wraps a single AsyncSession."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @property
    def user_repo(self) -> SQLAlchemyUserRepository:
        return SQLAlchemyUserRepository(self._session)

    @property
    def session_repo(self) -> SQLAlchemySessionRepository:
        return SQLAlchemySessionRepository(self._session)

    @property
    def blocklist_repo(self) -> SQLAlchemyTokenBlocklistRepository:
        return SQLAlchemyTokenBlocklistRepository(self._session)


class SQLAlchemyStorage:
    """Factory for SQLAlchemy-backed storage. Manages engine and session lifecycle."""

    def __init__(self, database_url: str, *, echo: bool = False) -> None:
        self._engine = create_async_engine(database_url, echo=echo)
        self._session_factory = async_sessionmaker(
            self._engine, expire_on_commit=False
        )

    async def create_tables(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    def get_session(self) -> AsyncSession:
        return self._session_factory()

    def request_storage(self, session: AsyncSession) -> SQLAlchemyRequestStorage:
        return SQLAlchemyRequestStorage(session)

    @property
    def user_repo(self) -> SQLAlchemyUserRepository:
        raise RuntimeError(
            "SQLAlchemyStorage requires per-request sessions. "
            "Use SQLAlchemyRequestStorage instead."
        )

    @property
    def session_repo(self) -> SQLAlchemySessionRepository:
        raise RuntimeError(
            "SQLAlchemyStorage requires per-request sessions. "
            "Use SQLAlchemyRequestStorage instead."
        )

    @property
    def blocklist_repo(self) -> SQLAlchemyTokenBlocklistRepository:
        raise RuntimeError(
            "SQLAlchemyStorage requires per-request sessions. "
            "Use SQLAlchemyRequestStorage instead."
        )
