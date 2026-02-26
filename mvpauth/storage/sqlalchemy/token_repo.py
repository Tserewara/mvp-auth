from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from mvpauth.storage.sqlalchemy.models import BlockedTokenModel


class SQLAlchemyTokenBlocklistRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, *, jti: str, token_type: str, expires_at: datetime) -> None:
        blocked = BlockedTokenModel(
            jti=jti, token_type=token_type, expires_at=expires_at
        )
        self._session.add(blocked)
        await self._session.flush()

    async def is_blocked(self, jti: str) -> bool:
        result = await self._session.execute(
            select(BlockedTokenModel).where(BlockedTokenModel.jti == jti)
        )
        return result.scalar_one_or_none() is not None

    async def purge_expired(self) -> int:
        now = datetime.now(timezone.utc)
        result = await self._session.execute(
            delete(BlockedTokenModel).where(BlockedTokenModel.expires_at <= now)
        )
        await self._session.flush()
        return result.rowcount  # type: ignore[return-value]
