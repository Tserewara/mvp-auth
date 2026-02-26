from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from mvpauth.core.schemas import SessionData
from mvpauth.storage.sqlalchemy.models import SessionModel


class SQLAlchemySessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        user_id: uuid.UUID,
        refresh_token_hash: str,
        device_info: str | None = None,
        ip_address: str | None = None,
        expires_at: datetime,
    ) -> SessionData:
        db_session = SessionModel(
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            device_info=device_info,
            ip_address=ip_address,
            expires_at=expires_at,
        )
        self._session.add(db_session)
        await self._session.flush()
        await self._session.refresh(db_session)
        return SessionData.model_validate(db_session)

    async def get_by_id(self, session_id: uuid.UUID) -> SessionData | None:
        result = await self._session.execute(
            select(SessionModel).where(SessionModel.id == session_id)
        )
        row = result.scalar_one_or_none()
        return SessionData.model_validate(row) if row else None

    async def get_active_by_user(self, user_id: uuid.UUID) -> Sequence[SessionData]:
        now = datetime.now(timezone.utc)
        result = await self._session.execute(
            select(SessionModel).where(
                SessionModel.user_id == user_id,
                SessionModel.is_revoked == False,  # noqa: E712
                SessionModel.expires_at > now,
            )
        )
        return [SessionData.model_validate(row) for row in result.scalars().all()]

    async def revoke(self, session_id: uuid.UUID) -> None:
        await self._session.execute(
            update(SessionModel)
            .where(SessionModel.id == session_id)
            .values(is_revoked=True)
        )
        await self._session.flush()

    async def revoke_all_for_user(self, user_id: uuid.UUID) -> int:
        result = await self._session.execute(
            update(SessionModel)
            .where(
                SessionModel.user_id == user_id,
                SessionModel.is_revoked == False,  # noqa: E712
            )
            .values(is_revoked=True)
        )
        await self._session.flush()
        return result.rowcount  # type: ignore[return-value]

    async def update_refresh_token(
        self,
        session_id: uuid.UUID,
        *,
        new_refresh_token_hash: str,
        new_expires_at: datetime,
    ) -> SessionData:
        await self._session.execute(
            update(SessionModel)
            .where(SessionModel.id == session_id)
            .values(
                refresh_token_hash=new_refresh_token_hash,
                expires_at=new_expires_at,
            )
        )
        await self._session.flush()
        result = await self._session.execute(
            select(SessionModel).where(SessionModel.id == session_id)
        )
        row = result.scalar_one()
        return SessionData.model_validate(row)
