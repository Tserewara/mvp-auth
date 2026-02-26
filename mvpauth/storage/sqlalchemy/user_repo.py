from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from mvpauth.core.schemas import UserData
from mvpauth.storage.sqlalchemy.models import UserModel


class SQLAlchemyUserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, *, email: str, hashed_password: str) -> UserData:
        user = UserModel(email=email, hashed_password=hashed_password)
        self._session.add(user)
        await self._session.flush()
        await self._session.refresh(user)
        return UserData.model_validate(user)

    async def get_by_id(self, user_id: uuid.UUID) -> UserData | None:
        result = await self._session.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalar_one_or_none()
        return UserData.model_validate(user) if user else None

    async def get_by_email(self, email: str) -> UserData | None:
        result = await self._session.execute(
            select(UserModel).where(UserModel.email == email)
        )
        user = result.scalar_one_or_none()
        return UserData.model_validate(user) if user else None

    async def update(self, user_id: uuid.UUID, **fields: object) -> UserData:
        fields["updated_at"] = datetime.now(timezone.utc)
        await self._session.execute(
            update(UserModel).where(UserModel.id == user_id).values(**fields)
        )
        await self._session.flush()
        result = await self._session.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalar_one()
        return UserData.model_validate(user)

    async def delete(self, user_id: uuid.UUID) -> None:
        result = await self._session.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalar_one_or_none()
        if user:
            await self._session.delete(user)
            await self._session.flush()
