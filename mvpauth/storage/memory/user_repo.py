from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mvpauth.core.schemas import UserData


class InMemoryUserRepository:
    def __init__(self) -> None:
        self._users: dict[uuid.UUID, UserData] = {}
        self._email_index: dict[str, uuid.UUID] = {}

    async def create(self, *, email: str, hashed_password: str) -> UserData:
        now = datetime.now(timezone.utc)
        user = UserData(
            id=uuid.uuid4(),
            email=email,
            hashed_password=hashed_password,
            is_active=True,
            is_verified=False,
            created_at=now,
            updated_at=now,
        )
        self._users[user.id] = user
        self._email_index[email] = user.id
        return user

    async def get_by_id(self, user_id: uuid.UUID) -> UserData | None:
        return self._users.get(user_id)

    async def get_by_email(self, email: str) -> UserData | None:
        uid = self._email_index.get(email)
        return self._users.get(uid) if uid else None

    async def update(self, user_id: uuid.UUID, **fields: object) -> UserData:
        user = self._users[user_id]
        updated = user.model_copy(
            update={**fields, "updated_at": datetime.now(timezone.utc)}
        )
        self._users[user_id] = updated
        if "email" in fields and fields["email"] != user.email:
            self._email_index.pop(user.email, None)
            self._email_index[str(fields["email"])] = user_id
        return updated

    async def delete(self, user_id: uuid.UUID) -> None:
        user = self._users.pop(user_id, None)
        if user:
            self._email_index.pop(user.email, None)
