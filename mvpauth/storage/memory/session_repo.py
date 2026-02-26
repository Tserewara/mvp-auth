from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from mvpauth.core.schemas import SessionData


class InMemorySessionRepository:
    def __init__(self) -> None:
        self._sessions: dict[uuid.UUID, SessionData] = {}

    async def create(
        self,
        *,
        user_id: uuid.UUID,
        refresh_token_hash: str,
        device_info: str | None = None,
        ip_address: str | None = None,
        expires_at: datetime,
    ) -> SessionData:
        session = SessionData(
            id=uuid.uuid4(),
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            device_info=device_info,
            ip_address=ip_address,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            is_revoked=False,
        )
        self._sessions[session.id] = session
        return session

    async def get_by_id(self, session_id: uuid.UUID) -> SessionData | None:
        return self._sessions.get(session_id)

    async def get_active_by_user(self, user_id: uuid.UUID) -> Sequence[SessionData]:
        now = datetime.now(timezone.utc)
        return [
            s
            for s in self._sessions.values()
            if s.user_id == user_id and not s.is_revoked and s.expires_at > now
        ]

    async def revoke(self, session_id: uuid.UUID) -> None:
        session = self._sessions.get(session_id)
        if session:
            self._sessions[session_id] = session.model_copy(update={"is_revoked": True})

    async def revoke_all_for_user(self, user_id: uuid.UUID) -> int:
        count = 0
        for sid, session in list(self._sessions.items()):
            if session.user_id == user_id and not session.is_revoked:
                self._sessions[sid] = session.model_copy(update={"is_revoked": True})
                count += 1
        return count

    async def update_refresh_token(
        self,
        session_id: uuid.UUID,
        *,
        new_refresh_token_hash: str,
        new_expires_at: datetime,
    ) -> SessionData:
        session = self._sessions[session_id]
        updated = session.model_copy(
            update={
                "refresh_token_hash": new_refresh_token_hash,
                "expires_at": new_expires_at,
            }
        )
        self._sessions[session_id] = updated
        return updated
