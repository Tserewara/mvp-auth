from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mvpauth.core.schemas import BlockedTokenData


class InMemoryTokenBlocklistRepository:
    def __init__(self) -> None:
        self._blocked: dict[str, BlockedTokenData] = {}

    async def add(self, *, jti: str, token_type: str, expires_at: datetime) -> None:
        self._blocked[jti] = BlockedTokenData(
            id=uuid.uuid4(),
            jti=jti,
            token_type=token_type,
            expires_at=expires_at,
        )

    async def is_blocked(self, jti: str) -> bool:
        return jti in self._blocked

    async def purge_expired(self) -> int:
        now = datetime.now(timezone.utc)
        expired = [jti for jti, data in self._blocked.items() if data.expires_at <= now]
        for jti in expired:
            del self._blocked[jti]
        return len(expired)
