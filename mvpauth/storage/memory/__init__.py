from __future__ import annotations

from mvpauth.storage.memory.user_repo import InMemoryUserRepository
from mvpauth.storage.memory.session_repo import InMemorySessionRepository
from mvpauth.storage.memory.token_repo import InMemoryTokenBlocklistRepository


class InMemoryStorage:
    def __init__(self) -> None:
        self._user_repo = InMemoryUserRepository()
        self._session_repo = InMemorySessionRepository()
        self._blocklist_repo = InMemoryTokenBlocklistRepository()

    @property
    def user_repo(self) -> InMemoryUserRepository:
        return self._user_repo

    @property
    def session_repo(self) -> InMemorySessionRepository:
        return self._session_repo

    @property
    def blocklist_repo(self) -> InMemoryTokenBlocklistRepository:
        return self._blocklist_repo


__all__ = [
    "InMemoryStorage",
    "InMemoryUserRepository",
    "InMemorySessionRepository",
    "InMemoryTokenBlocklistRepository",
]
