from __future__ import annotations

from typing import Awaitable, Callable

from mvpauth.config import AuthConfig
from mvpauth.services.auth_service import AuthService
from mvpauth.services.password_service import PasswordService
from mvpauth.services.user_service import UserService
from mvpauth.storage.protocols import StorageBackend


class Auth:
    """Central container for mvp-auth. Holds config, storage, and hooks."""

    def __init__(
        self,
        *,
        config: AuthConfig,
        storage: StorageBackend,
        on_verification_email: Callable[[str, str], Awaitable[None]] | None = None,
        on_password_reset_email: Callable[[str, str], Awaitable[None]] | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.on_verification_email = on_verification_email
        self.on_password_reset_email = on_password_reset_email

    def get_auth_service(self) -> AuthService:
        return AuthService(
            config=self.config,
            user_repo=self.storage.user_repo,
            session_repo=self.storage.session_repo,
            blocklist_repo=self.storage.blocklist_repo,
        )

    def get_user_service(self) -> UserService:
        return UserService(
            config=self.config,
            user_repo=self.storage.user_repo,
            on_verification_email=self.on_verification_email,
        )

    def get_password_service(self) -> PasswordService:
        return PasswordService(
            config=self.config,
            user_repo=self.storage.user_repo,
            session_repo=self.storage.session_repo,
            on_password_reset_email=self.on_password_reset_email,
        )


def create_auth(
    *,
    config: AuthConfig,
    storage: StorageBackend,
    on_verification_email: Callable[[str, str], Awaitable[None]] | None = None,
    on_password_reset_email: Callable[[str, str], Awaitable[None]] | None = None,
) -> Auth:
    return Auth(
        config=config,
        storage=storage,
        on_verification_email=on_verification_email,
        on_password_reset_email=on_password_reset_email,
    )


__all__ = ["Auth", "AuthConfig", "create_auth"]
