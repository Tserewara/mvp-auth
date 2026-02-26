from __future__ import annotations

import uuid
from typing import Awaitable, Callable

from mvpauth.config import AuthConfig
from mvpauth.core import passwords, tokens
from mvpauth.core.exceptions import (
    InvalidCredentialsError,
    InvalidVerificationTokenError,
    UserNotFoundError,
)
from mvpauth.storage.protocols import SessionRepository, UserRepository

OnPasswordResetEmail = Callable[[str, str], Awaitable[None]] | None


class PasswordService:
    def __init__(
        self,
        *,
        config: AuthConfig,
        user_repo: UserRepository,
        session_repo: SessionRepository,
        on_password_reset_email: OnPasswordResetEmail = None,
    ) -> None:
        self._config = config
        self._users = user_repo
        self._sessions = session_repo
        self._on_password_reset_email = on_password_reset_email

    async def forgot_password(self, *, email: str) -> None:
        user = await self._users.get_by_email(email)
        if user is None:
            return  # Don't reveal user existence

        if self._on_password_reset_email:
            token = self._create_reset_token(user.id)
            await self._on_password_reset_email(email, token)

    async def reset_password(self, *, token: str, new_password: str) -> None:
        try:
            payload = tokens.decode_token(
                token,
                secret_key=self._config.secret_key,
                algorithm=self._config.algorithm,
                expected_type="password_reset",
            )
        except Exception:
            raise InvalidVerificationTokenError("Invalid password reset token")

        passwords.validate_password_strength(
            new_password, min_length=self._config.min_password_length
        )

        user_id = uuid.UUID(payload.sub)
        user = await self._users.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError()

        hashed = passwords.hash_password(
            new_password, algorithm=self._config.password_algorithm
        )
        await self._users.update(user_id, hashed_password=hashed)

        # Revoke all sessions after password reset
        await self._sessions.revoke_all_for_user(user_id)

    async def change_password(
        self,
        *,
        user_id: uuid.UUID,
        current_password: str,
        new_password: str,
    ) -> None:
        user = await self._users.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError()

        if not passwords.verify_password(current_password, user.hashed_password):
            raise InvalidCredentialsError("Current password is incorrect")

        passwords.validate_password_strength(
            new_password, min_length=self._config.min_password_length
        )

        hashed = passwords.hash_password(
            new_password, algorithm=self._config.password_algorithm
        )
        await self._users.update(user_id, hashed_password=hashed)

        # Revoke all sessions after password change
        await self._sessions.revoke_all_for_user(user_id)

    def _create_reset_token(self, user_id: uuid.UUID) -> str:
        token, _ = tokens.create_token(
            user_id=user_id,
            token_type="password_reset",
            secret_key=self._config.secret_key,
            algorithm=self._config.algorithm,
            expires_seconds=self._config.reset_token_expire_seconds,
        )
        return token
