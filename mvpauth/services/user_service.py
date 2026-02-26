from __future__ import annotations

import uuid
from typing import Awaitable, Callable

from mvpauth.config import AuthConfig
from mvpauth.core import passwords, tokens
from mvpauth.core.exceptions import (
    AlreadyVerifiedError,
    InvalidVerificationTokenError,
    UserExistsError,
    UserNotFoundError,
)
from mvpauth.core.schemas import UserResponse
from mvpauth.storage.protocols import UserRepository

OnVerificationEmail = Callable[[str, str], Awaitable[None]] | None


class UserService:
    def __init__(
        self,
        *,
        config: AuthConfig,
        user_repo: UserRepository,
        on_verification_email: OnVerificationEmail = None,
    ) -> None:
        self._config = config
        self._users = user_repo
        self._on_verification_email = on_verification_email

    async def register(self, *, email: str, password: str) -> UserResponse:
        passwords.validate_password_strength(
            password, min_length=self._config.min_password_length
        )

        existing = await self._users.get_by_email(email)
        if existing is not None:
            raise UserExistsError()

        hashed = passwords.hash_password(
            password, algorithm=self._config.password_algorithm
        )
        user = await self._users.create(email=email, hashed_password=hashed)

        if self._on_verification_email:
            token = self._create_verification_token(user.id)
            await self._on_verification_email(email, token)

        return UserResponse.model_validate(user)

    async def verify_email(self, *, token: str) -> UserResponse:
        try:
            payload = tokens.decode_token(
                token,
                secret_key=self._config.secret_key,
                algorithm=self._config.algorithm,
                expected_type="email_verify",
            )
        except Exception:
            raise InvalidVerificationTokenError()

        user_id = uuid.UUID(payload.sub)
        user = await self._users.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError()
        if user.is_verified:
            raise AlreadyVerifiedError()

        updated = await self._users.update(user_id, is_verified=True)
        return UserResponse.model_validate(updated)

    async def resend_verification(self, *, email: str) -> None:
        user = await self._users.get_by_email(email)
        if user is None or user.is_verified:
            return

        if self._on_verification_email:
            token = self._create_verification_token(user.id)
            await self._on_verification_email(email, token)

    async def get_current_user(self, *, user_id: uuid.UUID) -> UserResponse:
        user = await self._users.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError()
        return UserResponse.model_validate(user)

    def _create_verification_token(self, user_id: uuid.UUID) -> str:
        token, _ = tokens.create_token(
            user_id=user_id,
            token_type="email_verify",
            secret_key=self._config.secret_key,
            algorithm=self._config.algorithm,
            expires_seconds=self._config.verification_token_expire_seconds,
        )
        return token
