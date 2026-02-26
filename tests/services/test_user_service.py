from __future__ import annotations

import pytest

from mvpauth import Auth
from mvpauth.core.exceptions import (
    AlreadyVerifiedError,
    InvalidVerificationTokenError,
    UserExistsError,
    UserNotFoundError,
)
from mvpauth.core.tokens import create_token


class TestRegister:
    async def test_success(self, auth: Auth) -> None:
        svc = auth.get_user_service()
        user = await svc.register(email="test@example.com", password="password123")
        assert user.email == "test@example.com"
        assert user.is_verified is False
        assert user.is_active is True

    async def test_duplicate_email(self, auth: Auth) -> None:
        svc = auth.get_user_service()
        await svc.register(email="dup@example.com", password="password123")
        with pytest.raises(UserExistsError):
            await svc.register(email="dup@example.com", password="password456")

    async def test_calls_verification_hook(self, auth: Auth) -> None:
        captured: list[tuple[str, str]] = []

        async def hook(email: str, token: str) -> None:
            captured.append((email, token))

        auth.on_verification_email = hook
        svc = auth.get_user_service()
        await svc.register(email="hook@example.com", password="password123")
        assert len(captured) == 1
        assert captured[0][0] == "hook@example.com"


class TestVerifyEmail:
    async def test_success(self, auth: Auth) -> None:
        svc = auth.get_user_service()
        user = await svc.register(email="verify@example.com", password="password123")

        token, _ = create_token(
            user_id=user.id,
            token_type="email_verify",
            secret_key=auth.config.secret_key,
            algorithm=auth.config.algorithm,
            expires_seconds=3600,
        )
        verified = await svc.verify_email(token=token)
        assert verified.is_verified is True

    async def test_invalid_token(self, auth: Auth) -> None:
        svc = auth.get_user_service()
        with pytest.raises(InvalidVerificationTokenError):
            await svc.verify_email(token="bad-token")

    async def test_already_verified(self, auth: Auth) -> None:
        svc = auth.get_user_service()
        user = await svc.register(email="already@example.com", password="password123")

        token, _ = create_token(
            user_id=user.id,
            token_type="email_verify",
            secret_key=auth.config.secret_key,
            algorithm=auth.config.algorithm,
            expires_seconds=3600,
        )
        await svc.verify_email(token=token)

        token2, _ = create_token(
            user_id=user.id,
            token_type="email_verify",
            secret_key=auth.config.secret_key,
            algorithm=auth.config.algorithm,
            expires_seconds=3600,
        )
        with pytest.raises(AlreadyVerifiedError):
            await svc.verify_email(token=token2)


class TestResendVerification:
    async def test_unknown_email_no_error(self, auth: Auth) -> None:
        svc = auth.get_user_service()
        await svc.resend_verification(email="unknown@example.com")  # no exception


class TestGetCurrentUser:
    async def test_success(self, auth: Auth) -> None:
        svc = auth.get_user_service()
        created = await svc.register(email="me@example.com", password="password123")
        user = await svc.get_current_user(user_id=created.id)
        assert user.email == "me@example.com"

    async def test_not_found(self, auth: Auth) -> None:
        import uuid

        svc = auth.get_user_service()
        with pytest.raises(UserNotFoundError):
            await svc.get_current_user(user_id=uuid.uuid4())
