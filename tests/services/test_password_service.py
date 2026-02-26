from __future__ import annotations

import pytest

from mvpauth import Auth
from mvpauth.core.exceptions import InvalidCredentialsError, InvalidVerificationTokenError
from mvpauth.core.tokens import create_token


class TestForgotPassword:
    async def test_calls_hook(self, auth: Auth) -> None:
        captured: list[tuple[str, str]] = []

        async def hook(email: str, token: str) -> None:
            captured.append((email, token))

        auth.on_password_reset_email = hook
        user_svc = auth.get_user_service()
        await user_svc.register(email="forgot@example.com", password="password123")

        pw_svc = auth.get_password_service()
        await pw_svc.forgot_password(email="forgot@example.com")
        assert len(captured) == 1
        assert captured[0][0] == "forgot@example.com"

    async def test_unknown_email_no_error(self, auth: Auth) -> None:
        pw_svc = auth.get_password_service()
        await pw_svc.forgot_password(email="noone@example.com")  # no exception


class TestResetPassword:
    async def test_success(self, auth: Auth) -> None:
        user_svc = auth.get_user_service()
        user = await user_svc.register(
            email="reset@example.com", password="old-password-123"
        )

        token, _ = create_token(
            user_id=user.id,
            token_type="password_reset",
            secret_key=auth.config.secret_key,
            algorithm=auth.config.algorithm,
            expires_seconds=3600,
        )

        pw_svc = auth.get_password_service()
        await pw_svc.reset_password(token=token, new_password="new-password-456")

        # Login with new password should work
        auth_svc = auth.get_auth_service()
        tokens = await auth_svc.login(
            email="reset@example.com", password="new-password-456"
        )
        assert tokens.access_token

    async def test_invalid_token(self, auth: Auth) -> None:
        pw_svc = auth.get_password_service()
        with pytest.raises(InvalidVerificationTokenError):
            await pw_svc.reset_password(token="bad-token", new_password="newpass123")


class TestChangePassword:
    async def test_success(self, auth: Auth) -> None:
        user_svc = auth.get_user_service()
        user = await user_svc.register(
            email="change@example.com", password="old-password-123"
        )

        pw_svc = auth.get_password_service()
        await pw_svc.change_password(
            user_id=user.id,
            current_password="old-password-123",
            new_password="new-password-456",
        )

        # Login with new password should work
        auth_svc = auth.get_auth_service()
        tokens = await auth_svc.login(
            email="change@example.com", password="new-password-456"
        )
        assert tokens.access_token

    async def test_wrong_current_password(self, auth: Auth) -> None:
        user_svc = auth.get_user_service()
        user = await user_svc.register(
            email="changefail@example.com", password="old-password-123"
        )

        pw_svc = auth.get_password_service()
        with pytest.raises(InvalidCredentialsError):
            await pw_svc.change_password(
                user_id=user.id,
                current_password="wrong-password",
                new_password="new-password-456",
            )
