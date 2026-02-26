from __future__ import annotations

import pytest

from mvpauth import Auth, AuthConfig, create_auth
from mvpauth.core.exceptions import (
    InvalidCredentialsError,
    TokenReuseError,
    UserNotVerifiedError,
)
from mvpauth.storage.memory import InMemoryStorage


class TestLogin:
    async def test_success(self, auth: Auth) -> None:
        user_svc = auth.get_user_service()
        await user_svc.register(email="login@example.com", password="password123")

        auth_svc = auth.get_auth_service()
        tokens = await auth_svc.login(email="login@example.com", password="password123")
        assert tokens.access_token
        assert tokens.refresh_token
        assert tokens.token_type == "bearer"
        assert tokens.expires_in > 0

    async def test_wrong_password(self, auth: Auth) -> None:
        user_svc = auth.get_user_service()
        await user_svc.register(email="wrong@example.com", password="password123")

        auth_svc = auth.get_auth_service()
        with pytest.raises(InvalidCredentialsError):
            await auth_svc.login(email="wrong@example.com", password="bad-password")

    async def test_nonexistent_user(self, auth: Auth) -> None:
        auth_svc = auth.get_auth_service()
        with pytest.raises(InvalidCredentialsError):
            await auth_svc.login(email="noone@example.com", password="whatever")

    async def test_unverified_when_required(self) -> None:
        config = AuthConfig(
            secret_key="test-secret", require_email_verification=True
        )
        storage = InMemoryStorage()
        auth = create_auth(config=config, storage=storage)

        user_svc = auth.get_user_service()
        await user_svc.register(
            email="unverified@example.com", password="password123"
        )

        auth_svc = auth.get_auth_service()
        with pytest.raises(UserNotVerifiedError):
            await auth_svc.login(
                email="unverified@example.com", password="password123"
            )


class TestRefresh:
    async def test_success(self, auth: Auth) -> None:
        user_svc = auth.get_user_service()
        await user_svc.register(email="refresh@example.com", password="password123")

        auth_svc = auth.get_auth_service()
        tokens = await auth_svc.login(
            email="refresh@example.com", password="password123"
        )

        new_tokens = await auth_svc.refresh(refresh_token=tokens.refresh_token)
        assert new_tokens.access_token != tokens.access_token
        assert new_tokens.refresh_token != tokens.refresh_token

    async def test_reuse_detection(self, auth: Auth) -> None:
        user_svc = auth.get_user_service()
        await user_svc.register(email="reuse@example.com", password="password123")

        auth_svc = auth.get_auth_service()
        tokens = await auth_svc.login(
            email="reuse@example.com", password="password123"
        )
        old_refresh = tokens.refresh_token

        # First refresh succeeds
        await auth_svc.refresh(refresh_token=old_refresh)

        # Second refresh with same token should trigger reuse detection
        with pytest.raises(TokenReuseError):
            await auth_svc.refresh(refresh_token=old_refresh)


class TestLogout:
    async def test_logout_blocks_token(self, auth: Auth) -> None:
        user_svc = auth.get_user_service()
        await user_svc.register(email="logout@example.com", password="password123")

        auth_svc = auth.get_auth_service()
        tokens = await auth_svc.login(
            email="logout@example.com", password="password123"
        )

        from mvpauth.core.tokens import decode_token

        payload = decode_token(
            tokens.access_token, secret_key=auth.config.secret_key
        )
        await auth_svc.logout(access_token_payload=payload)

        assert await auth.storage.blocklist_repo.is_blocked(payload.jti)


class TestLogoutAll:
    async def test_revokes_all_sessions(self, auth: Auth) -> None:
        user_svc = auth.get_user_service()
        await user_svc.register(email="logoutall@example.com", password="password123")

        auth_svc = auth.get_auth_service()
        # Create two sessions
        await auth_svc.login(email="logoutall@example.com", password="password123")
        await auth_svc.login(email="logoutall@example.com", password="password123")

        user = await user_svc.get_current_user(
            user_id=(await auth.storage.user_repo.get_by_email("logoutall@example.com")).id  # type: ignore[union-attr]
        )
        count = await auth_svc.logout_all(user_id=user.id)
        assert count == 2

        sessions = await auth.storage.session_repo.get_active_by_user(user.id)
        assert len(sessions) == 0
