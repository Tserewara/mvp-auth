from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from mvpauth.config import AuthConfig
from mvpauth.core import passwords, tokens
from mvpauth.core.exceptions import (
    InvalidCredentialsError,
    SessionNotFoundError,
    TokenReuseError,
    UserNotVerifiedError,
)
from mvpauth.core.schemas import TokenPair, TokenPayload
from mvpauth.storage.protocols import (
    SessionRepository,
    TokenBlocklistRepository,
    UserRepository,
)


class AuthService:
    def __init__(
        self,
        *,
        config: AuthConfig,
        user_repo: UserRepository,
        session_repo: SessionRepository,
        blocklist_repo: TokenBlocklistRepository,
    ) -> None:
        self._config = config
        self._users = user_repo
        self._sessions = session_repo
        self._blocklist = blocklist_repo

    async def login(
        self,
        *,
        email: str,
        password: str,
        device_info: str | None = None,
        ip_address: str | None = None,
    ) -> TokenPair:
        user = await self._users.get_by_email(email)
        if user is None or not passwords.verify_password(password, user.hashed_password):
            raise InvalidCredentialsError()

        if self._config.require_email_verification and not user.is_verified:
            raise UserNotVerifiedError()

        # Create session with placeholder hash, then update after token creation
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=self._config.refresh_token_expire_seconds
        )
        session = await self._sessions.create(
            user_id=user.id,
            refresh_token_hash="placeholder",
            device_info=device_info,
            ip_address=ip_address,
            expires_at=expires_at,
        )

        access_token, _ = tokens.create_access_token(
            user_id=user.id,
            secret_key=self._config.secret_key,
            algorithm=self._config.algorithm,
            expires_seconds=self._config.access_token_expire_seconds,
        )
        refresh_token, refresh_payload = tokens.create_refresh_token(
            user_id=user.id,
            session_id=session.id,
            secret_key=self._config.secret_key,
            algorithm=self._config.algorithm,
            expires_seconds=self._config.refresh_token_expire_seconds,
        )

        await self._sessions.update_refresh_token(
            session.id,
            new_refresh_token_hash=passwords.hash_token(refresh_token),
            new_expires_at=datetime.fromtimestamp(refresh_payload.exp, tz=timezone.utc),
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self._config.access_token_expire_seconds,
        )

    async def refresh(self, *, refresh_token: str) -> TokenPair:
        payload = tokens.decode_token(
            refresh_token,
            secret_key=self._config.secret_key,
            algorithm=self._config.algorithm,
            expected_type="refresh",
        )

        # Check blocklist — if blocked, this token was already used (reuse)
        if await self._blocklist.is_blocked(payload.jti):
            user_id = uuid.UUID(payload.sub)
            await self._sessions.revoke_all_for_user(user_id)
            raise TokenReuseError()

        session_id_str = payload.session_id
        if session_id_str is None:
            raise TokenReuseError("Refresh token missing session_id")

        session_id = uuid.UUID(session_id_str)
        session = await self._sessions.get_by_id(session_id)
        if session is None or session.is_revoked:
            # Session was already revoked — possible reuse
            user_id = uuid.UUID(payload.sub)
            await self._sessions.revoke_all_for_user(user_id)
            raise TokenReuseError()

        # Verify the hash matches
        if not passwords.verify_token_hash(refresh_token, session.refresh_token_hash):
            user_id = uuid.UUID(payload.sub)
            await self._sessions.revoke_all_for_user(user_id)
            raise TokenReuseError()

        # Block the old refresh token
        await self._blocklist.add(
            jti=payload.jti,
            token_type="refresh",
            expires_at=datetime.fromtimestamp(payload.exp, tz=timezone.utc),
        )

        # Issue new token pair
        user_id = uuid.UUID(payload.sub)
        new_access, _ = tokens.create_access_token(
            user_id=user_id,
            secret_key=self._config.secret_key,
            algorithm=self._config.algorithm,
            expires_seconds=self._config.access_token_expire_seconds,
        )
        new_refresh, new_refresh_payload = tokens.create_refresh_token(
            user_id=user_id,
            session_id=session_id,
            secret_key=self._config.secret_key,
            algorithm=self._config.algorithm,
            expires_seconds=self._config.refresh_token_expire_seconds,
        )

        # Update session with new refresh token hash
        await self._sessions.update_refresh_token(
            session_id,
            new_refresh_token_hash=passwords.hash_token(new_refresh),
            new_expires_at=datetime.fromtimestamp(
                new_refresh_payload.exp, tz=timezone.utc
            ),
        )

        return TokenPair(
            access_token=new_access,
            refresh_token=new_refresh,
            expires_in=self._config.access_token_expire_seconds,
        )

    async def logout(self, *, access_token_payload: TokenPayload) -> None:
        await self._blocklist.add(
            jti=access_token_payload.jti,
            token_type="access",
            expires_at=datetime.fromtimestamp(
                access_token_payload.exp, tz=timezone.utc
            ),
        )

    async def logout_all(self, *, user_id: uuid.UUID) -> int:
        return await self._sessions.revoke_all_for_user(user_id)
