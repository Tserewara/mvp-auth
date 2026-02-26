from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Callable

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from mvpauth.core.exceptions import TokenRevokedError
from mvpauth.core.schemas import TokenPayload, UserResponse
from mvpauth.core.tokens import decode_token

if TYPE_CHECKING:
    from mvpauth import Auth

_bearer_scheme = HTTPBearer()


def get_current_user(auth: Auth) -> Callable[..., object]:
    async def _get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    ) -> UserResponse:
        token = credentials.credentials
        payload = decode_token(
            token,
            secret_key=auth.config.secret_key,
            algorithm=auth.config.algorithm,
            expected_type="access",
        )

        if await auth.storage.blocklist_repo.is_blocked(payload.jti):
            raise TokenRevokedError()

        user_id = uuid.UUID(payload.sub)
        svc = auth.get_user_service()
        return await svc.get_current_user(user_id=user_id)

    return _get_current_user


def get_token_payload(auth: Auth) -> Callable[..., object]:
    async def _get_token_payload(
        credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    ) -> TokenPayload:
        token = credentials.credentials
        payload = decode_token(
            token,
            secret_key=auth.config.secret_key,
            algorithm=auth.config.algorithm,
            expected_type="access",
        )

        if await auth.storage.blocklist_repo.is_blocked(payload.jti):
            raise TokenRevokedError()

        return payload

    return _get_token_payload
