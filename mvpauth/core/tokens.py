from __future__ import annotations

import uuid
from datetime import datetime, timezone

import jwt

from mvpauth.core.exceptions import TokenExpiredError, TokenInvalidError
from mvpauth.core.schemas import TokenPayload


def create_token(
    *,
    user_id: uuid.UUID,
    token_type: str,
    secret_key: str,
    algorithm: str = "HS256",
    expires_seconds: int,
    session_id: uuid.UUID | None = None,
    extra_claims: dict[str, object] | None = None,
) -> tuple[str, TokenPayload]:
    now = datetime.now(timezone.utc)
    jti = uuid.uuid4().hex
    payload = TokenPayload(
        sub=str(user_id),
        jti=jti,
        type=token_type,
        session_id=str(session_id) if session_id else None,
        exp=int(now.timestamp()) + expires_seconds,
        iat=int(now.timestamp()),
    )
    claims = payload.model_dump(exclude_none=True)
    if extra_claims:
        claims.update(extra_claims)
    token = jwt.encode(claims, secret_key, algorithm=algorithm)
    return token, payload


def create_access_token(
    *,
    user_id: uuid.UUID,
    secret_key: str,
    algorithm: str = "HS256",
    expires_seconds: int = 900,
) -> tuple[str, TokenPayload]:
    return create_token(
        user_id=user_id,
        token_type="access",
        secret_key=secret_key,
        algorithm=algorithm,
        expires_seconds=expires_seconds,
    )


def create_refresh_token(
    *,
    user_id: uuid.UUID,
    session_id: uuid.UUID,
    secret_key: str,
    algorithm: str = "HS256",
    expires_seconds: int = 2_592_000,
) -> tuple[str, TokenPayload]:
    return create_token(
        user_id=user_id,
        token_type="refresh",
        secret_key=secret_key,
        algorithm=algorithm,
        expires_seconds=expires_seconds,
        session_id=session_id,
    )


def decode_token(
    token: str,
    *,
    secret_key: str,
    algorithm: str = "HS256",
    expected_type: str | None = None,
) -> TokenPayload:
    try:
        raw = jwt.decode(token, secret_key, algorithms=[algorithm])
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError()
    except jwt.InvalidTokenError:
        raise TokenInvalidError()

    payload = TokenPayload(**raw)
    if expected_type is not None and payload.type != expected_type:
        raise TokenInvalidError(f"Expected {expected_type} token, got {payload.type}")
    return payload
