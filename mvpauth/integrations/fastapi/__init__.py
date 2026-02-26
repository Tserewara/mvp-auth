from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mvpauth.core.exceptions import (
    AlreadyVerifiedError,
    InvalidCredentialsError,
    InvalidPasswordError,
    InvalidVerificationTokenError,
    MvpAuthError,
    SessionNotFoundError,
    TokenExpiredError,
    TokenInvalidError,
    TokenReuseError,
    TokenRevokedError,
    UserExistsError,
    UserNotFoundError,
    UserNotVerifiedError,
)
from mvpauth.integrations.fastapi.dependencies import get_current_user, get_token_payload
from mvpauth.integrations.fastapi.router import auth_router
from mvpauth.integrations.fastapi.routes import Routes

if TYPE_CHECKING:
    pass

_STATUS_MAP: dict[type[MvpAuthError], int] = {
    InvalidCredentialsError: 401,
    TokenExpiredError: 401,
    TokenInvalidError: 401,
    TokenRevokedError: 401,
    TokenReuseError: 401,
    UserNotVerifiedError: 403,
    AlreadyVerifiedError: 409,
    UserExistsError: 409,
    UserNotFoundError: 404,
    SessionNotFoundError: 404,
    InvalidPasswordError: 422,
    InvalidVerificationTokenError: 400,
}


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(MvpAuthError)
    async def _mvp_auth_error_handler(
        request: Request, exc: MvpAuthError
    ) -> JSONResponse:
        status = _STATUS_MAP.get(type(exc), 400)
        return JSONResponse(
            status_code=status,
            content={"detail": exc.message, "code": exc.code},
        )


__all__ = [
    "Routes",
    "auth_router",
    "get_current_user",
    "get_token_payload",
    "install_exception_handlers",
]
