from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Request

from mvpauth.core.exceptions import SessionNotFoundError
from mvpauth.core.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    SessionResponse,
    TokenPair,
    TokenPayload,
    UserResponse,
    VerifyEmailRequest,
)
from mvpauth.integrations.fastapi.dependencies import get_current_user, get_token_payload
from mvpauth.integrations.fastapi.routes import Routes

if TYPE_CHECKING:
    from mvpauth import Auth


def _resolve_routes(
    include: set[str] | frozenset[str] | None,
    exclude: set[str] | frozenset[str] | None,
) -> frozenset[str]:
    base = frozenset(include) if include is not None else Routes.ALL
    result = base - frozenset(exclude or ())

    unknown = (base | frozenset(exclude or ())) - Routes.ALL
    if unknown:
        raise ValueError(f"Unknown route names: {', '.join(sorted(unknown))}")

    if not result:
        raise ValueError("No routes to mount after applying include/exclude")

    return result


def auth_router(
    auth: Auth,
    *,
    include: set[str] | frozenset[str] | None = None,
    exclude: set[str] | frozenset[str] | None = None,
) -> APIRouter:
    enabled = _resolve_routes(include, exclude)
    router = APIRouter(tags=["auth"])

    # ── Public routes ────────────────────────────────────────────

    if Routes.REGISTER in enabled:

        @router.post("/register", response_model=UserResponse, status_code=201)
        async def register(body: RegisterRequest) -> UserResponse:
            svc = auth.get_user_service()
            return await svc.register(email=body.email, password=body.password)

    if Routes.LOGIN in enabled:

        @router.post("/login", response_model=TokenPair)
        async def login(body: LoginRequest, request: Request) -> TokenPair:
            svc = auth.get_auth_service()
            return await svc.login(
                email=body.email,
                password=body.password,
                device_info=request.headers.get("user-agent"),
                ip_address=request.client.host if request.client else None,
            )

    if Routes.REFRESH in enabled:

        @router.post("/refresh", response_model=TokenPair)
        async def refresh(body: RefreshRequest) -> TokenPair:
            svc = auth.get_auth_service()
            return await svc.refresh(refresh_token=body.refresh_token)

    if Routes.VERIFY_EMAIL in enabled:

        @router.post("/verify-email", response_model=UserResponse)
        async def verify_email(body: VerifyEmailRequest) -> UserResponse:
            svc = auth.get_user_service()
            return await svc.verify_email(token=body.token)

    if Routes.RESEND_VERIFICATION in enabled:

        @router.post("/resend-verification", response_model=MessageResponse)
        async def resend_verification(
            body: ResendVerificationRequest,
        ) -> MessageResponse:
            svc = auth.get_user_service()
            await svc.resend_verification(email=body.email)
            return MessageResponse(
                message="If the email exists, a verification link was sent."
            )

    if Routes.FORGOT_PASSWORD in enabled:

        @router.post("/forgot-password", response_model=MessageResponse)
        async def forgot_password(body: ForgotPasswordRequest) -> MessageResponse:
            svc = auth.get_password_service()
            await svc.forgot_password(email=body.email)
            return MessageResponse(
                message="If the email exists, a reset link was sent."
            )

    if Routes.RESET_PASSWORD in enabled:

        @router.post("/reset-password", response_model=MessageResponse)
        async def reset_password(body: ResetPasswordRequest) -> MessageResponse:
            svc = auth.get_password_service()
            await svc.reset_password(
                token=body.token, new_password=body.new_password
            )
            return MessageResponse(message="Password has been reset.")

    # ── Protected routes ─────────────────────────────────────────

    if Routes.ME in enabled:

        @router.get("/me", response_model=UserResponse)
        async def me(
            user: UserResponse = Depends(get_current_user(auth)),
        ) -> UserResponse:
            return user

    if Routes.LOGOUT in enabled:

        @router.post("/logout", response_model=MessageResponse)
        async def logout(
            payload: TokenPayload = Depends(get_token_payload(auth)),
        ) -> MessageResponse:
            svc = auth.get_auth_service()
            await svc.logout(access_token_payload=payload)
            return MessageResponse(message="Logged out.")

    if Routes.LOGOUT_ALL in enabled:

        @router.post("/logout-all", response_model=MessageResponse)
        async def logout_all(
            user: UserResponse = Depends(get_current_user(auth)),
        ) -> MessageResponse:
            svc = auth.get_auth_service()
            count = await svc.logout_all(user_id=user.id)
            return MessageResponse(message=f"Revoked {count} session(s).")

    if Routes.CHANGE_PASSWORD in enabled:

        @router.post("/change-password", response_model=MessageResponse)
        async def change_password(
            body: ChangePasswordRequest,
            user: UserResponse = Depends(get_current_user(auth)),
        ) -> MessageResponse:
            svc = auth.get_password_service()
            await svc.change_password(
                user_id=user.id,
                current_password=body.current_password,
                new_password=body.new_password,
            )
            return MessageResponse(message="Password changed.")

    if Routes.SESSIONS in enabled:

        @router.get("/sessions", response_model=list[SessionResponse])
        async def list_sessions(
            user: UserResponse = Depends(get_current_user(auth)),
        ) -> list[SessionResponse]:
            sessions = await auth.storage.session_repo.get_active_by_user(user.id)
            return [SessionResponse.model_validate(s) for s in sessions]

    if Routes.REVOKE_SESSION in enabled:

        @router.delete("/sessions/{session_id}", response_model=MessageResponse)
        async def revoke_session(
            session_id: uuid.UUID,
            user: UserResponse = Depends(get_current_user(auth)),
        ) -> MessageResponse:
            session = await auth.storage.session_repo.get_by_id(session_id)
            if session is None or session.user_id != user.id:
                raise SessionNotFoundError()
            await auth.storage.session_repo.revoke(session_id)
            return MessageResponse(message="Session revoked.")

    return router
