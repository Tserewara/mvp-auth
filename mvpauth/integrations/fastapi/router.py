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

if TYPE_CHECKING:
    from mvpauth import Auth


def auth_router(auth: Auth) -> APIRouter:
    router = APIRouter(tags=["auth"])

    # ── Public routes ────────────────────────────────────────────

    @router.post("/register", response_model=UserResponse, status_code=201)
    async def register(body: RegisterRequest) -> UserResponse:
        svc = auth.get_user_service()
        return await svc.register(email=body.email, password=body.password)

    @router.post("/login", response_model=TokenPair)
    async def login(body: LoginRequest, request: Request) -> TokenPair:
        svc = auth.get_auth_service()
        return await svc.login(
            email=body.email,
            password=body.password,
            device_info=request.headers.get("user-agent"),
            ip_address=request.client.host if request.client else None,
        )

    @router.post("/refresh", response_model=TokenPair)
    async def refresh(body: RefreshRequest) -> TokenPair:
        svc = auth.get_auth_service()
        return await svc.refresh(refresh_token=body.refresh_token)

    @router.post("/verify-email", response_model=UserResponse)
    async def verify_email(body: VerifyEmailRequest) -> UserResponse:
        svc = auth.get_user_service()
        return await svc.verify_email(token=body.token)

    @router.post("/resend-verification", response_model=MessageResponse)
    async def resend_verification(body: ResendVerificationRequest) -> MessageResponse:
        svc = auth.get_user_service()
        await svc.resend_verification(email=body.email)
        return MessageResponse(
            message="If the email exists, a verification link was sent."
        )

    @router.post("/forgot-password", response_model=MessageResponse)
    async def forgot_password(body: ForgotPasswordRequest) -> MessageResponse:
        svc = auth.get_password_service()
        await svc.forgot_password(email=body.email)
        return MessageResponse(message="If the email exists, a reset link was sent.")

    @router.post("/reset-password", response_model=MessageResponse)
    async def reset_password(body: ResetPasswordRequest) -> MessageResponse:
        svc = auth.get_password_service()
        await svc.reset_password(token=body.token, new_password=body.new_password)
        return MessageResponse(message="Password has been reset.")

    # ── Protected routes ─────────────────────────────────────────

    @router.get("/me", response_model=UserResponse)
    async def me(
        user: UserResponse = Depends(get_current_user(auth)),
    ) -> UserResponse:
        return user

    @router.post("/logout", response_model=MessageResponse)
    async def logout(
        payload: TokenPayload = Depends(get_token_payload(auth)),
    ) -> MessageResponse:
        svc = auth.get_auth_service()
        await svc.logout(access_token_payload=payload)
        return MessageResponse(message="Logged out.")

    @router.post("/logout-all", response_model=MessageResponse)
    async def logout_all(
        user: UserResponse = Depends(get_current_user(auth)),
    ) -> MessageResponse:
        svc = auth.get_auth_service()
        count = await svc.logout_all(user_id=user.id)
        return MessageResponse(message=f"Revoked {count} session(s).")

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

    @router.get("/sessions", response_model=list[SessionResponse])
    async def list_sessions(
        user: UserResponse = Depends(get_current_user(auth)),
    ) -> list[SessionResponse]:
        sessions = await auth.storage.session_repo.get_active_by_user(user.id)
        return [SessionResponse.model_validate(s) for s in sessions]

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
