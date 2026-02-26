from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ── Internal domain objects ──────────────────────────────────────


class UserData(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    hashed_password: str
    is_active: bool = True
    is_verified: bool = False
    created_at: datetime
    updated_at: datetime


class SessionData(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    refresh_token_hash: str
    device_info: str | None = None
    ip_address: str | None = None
    created_at: datetime
    expires_at: datetime
    is_revoked: bool = False


class BlockedTokenData(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    jti: str
    token_type: str
    expires_at: datetime


# ── Request schemas ──────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


# ── Response schemas ─────────────────────────────────────────────


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_info: str | None = None
    ip_address: str | None = None
    created_at: datetime
    expires_at: datetime
    is_revoked: bool


class MessageResponse(BaseModel):
    message: str


# ── Token payload (JWT claims) ───────────────────────────────────


class TokenPayload(BaseModel):
    sub: str
    jti: str
    type: str
    session_id: str | None = None
    exp: int
    iat: int
