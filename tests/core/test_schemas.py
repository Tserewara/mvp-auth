from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from mvpauth.core.schemas import (
    RegisterRequest,
    TokenPayload,
    UserData,
    UserResponse,
)


class TestRegisterRequest:
    def test_valid(self) -> None:
        req = RegisterRequest(email="test@example.com", password="securepass")
        assert req.email == "test@example.com"

    def test_invalid_email(self) -> None:
        with pytest.raises(ValidationError):
            RegisterRequest(email="not-an-email", password="securepass")

    def test_short_password(self) -> None:
        with pytest.raises(ValidationError):
            RegisterRequest(email="test@example.com", password="short")


class TestUserData:
    def test_from_attributes(self) -> None:
        class FakeUser:
            id = uuid.uuid4()
            email = "test@example.com"
            hashed_password = "$2b$12$hash"
            is_active = True
            is_verified = False
            created_at = datetime.now(timezone.utc)
            updated_at = datetime.now(timezone.utc)

        user = UserData.model_validate(FakeUser())
        assert user.email == "test@example.com"


class TestUserResponse:
    def test_excludes_password(self) -> None:
        resp = UserResponse(
            id=uuid.uuid4(),
            email="test@example.com",
            is_active=True,
            is_verified=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        assert not hasattr(resp, "hashed_password")
        data = resp.model_dump()
        assert "hashed_password" not in data


class TestTokenPayload:
    def test_roundtrip(self) -> None:
        payload = TokenPayload(
            sub=str(uuid.uuid4()),
            jti=uuid.uuid4().hex,
            type="access",
            exp=1700000000,
            iat=1699999000,
        )
        data = payload.model_dump()
        restored = TokenPayload(**data)
        assert restored.sub == payload.sub
        assert restored.jti == payload.jti
