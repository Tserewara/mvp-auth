from __future__ import annotations

import time
import uuid

import pytest

from mvpauth.core.exceptions import TokenExpiredError, TokenInvalidError
from mvpauth.core.tokens import (
    create_access_token,
    create_refresh_token,
    create_token,
    decode_token,
)

SECRET = "test-secret-key-for-tokens"


class TestCreateAccessToken:
    def test_creates_valid_token(self) -> None:
        user_id = uuid.uuid4()
        token, payload = create_access_token(
            user_id=user_id, secret_key=SECRET, expires_seconds=300
        )
        assert isinstance(token, str)
        assert payload.type == "access"
        assert payload.sub == str(user_id)
        assert payload.session_id is None

    def test_unique_jti(self) -> None:
        user_id = uuid.uuid4()
        _, p1 = create_access_token(user_id=user_id, secret_key=SECRET)
        _, p2 = create_access_token(user_id=user_id, secret_key=SECRET)
        assert p1.jti != p2.jti


class TestCreateRefreshToken:
    def test_creates_valid_token(self) -> None:
        user_id = uuid.uuid4()
        session_id = uuid.uuid4()
        token, payload = create_refresh_token(
            user_id=user_id, session_id=session_id, secret_key=SECRET
        )
        assert isinstance(token, str)
        assert payload.type == "refresh"
        assert payload.session_id == str(session_id)


class TestCreateToken:
    def test_custom_type(self) -> None:
        user_id = uuid.uuid4()
        token, payload = create_token(
            user_id=user_id,
            token_type="email_verify",
            secret_key=SECRET,
            expires_seconds=3600,
        )
        assert payload.type == "email_verify"


class TestDecodeToken:
    def test_decode_valid(self) -> None:
        user_id = uuid.uuid4()
        token, original = create_access_token(
            user_id=user_id, secret_key=SECRET, expires_seconds=300
        )
        decoded = decode_token(token, secret_key=SECRET)
        assert decoded.sub == original.sub
        assert decoded.jti == original.jti
        assert decoded.type == "access"

    def test_decode_expired(self) -> None:
        user_id = uuid.uuid4()
        token, _ = create_access_token(
            user_id=user_id, secret_key=SECRET, expires_seconds=-1
        )
        with pytest.raises(TokenExpiredError):
            decode_token(token, secret_key=SECRET)

    def test_decode_invalid_token(self) -> None:
        with pytest.raises(TokenInvalidError):
            decode_token("not-a-real-token", secret_key=SECRET)

    def test_decode_wrong_secret(self) -> None:
        user_id = uuid.uuid4()
        token, _ = create_access_token(user_id=user_id, secret_key=SECRET)
        with pytest.raises(TokenInvalidError):
            decode_token(token, secret_key="wrong-secret")

    def test_expected_type_mismatch(self) -> None:
        user_id = uuid.uuid4()
        token, _ = create_access_token(user_id=user_id, secret_key=SECRET)
        with pytest.raises(TokenInvalidError):
            decode_token(token, secret_key=SECRET, expected_type="refresh")

    def test_expected_type_match(self) -> None:
        user_id = uuid.uuid4()
        session_id = uuid.uuid4()
        token, _ = create_refresh_token(
            user_id=user_id, session_id=session_id, secret_key=SECRET
        )
        payload = decode_token(token, secret_key=SECRET, expected_type="refresh")
        assert payload.type == "refresh"
