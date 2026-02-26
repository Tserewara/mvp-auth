from __future__ import annotations

import pytest

from mvpauth.core.exceptions import InvalidPasswordError
from mvpauth.core.passwords import (
    hash_password,
    hash_token,
    validate_password_strength,
    verify_password,
    verify_token_hash,
)


class TestHashPassword:
    def test_bcrypt_roundtrip(self) -> None:
        password = "secure-password-123"
        hashed = hash_password(password, algorithm="bcrypt")
        assert hashed.startswith("$2b$")
        assert verify_password(password, hashed) is True

    def test_wrong_password(self) -> None:
        hashed = hash_password("correct-password", algorithm="bcrypt")
        assert verify_password("wrong-password", hashed) is False

    def test_different_hashes_for_same_password(self) -> None:
        password = "same-password"
        h1 = hash_password(password)
        h2 = hash_password(password)
        assert h1 != h2  # Salt should differ


class TestValidatePasswordStrength:
    def test_valid_password(self) -> None:
        validate_password_strength("long-enough-pw", min_length=8)

    def test_short_password_raises(self) -> None:
        with pytest.raises(InvalidPasswordError):
            validate_password_strength("short", min_length=8)

    def test_custom_min_length(self) -> None:
        validate_password_strength("ok", min_length=2)
        with pytest.raises(InvalidPasswordError):
            validate_password_strength("ok", min_length=5)


class TestTokenHash:
    def test_hash_and_verify(self) -> None:
        token = "some-refresh-token-value"
        h = hash_token(token)
        assert len(h) == 64  # SHA-256 hex
        assert verify_token_hash(token, h) is True

    def test_wrong_token(self) -> None:
        h = hash_token("original-token")
        assert verify_token_hash("different-token", h) is False
