from __future__ import annotations

import hashlib
import hmac

import bcrypt

from mvpauth.core.exceptions import InvalidPasswordError


def hash_password(password: str, *, algorithm: str = "bcrypt") -> str:
    if algorithm == "argon2":
        from argon2 import PasswordHasher

        ph = PasswordHasher()
        return ph.hash(password)
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    if hashed.startswith("$argon2"):
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError

        ph = PasswordHasher()
        try:
            return ph.verify(hashed, password)
        except VerifyMismatchError:
            return False
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def validate_password_strength(password: str, *, min_length: int = 8) -> None:
    if len(password) < min_length:
        raise InvalidPasswordError(
            f"Password must be at least {min_length} characters"
        )


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token_hash(token: str, token_hash: str) -> bool:
    computed = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed, token_hash)
