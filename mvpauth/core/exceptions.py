from __future__ import annotations


class MvpAuthError(Exception):
    """Root of all mvp-auth exceptions."""

    def __init__(self, message: str = "", *, code: str = "AUTH_ERROR") -> None:
        self.message = message
        self.code = code
        super().__init__(message)


class InvalidCredentialsError(MvpAuthError):
    def __init__(self, message: str = "Invalid credentials") -> None:
        super().__init__(message, code="INVALID_CREDENTIALS")


class TokenError(MvpAuthError):
    def __init__(self, message: str = "Token error", *, code: str = "TOKEN_ERROR") -> None:
        super().__init__(message, code=code)


class TokenExpiredError(TokenError):
    def __init__(self, message: str = "Token has expired") -> None:
        super().__init__(message, code="TOKEN_EXPIRED")


class TokenInvalidError(TokenError):
    def __init__(self, message: str = "Token is invalid") -> None:
        super().__init__(message, code="TOKEN_INVALID")


class TokenRevokedError(TokenError):
    def __init__(self, message: str = "Token has been revoked") -> None:
        super().__init__(message, code="TOKEN_REVOKED")


class TokenReuseError(TokenError):
    def __init__(self, message: str = "Refresh token reuse detected") -> None:
        super().__init__(message, code="TOKEN_REUSE")


class UserExistsError(MvpAuthError):
    def __init__(self, message: str = "User already exists") -> None:
        super().__init__(message, code="USER_EXISTS")


class UserNotFoundError(MvpAuthError):
    def __init__(self, message: str = "User not found") -> None:
        super().__init__(message, code="USER_NOT_FOUND")


class UserNotVerifiedError(MvpAuthError):
    def __init__(self, message: str = "Email not verified") -> None:
        super().__init__(message, code="EMAIL_NOT_VERIFIED")


class SessionNotFoundError(MvpAuthError):
    def __init__(self, message: str = "Session not found") -> None:
        super().__init__(message, code="SESSION_NOT_FOUND")


class InvalidPasswordError(MvpAuthError):
    def __init__(self, message: str = "Password does not meet requirements") -> None:
        super().__init__(message, code="PASSWORD_VALIDATION")


class AlreadyVerifiedError(MvpAuthError):
    def __init__(self, message: str = "Email is already verified") -> None:
        super().__init__(message, code="ALREADY_VERIFIED")


class InvalidVerificationTokenError(MvpAuthError):
    def __init__(self, message: str = "Invalid verification token") -> None:
        super().__init__(message, code="INVALID_VERIFICATION_TOKEN")
