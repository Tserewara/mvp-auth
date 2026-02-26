from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_")

    secret_key: str

    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30

    algorithm: str = "HS256"

    password_algorithm: str = "bcrypt"
    min_password_length: int = 8

    require_email_verification: bool = False
    verification_token_expire_hours: int = 24

    reset_token_expire_hours: int = 1

    database_url: str | None = None

    @property
    def access_token_expire_seconds(self) -> int:
        return self.access_token_expire_minutes * 60

    @property
    def refresh_token_expire_seconds(self) -> int:
        return self.refresh_token_expire_days * 86_400

    @property
    def verification_token_expire_seconds(self) -> int:
        return self.verification_token_expire_hours * 3600

    @property
    def reset_token_expire_seconds(self) -> int:
        return self.reset_token_expire_hours * 3600
