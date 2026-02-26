from __future__ import annotations

import pytest

from mvpauth import Auth, AuthConfig, create_auth
from mvpauth.storage.memory import InMemoryStorage


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(secret_key="test-secret-key-for-mvp-auth-unit-tests!")


@pytest.fixture
def storage() -> InMemoryStorage:
    return InMemoryStorage()


@pytest.fixture
def auth(config: AuthConfig, storage: InMemoryStorage) -> Auth:
    return create_auth(config=config, storage=storage)
