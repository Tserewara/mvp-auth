from __future__ import annotations

from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from mvpauth import AuthConfig, create_auth
from mvpauth.storage.memory import InMemoryStorage
from mvpauth.integrations.fastapi import Routes, auth_router, install_exception_handlers


@pytest.fixture
def app() -> FastAPI:
    config = AuthConfig(secret_key="test-secret-for-fastapi-router-tests!")
    storage = InMemoryStorage()
    auth = create_auth(config=config, storage=storage)
    app = FastAPI()
    install_exception_handlers(app)
    app.include_router(auth_router(auth), prefix="/auth")
    return app


@pytest.fixture
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _register_and_login(client: AsyncClient) -> dict[str, str]:
    await client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "password123"},
    )
    resp = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "password123"},
    )
    return resp.json()


class TestRegisterRoute:
    async def test_register_success(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/register",
            json={"email": "new@example.com", "password": "password123"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "new@example.com"
        assert "hashed_password" not in data

    async def test_register_duplicate(self, client: AsyncClient) -> None:
        await client.post(
            "/auth/register",
            json={"email": "dup@example.com", "password": "password123"},
        )
        resp = await client.post(
            "/auth/register",
            json={"email": "dup@example.com", "password": "password456"},
        )
        assert resp.status_code == 409

    async def test_register_invalid_email(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/register",
            json={"email": "not-email", "password": "password123"},
        )
        assert resp.status_code == 422


class TestLoginRoute:
    async def test_login_success(self, client: AsyncClient) -> None:
        await client.post(
            "/auth/register",
            json={"email": "login@example.com", "password": "password123"},
        )
        resp = await client.post(
            "/auth/login",
            json={"email": "login@example.com", "password": "password123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_wrong_password(self, client: AsyncClient) -> None:
        await client.post(
            "/auth/register",
            json={"email": "wrong@example.com", "password": "password123"},
        )
        resp = await client.post(
            "/auth/login",
            json={"email": "wrong@example.com", "password": "bad-password"},
        )
        assert resp.status_code == 401


class TestRefreshRoute:
    async def test_refresh_success(self, client: AsyncClient) -> None:
        tokens = await _register_and_login(client)
        resp = await client.post(
            "/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] != tokens["access_token"]


class TestMeRoute:
    async def test_success(self, client: AsyncClient) -> None:
        tokens = await _register_and_login(client)
        resp = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "user@example.com"

    async def test_no_token(self, client: AsyncClient) -> None:
        resp = await client.get("/auth/me")
        assert resp.status_code == 403


class TestLogoutRoute:
    async def test_logout(self, client: AsyncClient) -> None:
        tokens = await _register_and_login(client)
        resp = await client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert resp.status_code == 200

        # Token should now be revoked
        resp = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert resp.status_code == 401


class TestSessionsRoute:
    async def test_list_sessions(self, client: AsyncClient) -> None:
        tokens = await _register_and_login(client)
        resp = await client.get(
            "/auth/sessions",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1


class TestChangePasswordRoute:
    async def test_change_password(self, client: AsyncClient) -> None:
        tokens = await _register_and_login(client)
        resp = await client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={
                "current_password": "password123",
                "new_password": "new-password-456",
            },
        )
        assert resp.status_code == 200

        # Login with new password
        resp = await client.post(
            "/auth/login",
            json={"email": "user@example.com", "password": "new-password-456"},
        )
        assert resp.status_code == 200


class TestForgotPasswordRoute:
    async def test_forgot_password(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/forgot-password",
            json={"email": "noone@example.com"},
        )
        assert resp.status_code == 200  # Always returns 200


class TestResetPasswordRoute:
    async def test_invalid_token(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/reset-password",
            json={"token": "bad-token", "new_password": "newpassword123"},
        )
        assert resp.status_code == 400


# ── Route selection tests ────────────────────────────────────────


def _make_app(
    *,
    include: set[str] | frozenset[str] | None = None,
    exclude: set[str] | frozenset[str] | None = None,
) -> FastAPI:
    config = AuthConfig(secret_key="test-secret-for-route-selection!")
    storage = InMemoryStorage()
    auth = create_auth(config=config, storage=storage)
    app = FastAPI()
    install_exception_handlers(app)
    app.include_router(
        auth_router(auth, include=include, exclude=exclude), prefix="/auth"
    )
    return app


class TestRouteSelection:
    async def test_default_mounts_all(self) -> None:
        app = _make_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # Spot-check several routes exist (not 404/405)
            resp = await c.post(
                "/auth/register",
                json={"email": "a@b.com", "password": "password123"},
            )
            assert resp.status_code == 201

            resp = await c.post(
                "/auth/forgot-password", json={"email": "a@b.com"}
            )
            assert resp.status_code == 200

            resp = await c.get("/auth/sessions")
            # 403 (no auth), not 404 — route exists
            assert resp.status_code == 403

    async def test_include_subset(self) -> None:
        app = _make_app(include={Routes.REGISTER, Routes.LOGIN})
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/auth/register",
                json={"email": "a@b.com", "password": "password123"},
            )
            assert resp.status_code == 201

            resp = await c.post(
                "/auth/login",
                json={"email": "a@b.com", "password": "password123"},
            )
            assert resp.status_code == 200

            # /me is not mounted
            resp = await c.get("/auth/me")
            assert resp.status_code == 404

            # /refresh is not mounted
            resp = await c.post(
                "/auth/refresh", json={"refresh_token": "x"}
            )
            assert resp.status_code == 404

    async def test_exclude_routes(self) -> None:
        app = _make_app(exclude=Routes.SESSION_MANAGEMENT | Routes.VERIFY)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # Core routes still work
            resp = await c.post(
                "/auth/register",
                json={"email": "a@b.com", "password": "password123"},
            )
            assert resp.status_code == 201

            # Excluded routes return 404
            resp = await c.get("/auth/sessions")
            assert resp.status_code == 404

            resp = await c.post(
                "/auth/verify-email", json={"token": "x"}
            )
            assert resp.status_code == 404

    async def test_feature_group_core(self) -> None:
        app = _make_app(include=Routes.CORE)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/auth/register",
                json={"email": "a@b.com", "password": "password123"},
            )
            assert resp.status_code == 201

            # Password and verify routes not mounted
            resp = await c.post(
                "/auth/forgot-password", json={"email": "a@b.com"}
            )
            assert resp.status_code == 404

            resp = await c.post(
                "/auth/verify-email", json={"token": "x"}
            )
            assert resp.status_code == 404

    async def test_combine_groups(self) -> None:
        app = _make_app(include=Routes.CORE | Routes.PASSWORD)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/auth/register",
                json={"email": "a@b.com", "password": "password123"},
            )
            assert resp.status_code == 201

            resp = await c.post(
                "/auth/forgot-password", json={"email": "a@b.com"}
            )
            assert resp.status_code == 200

            # Verify group still excluded
            resp = await c.post(
                "/auth/verify-email", json={"token": "x"}
            )
            assert resp.status_code == 404

    async def test_group_plus_individual(self) -> None:
        app = _make_app(include=Routes.CORE | {Routes.CHANGE_PASSWORD})
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/auth/register",
                json={"email": "a@b.com", "password": "password123"},
            )
            assert resp.status_code == 201

            # change-password is mounted (needs auth to actually work)
            resp = await c.post(
                "/auth/change-password",
                json={
                    "current_password": "password123",
                    "new_password": "newpass456",
                },
            )
            # 403 because no auth header, but NOT 404 — route exists
            assert resp.status_code == 403

            # forgot-password is NOT mounted
            resp = await c.post(
                "/auth/forgot-password", json={"email": "a@b.com"}
            )
            assert resp.status_code == 404

    async def test_unknown_route_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown route names"):
            _make_app(include={"register", "nonexistent_route"})

    async def test_unknown_in_exclude_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown route names"):
            _make_app(exclude={"bad_name"})

    async def test_empty_result_raises(self) -> None:
        with pytest.raises(ValueError, match="No routes to mount"):
            _make_app(include={Routes.REGISTER}, exclude={Routes.REGISTER})
