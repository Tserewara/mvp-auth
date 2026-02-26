from __future__ import annotations


class Routes:
    """Route name constants and feature groups for selective route mounting.

    Individual names are strings. Feature groups are frozensets that can be
    combined with ``|`` and mixed freely::

        from mvpauth.integrations.fastapi import Routes, auth_router

        # Feature groups
        auth_router(auth, include=Routes.CORE | Routes.PASSWORD)

        # Group + individual route
        auth_router(auth, include=Routes.CORE | {Routes.CHANGE_PASSWORD})

        # Exclude specific groups
        auth_router(auth, exclude=Routes.SESSION_MANAGEMENT | Routes.VERIFY)
    """

    # ── Individual route names ───────────────────────────────────
    REGISTER: str = "register"
    LOGIN: str = "login"
    REFRESH: str = "refresh"
    VERIFY_EMAIL: str = "verify_email"
    RESEND_VERIFICATION: str = "resend_verification"
    FORGOT_PASSWORD: str = "forgot_password"
    RESET_PASSWORD: str = "reset_password"
    ME: str = "me"
    LOGOUT: str = "logout"
    LOGOUT_ALL: str = "logout_all"
    CHANGE_PASSWORD: str = "change_password"
    SESSIONS: str = "sessions"
    REVOKE_SESSION: str = "revoke_session"

    # ── Feature groups ───────────────────────────────────────────
    CORE: frozenset[str] = frozenset({
        REGISTER, LOGIN, REFRESH, ME, LOGOUT,
    })
    VERIFY: frozenset[str] = frozenset({
        VERIFY_EMAIL, RESEND_VERIFICATION,
    })
    PASSWORD: frozenset[str] = frozenset({
        FORGOT_PASSWORD, RESET_PASSWORD, CHANGE_PASSWORD,
    })
    SESSION_MANAGEMENT: frozenset[str] = frozenset({
        SESSIONS, REVOKE_SESSION, LOGOUT_ALL,
    })

    ALL: frozenset[str] = CORE | VERIFY | PASSWORD | SESSION_MANAGEMENT
