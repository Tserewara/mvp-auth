# mvp-auth

Pluggable async JWT authentication library for rapid MVP development. Install, configure in ~5 lines, and get a complete auth system with all routes mounted.

**Database-agnostic** (defaults to PostgreSQL) · **Framework-agnostic** (first-class FastAPI integration) · **Async-first**

## Installation

```bash
# Core only
pip install git+https://github.com/Tserewara/mvp-auth.git

# With FastAPI + PostgreSQL (most common)
pip install "mvp-auth[fastapi,postgres] @ git+https://github.com/Tserewara/mvp-auth.git"

# Everything
pip install "mvp-auth[all] @ git+https://github.com/Tserewara/mvp-auth.git"
```

### Extras

| Extra      | What it adds                          |
|------------|---------------------------------------|
| `fastapi`  | FastAPI router & dependencies         |
| `postgres` | SQLAlchemy 2.0 async + asyncpg        |
| `argon2`   | argon2-cffi password hashing          |
| `dev`      | pytest, pytest-asyncio, httpx          |
| `all`      | All of the above                      |

## Quick Start — FastAPI + PostgreSQL

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends

from mvpauth import AuthConfig, create_auth
from mvpauth.storage.sqlalchemy import SQLAlchemyStorage, SQLAlchemyRequestStorage
from mvpauth.integrations.fastapi import (
    auth_router,
    get_current_user,
    install_exception_handlers,
)

# 1. Configure
config = AuthConfig(
    secret_key="change-me-in-production",
    database_url="postgresql+asyncpg://user:pass@localhost:5432/mydb",
)

# 2. Set up storage
db = SQLAlchemyStorage(config.database_url)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.create_tables()  # Creates auth_users, auth_sessions, auth_blocked_tokens
    yield


app = FastAPI(lifespan=lifespan)

# 3. Per-request storage middleware
@app.middleware("http")
async def db_session_middleware(request, call_next):
    async with db.get_session() as session:
        request.state.storage = db.request_storage(session)
        response = await call_next(request)
        await session.commit()
        return response


# 4. Create auth with a storage factory that reads from request state
auth = create_auth(config=config, storage=db.request_storage(db.get_session()))

# 5. Install exception handlers and mount routes
install_exception_handlers(app)
app.include_router(auth_router(auth), prefix="/auth")


# 6. Protect your own routes
@app.get("/protected")
async def protected(user=Depends(get_current_user(auth))):
    return {"message": f"Hello {user.email}", "user_id": str(user.id)}
```

## Quick Start — FastAPI + In-Memory (prototyping)

For rapid prototyping without a database:

```python
from fastapi import FastAPI, Depends

from mvpauth import AuthConfig, create_auth
from mvpauth.storage.memory import InMemoryStorage
from mvpauth.integrations.fastapi import (
    auth_router,
    get_current_user,
    install_exception_handlers,
)

app = FastAPI()

config = AuthConfig(secret_key="dev-secret-key")
storage = InMemoryStorage()
auth = create_auth(config=config, storage=storage)

install_exception_handlers(app)
app.include_router(auth_router(auth), prefix="/auth")


@app.get("/me")
async def whoami(user=Depends(get_current_user(auth))):
    return {"email": user.email, "verified": user.is_verified}
```

Run it:

```bash
uvicorn main:app --reload
```

All 13 auth routes are now live at `/auth/*`. Open `/docs` to explore them interactively.

## Configuration

All settings are configurable via environment variables (prefixed with `AUTH_`) or passed directly:

```python
from mvpauth import AuthConfig

# Via constructor
config = AuthConfig(
    secret_key="your-secret-key",
    access_token_expire_minutes=15,       # Access token TTL (default: 15)
    refresh_token_expire_days=30,         # Refresh token TTL (default: 30)
    algorithm="HS256",                    # JWT algorithm (default: HS256)
    password_algorithm="bcrypt",          # "bcrypt" or "argon2" (default: bcrypt)
    min_password_length=8,                # Minimum password length (default: 8)
    require_email_verification=False,     # Block login for unverified users (default: False)
    verification_token_expire_hours=24,   # Verification token TTL (default: 24)
    reset_token_expire_hours=1,           # Password reset token TTL (default: 1)
)
```

Or via environment variables:

```bash
export AUTH_SECRET_KEY="your-secret-key"
export AUTH_ACCESS_TOKEN_EXPIRE_MINUTES=30
export AUTH_REQUIRE_EMAIL_VERIFICATION=true
export AUTH_PASSWORD_ALGORITHM=argon2
```

## API Routes

All routes are mounted under a configurable prefix (default: `/auth`).

### Public Routes

| Method | Route                  | Body                                        | Response       |
|--------|------------------------|---------------------------------------------|----------------|
| POST   | `/register`            | `{"email": "...", "password": "..."}`       | `UserResponse` (201) |
| POST   | `/login`               | `{"email": "...", "password": "..."}`       | `TokenPair`    |
| POST   | `/refresh`             | `{"refresh_token": "..."}`                  | `TokenPair`    |
| POST   | `/verify-email`        | `{"token": "..."}`                          | `UserResponse` |
| POST   | `/resend-verification` | `{"email": "..."}`                          | `MessageResponse` |
| POST   | `/forgot-password`     | `{"email": "..."}`                          | `MessageResponse` |
| POST   | `/reset-password`      | `{"token": "...", "new_password": "..."}`   | `MessageResponse` |

### Protected Routes (Bearer token required)

| Method | Route                  | Body                                                  | Response       |
|--------|------------------------|-------------------------------------------------------|----------------|
| GET    | `/me`                  | —                                                     | `UserResponse` |
| POST   | `/logout`              | —                                                     | `MessageResponse` |
| POST   | `/logout-all`          | —                                                     | `MessageResponse` |
| POST   | `/change-password`     | `{"current_password": "...", "new_password": "..."}`  | `MessageResponse` |
| GET    | `/sessions`            | —                                                     | `SessionResponse[]` |
| DELETE | `/sessions/{id}`       | —                                                     | `MessageResponse` |

### Response Shapes

```jsonc
// TokenPair
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 900
}

// UserResponse
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "is_active": true,
  "is_verified": false,
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T10:30:00Z"
}

// Error
{
  "detail": "Invalid credentials",
  "code": "INVALID_CREDENTIALS"
}
```

## Email Hooks

mvp-auth doesn't send emails — it calls your async callback with the email address and a signed JWT token. Wire up any email provider you want:

```python
async def send_verification_email(email: str, token: str) -> None:
    # Use SendGrid, SES, Resend, or print to console — your choice
    verification_url = f"https://myapp.com/verify?token={token}"
    await my_email_service.send(
        to=email,
        subject="Verify your email",
        body=f"Click here: {verification_url}",
    )

async def send_reset_email(email: str, token: str) -> None:
    reset_url = f"https://myapp.com/reset-password?token={token}"
    await my_email_service.send(
        to=email,
        subject="Reset your password",
        body=f"Click here: {reset_url}",
    )

auth = create_auth(
    config=config,
    storage=storage,
    on_verification_email=send_verification_email,
    on_password_reset_email=send_reset_email,
)
```

If no hooks are provided, the registration and forgot-password endpoints still work — they just won't trigger any email delivery.

## Auth Flow Details

### Token Lifecycle

1. **Login** returns an access token (short-lived, 15 min) and a refresh token (long-lived, 30 days)
2. **Access token** is sent as `Authorization: Bearer <token>` on protected routes
3. When the access token expires, call `/refresh` with the refresh token to get a new pair
4. **Logout** blocklists the current access token's `jti`

### Refresh Token Rotation & Reuse Detection

Every call to `/refresh` issues a brand-new token pair and invalidates the old refresh token. If a previously-used refresh token is sent again (indicating a potential token theft), **all sessions for that user are immediately revoked**:

```
Client A (legitimate):  refresh(token_v1) → token_v2  ✓
Client B (attacker):    refresh(token_v1) → REUSE DETECTED → all sessions revoked
```

### Session Management

Each login creates a session record tracking:
- Device info (from `User-Agent` header)
- IP address
- Creation and expiry timestamps

Users can view their active sessions via `GET /sessions` and revoke individual sessions via `DELETE /sessions/{id}`.

## Custom Storage Backends

Implement the `StorageBackend` protocol to use any database:

```python
from mvpauth.storage.protocols import (
    StorageBackend,
    UserRepository,
    SessionRepository,
    TokenBlocklistRepository,
)

class MyCustomStorage:
    @property
    def user_repo(self) -> UserRepository: ...

    @property
    def session_repo(self) -> SessionRepository: ...

    @property
    def blocklist_repo(self) -> TokenBlocklistRepository: ...
```

Each repository is a `typing.Protocol` — no inheritance required. Any class that implements the right method signatures works.

## Using Services Directly

You don't have to use the FastAPI integration. The service layer works standalone:

```python
from mvpauth import AuthConfig, create_auth
from mvpauth.storage.memory import InMemoryStorage

config = AuthConfig(secret_key="my-secret")
storage = InMemoryStorage()
auth = create_auth(config=config, storage=storage)

# Register
user_svc = auth.get_user_service()
user = await user_svc.register(email="user@example.com", password="secure-pw-123")

# Login
auth_svc = auth.get_auth_service()
tokens = await auth_svc.login(email="user@example.com", password="secure-pw-123")
print(tokens.access_token)

# Refresh
new_tokens = await auth_svc.refresh(refresh_token=tokens.refresh_token)

# Change password
pw_svc = auth.get_password_service()
await pw_svc.change_password(
    user_id=user.id,
    current_password="secure-pw-123",
    new_password="even-more-secure-456",
)
```

## Error Handling

All errors extend `MvpAuthError` with a machine-readable `code`:

| Exception                      | HTTP Status | Code                        |
|-------------------------------|-------------|-----------------------------|
| `InvalidCredentialsError`     | 401         | `INVALID_CREDENTIALS`       |
| `TokenExpiredError`           | 401         | `TOKEN_EXPIRED`             |
| `TokenInvalidError`           | 401         | `TOKEN_INVALID`             |
| `TokenRevokedError`           | 401         | `TOKEN_REVOKED`             |
| `TokenReuseError`             | 401         | `TOKEN_REUSE`               |
| `UserNotVerifiedError`        | 403         | `EMAIL_NOT_VERIFIED`        |
| `UserExistsError`             | 409         | `USER_EXISTS`               |
| `AlreadyVerifiedError`        | 409         | `ALREADY_VERIFIED`          |
| `UserNotFoundError`           | 404         | `USER_NOT_FOUND`            |
| `SessionNotFoundError`        | 404         | `SESSION_NOT_FOUND`         |
| `InvalidPasswordError`        | 422         | `PASSWORD_VALIDATION`       |
| `InvalidVerificationTokenError` | 400       | `INVALID_VERIFICATION_TOKEN` |

Call `install_exception_handlers(app)` to automatically convert these to JSON responses with the appropriate status codes.

## Testing

```bash
pip install "mvp-auth[dev]"
pytest -xvs
```

Tests use the in-memory storage backend — no database needed.

## Architecture

```
mvpauth/
├── core/           # Pure logic — zero I/O, zero framework deps
│   ├── tokens.py       # JWT create/decode
│   ├── passwords.py    # bcrypt/argon2 hashing
│   ├── schemas.py      # Pydantic v2 models
│   └── exceptions.py   # Exception hierarchy
├── services/       # Business logic — uses storage via Protocol interfaces
│   ├── auth_service.py     # login, logout, refresh
│   ├── user_service.py     # register, verify, me
│   └── password_service.py # forgot, reset, change
├── storage/        # Database adapters
│   ├── protocols.py    # UserRepo, SessionRepo, TokenBlocklist protocols
│   ├── memory/         # In-memory (for tests & prototyping)
│   └── sqlalchemy/     # PostgreSQL via SQLAlchemy 2.0 async
└── integrations/   # Framework bindings
    └── fastapi/
        ├── router.py       # auth_router() factory
        └── dependencies.py # get_current_user, get_token_payload
```

## License

MIT
