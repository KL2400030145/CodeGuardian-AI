import hashlib
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from jose import JWTError, jwt


_algorithm = "HS256"
_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    if os.getenv("APP_ENV", "development").lower() == "production":
        raise RuntimeError("SECRET_KEY must be configured in production.")
    _secret_key = secrets.token_urlsafe(48)
_password_hasher = PasswordHasher()
_login_attempts: dict[str, deque[float]] = defaultdict(deque)
_login_lock = threading.Lock()


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def create_access_token(user_id: int, session_id: int) -> str:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=int(os.getenv("ACCESS_TOKEN_MINUTES", "15")))
    return jwt.encode(
        {"sub": str(user_id), "sid": str(session_id), "iat": now, "exp": expires, "type": "access"},
        _secret_key,
        algorithm=_algorithm,
    )


def decode_access_token(token: str) -> tuple[int, int]:
    try:
        payload = jwt.decode(token, _secret_key, algorithms=[_algorithm])
        if payload.get("type") != "access":
            raise ValueError("Invalid token type.")
        return int(payload["sub"]), int(payload["sid"])
    except (JWTError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid or expired access token.") from exc


def create_refresh_token(days: int | None = None) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(48)
    lifetime = days if days is not None else int(os.getenv("REFRESH_TOKEN_DAYS", "7"))
    expires = datetime.now(timezone.utc) + timedelta(days=lifetime)
    return token, expires


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def allow_login_attempt(client_key: str, *, limit: int = 8, window_seconds: int = 300) -> bool:
    now = time.monotonic()
    with _login_lock:
        attempts = _login_attempts[client_key]
        while attempts and now - attempts[0] > window_seconds:
            attempts.popleft()
        if len(attempts) >= limit:
            return False
        attempts.append(now)
        return True


def clear_login_attempts(client_key: str) -> None:
    with _login_lock:
        _login_attempts.pop(client_key, None)
