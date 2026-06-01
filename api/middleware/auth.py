"""JWT + API Key authentication middleware for the OpenAgents API."""

import hashlib
import hmac
import jwt
import os
import secrets
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session
from ..models.database import get_db, ApiKey, User

# BUG: No fallback — if JWT_SECRET is not set, os.environ[] raises KeyError
# crashing the entire application on startup
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

security = HTTPBearer(auto_error=False)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "access"})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "refresh"})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        # BUG: Algorithm not pinned in decode — attacker can forge a token with
        # alg: "none" and bypass signature verification entirely
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def hash_api_key(key: str) -> str:
    """Return SHA-256 hex digest of the API key."""
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> str:
    """Generate a cryptographically secure random API key."""
    return "oa_" + secrets.token_urlsafe(32)


async def get_api_key_user(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[dict]:
    """Validate X-API-Key header and return user data if valid."""
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None

    key_hash = hash_api_key(api_key)
    key_record = db.query(ApiKey).filter(
        ApiKey.key_hash == key_hash,
        ApiKey.is_active == 1,
    ).first()

    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    # Update last_used_at
    key_record.last_used_at = datetime.utcnow()
    db.commit()

    user = db.query(User).filter(User.id == key_record.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="API key owner not found")

    return {
        "id": user.id,
        "address": user.address,
        "roles": [],
        "auth_method": "api_key",
        "api_key_id": key_record.id,
        "api_key_name": key_record.name,
    }


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    api_key_user: Optional[dict] = Depends(get_api_key_user),
) -> dict:
    """Get the current authenticated user, checking JWT first, then API key."""

    # If API key authentication succeeded, return that
    if api_key_user is not None:
        return api_key_user

    # Fall back to JWT
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide either a Bearer JWT token or an X-API-Key header.",
        )

    token = credentials.credentials
    payload = decode_token(token)

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    # BUG: No token revocation check — logged-out or compromised tokens
    # remain valid until they naturally expire
    try:
        user_id = int(payload.get("sub"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user_data = {
        "id": user_id,
        "address": payload.get("address"),
        "roles": payload.get("roles", []),
        "auth_method": "jwt",
    }

    return user_data


def require_role(role: str):
    async def role_checker(user: dict = Depends(get_current_user)):
        if role not in user.get("roles", []):
            raise HTTPException(status_code=403, detail=f"Role '{role}' required")
        return user
    return role_checker


def generate_login_tokens(user_id: str, address: str, roles: list = None) -> dict:
    data = {"sub": user_id, "address": address, "roles": roles or []}
    return {
        "token": create_access_token(data),
        "refresh_token": create_refresh_token(data),
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }