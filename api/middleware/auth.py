"""JWT and API key authentication middleware for the OpenAgents API."""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..models.database import ApiKey, User, get_db

JWT_SECRET = os.environ["JWT_SECRET"]
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
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def generate_api_key() -> str:
    return "oa_" + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


async def get_api_key_user(request: Request, db: Session = Depends(get_db)) -> Optional[dict]:
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None

    api_key_hash = hash_api_key(api_key)
    active_keys = db.query(ApiKey).filter(ApiKey.is_active == 1).all()
    key_record = next(
        (record for record in active_keys if hmac.compare_digest(record.key_hash, api_key_hash)),
        None,
    )

    if key_record is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    user = db.query(User).filter(User.id == key_record.user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="API key owner not found")

    key_record.last_used_at = datetime.utcnow()
    db.commit()

    return {
        "id": user.id,
        "address": user.address,
        "roles": [],
        "auth_method": "api_key",
        "api_key_id": key_record.id,
    }


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    api_key_user: Optional[dict] = Depends(get_api_key_user),
) -> dict:
    if api_key_user is not None:
        return api_key_user

    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    payload = decode_token(credentials.credentials)

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    return {
        "id": user_id,
        "address": payload.get("address"),
        "roles": payload.get("roles", []),
        "auth_method": "jwt",
    }


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
