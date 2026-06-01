"""Authentication endpoints for API key management."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from sqlalchemy.orm import Session

from ..models.database import get_db, ApiKey, User
from ..middleware.auth import (
    get_current_user,
    generate_api_key,
    hash_api_key,
    generate_login_tokens,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    address: str
    signature: Optional[str] = None


class ApiKeyCreateResponse(BaseModel):
    id: int
    name: str
    api_key: str  # Plaintext key shown once
    created_at: datetime


class ApiKeyInfo(BaseModel):
    id: int
    name: str
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None


@router.post("/api-keys", response_model=ApiKeyCreateResponse)
async def create_api_key(
    name: str,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a new API key. The returned plaintext key is shown only once."""
    plaintext_key = generate_api_key()
    key_hash = hash_api_key(plaintext_key)

    api_key_record = ApiKey(
        key_hash=key_hash,
        name=name,
        user_id=user["id"],
        is_active=1,
        created_at=datetime.utcnow(),
    )
    db.add(api_key_record)
    db.commit()
    db.refresh(api_key_record)

    return ApiKeyCreateResponse(
        id=api_key_record.id,
        name=api_key_record.name,
        api_key=plaintext_key,
        created_at=api_key_record.created_at,
    )


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke an API key by its ID."""
    key_record = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not key_record:
        raise HTTPException(status_code=404, detail="API key not found")
    if key_record.user_id != user["id"]:
        raise HTTPException(status_code=403, detail="Not the owner of this API key")

    key_record.is_active = 0
    db.commit()
    return {"detail": "API key revoked", "id": key_id}


@router.get("/api-keys", response_model=list[ApiKeyInfo])
async def list_api_keys(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all API keys for the authenticated user."""
    keys = db.query(ApiKey).filter(ApiKey.user_id == user["id"]).all()
    return [
        ApiKeyInfo(
            id=k.id,
            name=k.name,
            is_active=bool(k.is_active),
            created_at=k.created_at,
            last_used_at=k.last_used_at,
        )
        for k in keys
    ]


@router.post("/login")
async def login(
    login_req: LoginRequest,
    db: Session = Depends(get_db),
):
    """Login or register with a wallet address.

    In production this would verify a signed message. For development,
    any valid address is accepted.
    """
    user = db.query(User).filter(User.address == login_req.address).first()
    if not user:
        user = User(
            address=login_req.address,
            created_at=datetime.utcnow(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    tokens = generate_login_tokens(str(user.id), user.address)
    return tokens