"""API key management endpoints."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..middleware.auth import generate_api_key, get_current_user, hash_api_key
from ..models.database import ApiKey, get_db

router = APIRouter(prefix="/auth", tags=["auth"])


class ApiKeyCreateResponse(BaseModel):
    id: int
    name: str
    api_key: str
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
    plaintext_key = generate_api_key()
    api_key = ApiKey(
        key_hash=hash_api_key(plaintext_key),
        name=name,
        user_id=user["id"],
        is_active=1,
        created_at=datetime.utcnow(),
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return ApiKeyCreateResponse(
        id=api_key.id,
        name=api_key.name,
        api_key=plaintext_key,
        created_at=api_key.created_at,
    )


@router.get("/api-keys", response_model=list[ApiKeyInfo])
async def list_api_keys(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    keys = db.query(ApiKey).filter(ApiKey.user_id == user["id"]).all()
    return [
        ApiKeyInfo(
            id=key.id,
            name=key.name,
            is_active=bool(key.is_active),
            created_at=key.created_at,
            last_used_at=key.last_used_at,
        )
        for key in keys
    ]


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found")
    if str(api_key.user_id) != str(user["id"]):
        raise HTTPException(status_code=403, detail="Not the owner of this API key")

    api_key.is_active = 0
    db.commit()
    return {"detail": "API key revoked", "id": key_id}
