import os
from datetime import datetime

import jwt
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("JWT_SECRET", "test-secret")

from api.middleware.auth import (  # noqa: E402
    create_access_token,
    generate_api_key,
    get_current_user,
    hash_api_key,
)
from api.models.database import ApiKey, Base, User, get_db  # noqa: E402
from api.routes.auth import router as auth_router  # noqa: E402


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    app = FastAPI()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    @app.get("/protected")
    async def protected(user: dict = Depends(get_current_user)):
        return user

    app.include_router(auth_router)
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        test_client.db = TestingSessionLocal
        yield test_client


def create_user(client, address="0x0000000000000000000000000000000000000001"):
    db = client.db()
    user = User(address=address, created_at=datetime.utcnow())
    db.add(user)
    db.commit()
    db.refresh(user)
    user_id = user.id
    db.close()
    return user_id


def create_key(client, user_id, active=True):
    plaintext = generate_api_key()
    db = client.db()
    api_key = ApiKey(
        key_hash=hash_api_key(plaintext),
        name="test-key",
        user_id=user_id,
        is_active=1 if active else 0,
        created_at=datetime.utcnow(),
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    key_id = api_key.id
    db.close()
    return plaintext, key_id


def test_jwt_auth_accepts_valid_token(client):
    token = create_access_token({"sub": "123", "address": "0xtest"})
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["auth_method"] == "jwt"


def test_jwt_decode_rejects_alg_none(client):
    token = jwt.encode(
        {"sub": "123", "address": "0xtest", "type": "access"},
        key="",
        algorithm="none",
    )
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_api_key_auth_accepts_valid_key(client):
    user_id = create_user(client)
    plaintext, _ = create_key(client, user_id)

    response = client.get("/protected", headers={"X-API-Key": plaintext})

    assert response.status_code == 200
    assert response.json()["auth_method"] == "api_key"
    assert response.json()["id"] == user_id


def test_api_key_auth_rejects_revoked_key(client):
    user_id = create_user(client)
    plaintext, _ = create_key(client, user_id, active=False)

    response = client.get("/protected", headers={"X-API-Key": plaintext})

    assert response.status_code == 401


def test_api_key_hash_uses_sha256():
    key = "oa_test_key"
    expected = __import__("hashlib").sha256(key.encode("utf-8")).hexdigest()

    assert hash_api_key(key) == expected


def test_create_api_key_returns_plaintext_once_and_stores_hash(client):
    user_id = create_user(client)
    token = create_access_token({"sub": str(user_id), "address": "0xtest"})

    response = client.post(
        "/auth/api-keys?name=integration",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["api_key"].startswith("oa_")

    db = client.db()
    stored = db.query(ApiKey).filter(ApiKey.id == body["id"]).first()
    assert stored.key_hash == hash_api_key(body["api_key"])
    assert stored.key_hash != body["api_key"]
    db.close()


def test_revoke_api_key_immediately_blocks_key(client):
    user_id = create_user(client)
    plaintext, key_id = create_key(client, user_id)
    token = create_access_token({"sub": str(user_id), "address": "0xtest"})

    response = client.delete(
        f"/auth/api-keys/{key_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    blocked = client.get("/protected", headers={"X-API-Key": plaintext})

    assert response.status_code == 200
    assert blocked.status_code == 401
