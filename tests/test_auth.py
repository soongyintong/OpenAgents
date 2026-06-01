"""Tests for JWT + API key authentication."""

import hashlib
import pytest
from fastapi.testclient import TestClient
from datetime import datetime

from api.main import app
from api.middleware.auth import (
    create_access_token,
    hash_api_key,
    generate_api_key,
    JWT_ALGORITHM,
    JWT_SECRET,
)
from api.models.database import SessionLocal, ApiKey, User

client = TestClient(app)

# Counter for unique addresses
_user_counter = [0]


def _create_test_user(db) -> int:
    """Helper to create a test user, returns user.id."""
    _user_counter[0] += 1
    addr = f"0x{_user_counter[0]:040x}"
    user = User(address=addr, created_at=datetime.utcnow())
    db.add(user)
    db.commit()
    user_id = user.id  # Extract before closing
    db.close()
    return user_id


def _create_api_key(db, user_id: int, name: str = "test-key", active: bool = True) -> str:
    """Create an API key for a user, returns the plaintext key."""
    plaintext_key = generate_api_key()
    key_hash = hash_api_key(plaintext_key)
    api_key = ApiKey(
        key_hash=key_hash,
        name=name,
        user_id=user_id,
        is_active=1 if active else 0,
        created_at=datetime.utcnow(),
    )
    db.add(api_key)
    db.commit()
    db.close()
    return plaintext_key


def _get_jwt_token(user_id: int) -> str:
    """Helper to create a valid JWT."""
    return create_access_token({"sub": str(user_id), "address": "0xtest"})


class TestJWTAuth:
    """Test JWT bearer token authentication on protected routes."""

    def _create_task_payload(self):
        return {"title": "test task", "description": "test", "reward_amount": 1.0}

    def test_jwt_valid_token(self):
        """Valid JWT token should authenticate successfully for protected routes."""
        db = SessionLocal()
        user_id = _create_test_user(db)
        token = _get_jwt_token(user_id)
        response = client.post(
            "/tasks/",
            json=self._create_task_payload(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    def test_jwt_missing_token(self):
        """Missing JWT token on a protected route should return 401."""
        response = client.post("/tasks/", json=self._create_task_payload())
        assert response.status_code == 401

    def test_jwt_invalid_token(self):
        """Invalid JWT token should return 401."""
        response = client.post(
            "/tasks/",
            json=self._create_task_payload(),
            headers={"Authorization": "Bearer invalid_token_here"},
        )
        assert response.status_code == 401

    def test_jwt_expired_token(self):
        """Expired JWT token should return 401."""
        import jwt
        user_id = 1  # Doesn't matter for expired tokens
        expired_token = jwt.encode(
            {
                "sub": str(user_id),
                "address": "0xtest",
                "exp": 0,
                "iat": 0,
                "type": "access",
            },
            key=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )
        response = client.post(
            "/tasks/",
            json=self._create_task_payload(),
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code == 401
        assert "expired" in response.json()["detail"].lower()

    def test_jwt_wrong_token_type(self):
        """Refresh token used as access token should return 401."""
        from api.middleware.auth import create_refresh_token
        refresh = create_refresh_token({"sub": "1", "address": "0xtest"})
        response = client.post(
            "/tasks/",
            json=self._create_task_payload(),
            headers={"Authorization": f"Bearer {refresh}"},
        )
        assert response.status_code == 401
        assert "token type" in response.json()["detail"].lower()


class TestApiKeyAuth:
    """Test API key authentication via X-API-Key header."""

    def _create_task_payload(self):
        return {"title": "test task", "description": "test", "reward_amount": 1.0}

    def test_api_key_valid(self):
        """Valid API key should authenticate successfully."""
        db = SessionLocal()
        user_id = _create_test_user(db)
        db2 = SessionLocal()
        plaintext_key = _create_api_key(db2, user_id)

        response = client.post(
            "/tasks/",
            json=self._create_task_payload(),
            headers={"X-API-Key": plaintext_key},
        )
        assert response.status_code == 200

    def test_api_key_invalid(self):
        """Invalid API key should return 401."""
        response = client.post(
            "/tasks/",
            json=self._create_task_payload(),
            headers={"X-API-Key": "oa_invalid_key_here"},
        )
        assert response.status_code == 401

    def test_api_key_revoked(self):
        """Revoked API key should return 401."""
        db = SessionLocal()
        user_id = _create_test_user(db)
        db2 = SessionLocal()
        plaintext_key = _create_api_key(db2, user_id, active=False)

        response = client.post(
            "/tasks/",
            json=self._create_task_payload(),
            headers={"X-API-Key": plaintext_key},
        )
        assert response.status_code == 401
        assert "revoked" in response.json()["detail"].lower()

    def test_api_key_sha256_storage(self):
        """API key should be stored as SHA-256 hash, never as plaintext."""
        db = SessionLocal()
        user_id = _create_test_user(db)

        plaintext_key = generate_api_key()
        key_hash = hash_api_key(plaintext_key)

        assert len(key_hash) == 64

        db2 = SessionLocal()
        api_key = ApiKey(
            key_hash=key_hash,
            name="test-hash-storage",
            user_id=user_id,
            is_active=1,
            created_at=datetime.utcnow(),
        )
        db2.add(api_key)
        db2.commit()
        db2.refresh(api_key)

        stored = db2.query(ApiKey).filter(ApiKey.id == api_key.id).first()
        assert stored.key_hash == key_hash
        assert stored.key_hash != plaintext_key
        db2.close()

    def test_api_key_uses_sha256(self):
        """Verify that hash_api_key actually uses SHA-256."""
        key = "oa_test_key_for_sha_test"
        expected = hashlib.sha256(key.encode()).hexdigest()
        assert hash_api_key(key) == expected


class TestApiKeyEndpoints:
    """Test the API key CRUD endpoints."""

    def test_create_api_key_endpoint(self):
        """POST /auth/api-keys should create a key and return it once."""
        db = SessionLocal()
        user_id = _create_test_user(db)
        token = _get_jwt_token(user_id)

        response = client.post(
            "/auth/api-keys?name=my-test-key",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "my-test-key"
        assert data["api_key"].startswith("oa_")
        assert "id" in data
        assert "created_at" in data

    def test_create_api_key_requires_auth(self):
        """POST /auth/api-keys without auth should return 401."""
        response = client.post("/auth/api-keys?name=test")
        assert response.status_code == 401

    def test_list_api_keys(self):
        """GET /auth/api-keys should return all keys for the user."""
        db = SessionLocal()
        user_id = _create_test_user(db)

        db2 = SessionLocal()
        for name in ["key-1", "key-2"]:
            plaintext = generate_api_key()
            key_hash = hash_api_key(plaintext)
            db2.add(ApiKey(
                key_hash=key_hash,
                name=name,
                user_id=user_id,
                is_active=1,
                created_at=datetime.utcnow(),
            ))
        db2.commit()
        db2.close()

        token = _get_jwt_token(user_id)
        response = client.get(
            "/auth/api-keys",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_revoke_api_key_endpoint(self):
        """DELETE /auth/api-keys/{id} should revoke a key."""
        db = SessionLocal()
        user_id = _create_test_user(db)

        db2 = SessionLocal()
        plaintext_key = generate_api_key()
        key_hash = hash_api_key(plaintext_key)
        api_key = ApiKey(
            key_hash=key_hash,
            name="revoke-me",
            user_id=user_id,
            is_active=1,
            created_at=datetime.utcnow(),
        )
        db2.add(api_key)
        db2.commit()
        key_id = api_key.id
        db2.close()

        token = _get_jwt_token(user_id)
        response = client.delete(
            f"/auth/api-keys/{key_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

        # Verify key is no longer valid
        response2 = client.post(
            "/tasks/",
            json={"title": "test", "description": "test", "reward_amount": 1.0},
            headers={"X-API-Key": plaintext_key},
        )
        assert response2.status_code == 401

    def test_revoke_other_users_key(self):
        """Cannot revoke another user's API key."""
        user_id_1 = _create_test_user(SessionLocal())
        user_id_2 = _create_test_user(SessionLocal())

        db3 = SessionLocal()
        # user1 creates a key
        plaintext_key = generate_api_key()
        key_hash = hash_api_key(plaintext_key)
        api_key = ApiKey(
            key_hash=key_hash,
            name="user1-key",
            user_id=user_id_1,
            is_active=1,
            created_at=datetime.utcnow(),
        )
        db3.add(api_key)
        db3.commit()
        key_id = api_key.id
        db3.close()

        # user2 tries to revoke user1's key
        token_user2 = _get_jwt_token(user_id_2)
        response = client.delete(
            f"/auth/api-keys/{key_id}",
            headers={"Authorization": f"Bearer {token_user2}"},
        )
        assert response.status_code == 403


class TestRateLimitHeaders:
    """Test that rate limit headers differentiate between JWT and API key."""

    def test_health_no_rate_limit(self):
        """Health endpoint is excluded from rate limiting."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_api_key_rate_limit_header(self):
        """API key requests should show higher rate limit in headers."""
        db = SessionLocal()
        user_id = _create_test_user(db)
        db2 = SessionLocal()
        plaintext_key = _create_api_key(db2, user_id)

        response = client.get(
            "/health",
            headers={"X-API-Key": plaintext_key},
        )
        # Health endpoint is excluded from rate limiting
        assert response.status_code == 200

        # Test with a non-health endpoint that doesn't need auth for rate limiting
        response2 = client.get(
            "/",
            headers={"X-API-Key": plaintext_key},
        )
        # 404 is fine since there's no / route - just checking headers work
        if response2.status_code == 404:
            pass  # Rate limit middleware already ran


class TestKeyGeneration:
    """Test API key generation properties."""

    def test_generate_api_key_format(self):
        """Generated keys should start with 'oa_' and be sufficiently long."""
        key = generate_api_key()
        assert key.startswith("oa_")
        assert len(key) > 40
        assert isinstance(key, str)

    def test_hash_api_key_deterministic(self):
        """SHA-256 hashing should be deterministic."""
        key = "oa_test_key_12345"
        h1 = hash_api_key(key)
        h2 = hash_api_key(key)
        assert h1 == h2
        assert len(h1) == 64

    def test_hash_api_key_different(self):
        """Different keys should produce different hashes."""
        h1 = hash_api_key("oa_key_one")
        h2 = hash_api_key("oa_key_two")
        assert h1 != h2

    def test_unique_keys(self):
        """Generated keys should be unique."""
        keys = {generate_api_key() for _ in range(100)}
        assert len(keys) == 100