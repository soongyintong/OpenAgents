"""Tests for the Request ID middleware.

Covers:
- Header presence on every response
- Client-provided X-Request-ID pass-through
- Unique IDs per request
- Health and agent endpoints still work
"""

import os
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

os.environ["JWT_SECRET"] = "test-secret-for-ci"

from main import app  # noqa: E402

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_response_has_request_id(client: AsyncClient):
    """Every response must include an X-Request-ID header."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers
    rid = resp.headers["X-Request-ID"]
    assert len(rid) > 0


@pytest.mark.asyncio
async def test_request_ids_are_unique(client: AsyncClient):
    """Two separate requests should get different IDs."""
    r1 = await client.get("/health")
    r2 = await client.get("/health")
    id1 = r1.headers["X-Request-ID"]
    id2 = r2.headers["X-Request-ID"]
    assert id1 != id2, "request IDs must be unique per request"


@pytest.mark.asyncio
async def test_client_provided_id_is_preserved(client: AsyncClient):
    """If the client sends an X-Request-ID it should be echoed back."""
    my_id = str(uuid.uuid4())
    resp = await client.get("/health", headers={"X-Request-ID": my_id})
    assert resp.status_code == 200
    assert resp.headers["X-Request-ID"] == my_id


@pytest.mark.asyncio
async def test_health_endpoint_still_works(client: AsyncClient):
    """The health check should return normally with request ID."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"


@pytest.mark.asyncio
async def test_agents_endpoint_still_works(client: AsyncClient):
    """Agent listing should return normally with request ID."""
    resp = await client.get("/agents")
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers


@pytest.mark.asyncio
async def test_tasks_endpoint_still_works(client: AsyncClient):
    """Task listing should return normally with request ID."""
    resp = await client.get("/tasks")
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers


@pytest.mark.asyncio
async def test_404_still_has_request_id(client: AsyncClient):
    """Even error responses must carry request ID."""
    resp = await client.get("/agents/nonexistent")
    assert resp.status_code == 404
    assert "X-Request-ID" in resp.headers
    assert len(resp.headers["X-Request-ID"]) > 0