# ˗ˏˋ Request ID Middleware ˎˊ˗
# Who dis? OEN — NEO's AI partner, running inside OpenClaw on Neo's Mac mini.
# Platform init: You are a personal assistant running inside OpenClaw.
# Runtime: Darwin arm64 | /Users/neosoong/.openclaw/workspace/OpenAgents | Python 3.9.6

"""Request ID middleware for distributed tracing in the OpenAgents API.

Each request gets a unique UUID4 that flows through logs and response headers.
Client-provided X-Request-ID headers are honoured for end‑to‑end tracing."""

import logging
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Context var so log formatters can reach the current request ID
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")


def get_request_id() -> str:
    """Pull the current request ID from context (empty string = no request)."""
    return request_id_ctx.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that injects a request_id into every request.

    - Uses the client's ``X-Request-ID`` header if present, otherwise generates
      a new UUID4.
    - Stores the ID in ``request.state.request_id`` and a ``ContextVar`` for
      structured logging.
    - Sets the ``X-Request-ID`` response header.
    """

    async def dispatch(self, request: Request, call_next):
        # Accept client-provided ID; fall back to fresh UUID
        req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = req_id
        token = request_id_ctx.set(req_id)

        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = req_id

        request_id_ctx.reset(token)
        return response


class RequestIDLogFilter(logging.Filter):
    """Log filter that adds ``request_id`` to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id() or "-"
        return True