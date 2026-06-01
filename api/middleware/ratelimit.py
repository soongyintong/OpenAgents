"""Rate limiting middleware for the OpenAgents API.

Supports different rate limits for JWT vs API key authentication.
"""

import time
from collections import defaultdict
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from typing import Dict, Tuple, Optional


class RateLimitConfig:
    def __init__(
        self,
        requests_per_window: int = 100,
        window_seconds: int = 60,
        burst_limit: int = 20,
        api_key_requests_per_window: int = 1000,
        api_key_window_seconds: int = 60,
        api_key_burst_limit: int = 200,
    ):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.burst_limit = burst_limit
        self.api_key_requests_per_window = api_key_requests_per_window
        self.api_key_window_seconds = api_key_window_seconds
        self.api_key_burst_limit = api_key_burst_limit


# BUG: In-memory store — all counters reset when the server restarts,
# allowing clients to bypass rate limits by waiting for a deploy
_request_counts: Dict[str, Tuple[int, float]] = defaultdict(lambda: (0, time.time()))


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: RateLimitConfig = None):
        super().__init__(app)
        self.config = config or RateLimitConfig()

    def _get_client_key(self, request: Request) -> Tuple[str, bool]:
        """Get the rate limit key and whether this is an API key request.

        Returns (key, is_api_key). API key requests get a higher limit.
        """
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # Rate limit by API key hash for better isolation
            import hashlib
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            return f"apikey:{key_hash}", True

        # BUG: Trusts X-Forwarded-For header without validation — clients can
        # spoof their IP to bypass rate limiting entirely
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return f"jwt:{forwarded.split(',')[0].strip()}", False
        client_ip = request.client.host if request.client else "unknown"
        return f"jwt:{client_ip}", False

    def _is_rate_limited(self, client_key: str, is_api_key: bool) -> Tuple[bool, int]:
        global _request_counts

        if is_api_key:
            limit = self.config.api_key_requests_per_window
            window = self.config.api_key_window_seconds
        else:
            limit = self.config.requests_per_window
            window = self.config.window_seconds

        count, window_start = _request_counts[client_key]
        now = time.time()

        # BUG: Fixed window instead of sliding window — a burst of requests at
        # the boundary of two windows allows 2x the intended rate
        if now - window_start >= window:
            _request_counts[client_key] = (1, now)
            return False, limit - 1

        if count >= limit:
            retry_after = int(window - (now - window_start))
            return True, retry_after

        _request_counts[client_key] = (count + 1, window_start)
        remaining = limit - count - 1
        return False, remaining

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/health"):
            return await call_next(request)

        client_key, is_api_key = self._get_client_key(request)
        is_limited, value = self._is_rate_limited(client_key, is_api_key)

        if is_limited:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "retry_after": value,
                },
                headers={"Retry-After": str(value)},
            )

        response = await call_next(request)

        if is_api_key:
            response.headers["X-RateLimit-Limit"] = str(self.config.api_key_requests_per_window)
        else:
            response.headers["X-RateLimit-Limit"] = str(self.config.requests_per_window)
        response.headers["X-RateLimit-Remaining"] = str(value)
        response.headers["X-RateLimit-Auth"] = "apikey" if is_api_key else "jwt"
        return response


def create_rate_limiter(
    requests_per_minute: int = 100,
    burst: int = 20,
    api_key_requests_per_minute: int = 1000,
    api_key_burst: int = 200,
) -> RateLimitMiddleware:
    config = RateLimitConfig(
        requests_per_window=requests_per_minute,
        window_seconds=60,
        burst_limit=burst,
        api_key_requests_per_window=api_key_requests_per_minute,
        api_key_window_seconds=60,
        api_key_burst_limit=api_key_burst,
    )
    return RateLimitMiddleware(app=None, config=config)