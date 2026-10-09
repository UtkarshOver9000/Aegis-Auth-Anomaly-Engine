"""
Per-IP token-bucket rate limits for the public, keyless endpoints.

Buckets live in process memory, so on a serverless platform each instance keeps its own
count. That stops one client hammering an instance; a gateway or CDN limit is still the
right place for a hard global cap.
"""

from __future__ import annotations

import math
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# path prefix -> (bucket size, refill per second). First match wins.
LIMITS = (
    ("/v1/demo/", (20, 20 / 60)),  # a full sign-in story per call: 20 a minute
    ("/v1/auth/", (60, 1.0)),
    ("/v1/", (120, 2.0)),  # read-only intel endpoints
)
EXEMPT = ("/v1/health",)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limits=LIMITS):
        super().__init__(app)
        self.limits = limits
        self.buckets: dict[tuple[str, str], tuple[float, float]] = {}  # (ip, prefix) -> (tokens, last time)
        self.last_prune = time.monotonic()

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        rule = next(((p, r) for p, r in self.limits if path.startswith(p)), None)
        if rule is None or path.startswith(EXEMPT):
            return await call_next(request)
        prefix, (size, refill) = rule
        now = time.monotonic()
        key = (client_ip(request), prefix)
        tokens, last = self.buckets.get(key, (float(size), now))
        tokens = min(size, tokens + (now - last) * refill)
        if tokens < 1:
            wait = math.ceil((1 - tokens) / refill)
            return JSONResponse(
                {"detail": f"Too many requests. Try again in {wait} s."}, status_code=429,
                headers={"Retry-After": str(wait)},
            )
        self.buckets[key] = (tokens - 1, now)
        if now - self.last_prune > 600:  # forget idle clients
            self.buckets = {k: v for k, v in self.buckets.items() if now - v[1] < 600}
            self.last_prune = now
        return await call_next(request)
