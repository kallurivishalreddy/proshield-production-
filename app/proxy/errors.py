"""Proxy domain errors.

Reference: docs/PHASE 3/SECURE_FOUNDATION.md (Section 30
safe errors), docs/PHASE 4/PHASE 4-08.

The proxy error catalogue is small, on purpose:

* :class:`ProxyError` - base.
* :class:`ProxyUnauthorizedError` - the session token
  is missing / malformed / expired (``http_status=401``).
* :class:`ProxyRateLimitedError` - the per-subject
  budget is exhausted (``http_status=429``).
* :class:`InvalidProxyRequestError` - the request is
  malformed (``http_status=400``).
"""
from __future__ import annotations

from ..domain.errors import (
    AuthenticationRequiredError,
    AuthorizationError,
    DomainError,
    ValidationError,
)


class ProxyError(DomainError):
    """Base class for all proxy domain errors."""


class ProxyUnauthorizedError(AuthenticationRequiredError):
    """The session token is missing, malformed, or expired."""


class ProxyRateLimitedError(DomainError):
    """The per-subject rate limit was exhausted."""

    code = "rate_limited"
    http_status = 429


class InvalidProxyRequestError(ValidationError):
    """The proxy request failed validation."""


class ProxyInternalError(ProxyError):
    """An unexpected internal failure escaped the fail-safe boundary.

    ``code="internal_error"`` and ``http_status=500`` so the wire
    never labels an internal failure as an authentication failure
    (STRIX F-7 / N-3).
    """

    code = "internal_error"
    http_status = 500


__all__ = [
    "InvalidProxyRequestError",
    "ProxyError",
    "ProxyInternalError",
    "ProxyRateLimitedError",
    "ProxyUnauthorizedError",
]