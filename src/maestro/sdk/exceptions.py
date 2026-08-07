"""Typed exceptions for the MAESTRO SDK."""
from __future__ import annotations

from typing import Any


class MaestroError(Exception):
    """Base exception for all MAESTRO SDK errors."""
    
    def __init__(self, message: str, *, request_id: str | None = None, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        self.request_id = request_id
        self.status_code = status_code


class NotFound(MaestroError):
    """Resource not found (404)."""
    pass


class Unauthorized(MaestroError):
    """Authentication failed or token expired (401/403)."""
    pass


class ValidationError(MaestroError):
    """Request validation failed (400/422)."""
    
    def __init__(self, message: str, *, errors: list[dict[str, Any]] | None = None, **kwargs):
        super().__init__(message, **kwargs)
        self.errors = errors or []


class Conflict(MaestroError):
    """Resource conflict (409)."""
    pass


class RateLimited(MaestroError):
    """Rate limit exceeded (429)."""
    
    def __init__(self, message: str, *, retry_after: float | None = None, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ServerError(MaestroError):
    """Server-side error (5xx)."""
    pass


class ConfigurationError(MaestroError):
    """SDK configuration error (missing auth, invalid config, etc.)."""
    pass


class TimeoutError(MaestroError):
    """Request timeout."""
    pass