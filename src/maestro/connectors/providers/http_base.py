"""Shared HTTP plumbing for network-backed connectors.

Concrete providers (OpenAI, Anthropic, Ollama, custom) subclass
:class:`HttpConnector`. The single ``_post_json`` helper centralizes error
mapping so every provider raises the same :class:`ConnectorError` hierarchy,
and the injectable ``http_client`` makes the whole stack testable offline with
``httpx.MockTransport``.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Any
from urllib.parse import urlparse

import httpx

from ..base import (
    AuthenticationError,
    ConnectorError,
    InvalidRequestError,
    ModelConnector,
    ProviderUnavailableError,
    RateLimitError,
)

DEFAULT_TIMEOUT_S = 60.0

#: Set to ``1`` to disable the SSRF guard (e.g. a lab pointing at link-local).
ALLOW_UNSAFE_HOSTS_ENV = "MAESTRO_ALLOW_UNSAFE_HOSTS"


def assert_safe_base_url(url: str) -> None:
    """Reject a ``base_url`` whose host is an IP literal in a dangerous range.

    Blocks link-local (incl. cloud metadata ``169.254.169.254``), multicast,
    reserved, and unspecified addresses — the classic SSRF-to-metadata targets
    a registered *custom* provider could otherwise be pointed at. Loopback and
    private (LAN) addresses are allowed so legitimate local model servers
    (Ollama, self-hosted engines) keep working. Hostname-based rebinding is a
    documented residual risk; gate connector registration with auth in
    untrusted deployments. Override with ``MAESTRO_ALLOW_UNSAFE_HOSTS=1``.
    """
    if os.environ.get(ALLOW_UNSAFE_HOSTS_ENV):
        return
    host = urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # hostname (not an IP literal) — not resolved here
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise ValueError(
            f"refusing base_url with blocked host '{host}' "
            f"(link-local/metadata/multicast/reserved); set "
            f"{ALLOW_UNSAFE_HOSTS_ENV}=1 to override"
        )


class HttpConnector(ModelConnector):
    """Base for connectors that speak HTTP+JSON to a provider endpoint."""

    def __init__(
        self,
        name: str,
        model: str,
        *,
        base_url: str,
        api_key: str | None = None,
        enabled: bool = True,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        http_client: httpx.Client | None = None,
    ):
        super().__init__(name, model, enabled=enabled)
        assert_safe_base_url(base_url)  # SSRF guard (raises ValueError -> 400 via API)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_s = timeout_s
        # An injected client is owned by the caller; a lazily-created one is
        # owned here. Kept separate so ``close()`` never shuts a shared client.
        self._client = http_client
        self._owns_client = http_client is None

    # -- client lifecycle -------------------------------------------------- #
    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout_s)
        return self._client

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    # -- request helper ---------------------------------------------------- #
    def _headers(self) -> dict[str, str]:
        """Auth/content headers. Subclasses override for provider specifics."""
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        return headers

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST JSON to ``base_url + path`` and map failures to ConnectorError."""
        url = f"{self.base_url}{path}"
        try:
            resp = self.client.post(url, json=payload, headers=self._headers())
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ProviderUnavailableError(
                f"cannot reach {self.provider} at {url}: {exc}", provider=self.provider
            ) from exc
        except httpx.HTTPError as exc:  # other transport-level failures
            raise ProviderUnavailableError(
                f"{self.provider} transport error: {exc}", provider=self.provider
            ) from exc

        code = resp.status_code
        if code in (401, 403):
            raise AuthenticationError(
                f"{self.provider} auth failed ({code}): {_safe_body(resp)}",
                provider=self.provider,
                status_code=code,
            )
        if code == 429:
            raise RateLimitError(
                f"{self.provider} rate limited (429)",
                provider=self.provider,
                status_code=code,
            )
        if code >= 500:
            raise ProviderUnavailableError(
                f"{self.provider} server error ({code})",
                provider=self.provider,
                status_code=code,
            )
        if code >= 400:
            raise InvalidRequestError(
                f"{self.provider} rejected request ({code}): {_safe_body(resp)}",
                provider=self.provider,
                status_code=code,
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectorError(
                f"{self.provider} returned non-JSON response", provider=self.provider
            ) from exc

    def describe(self) -> dict[str, Any]:
        d = super().describe()
        d["base_url"] = self.base_url
        d["authenticated"] = bool(self.api_key)
        return d


def _safe_body(resp: httpx.Response, limit: int = 300) -> str:
    """Truncated response body for error messages (never raises)."""
    try:
        return resp.text[:limit]
    except Exception:  # noqa: BLE001 - error path must not raise
        return "<unreadable body>"
