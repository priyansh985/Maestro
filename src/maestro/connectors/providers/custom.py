"""User-registered external providers.

Lets a user plug in *any* OpenAI-compatible endpoint by supplying a base URL,
an API key, and (optionally) how that key should be sent — either as an
``Authorization: Bearer`` header (the default) or a custom header such as
``x-api-key``. This satisfies the "register external providers by supplying a
custom API URL + authentication key" requirement without new code.
"""
from __future__ import annotations

from typing import Any

from .openai import OpenAIConnector


class CustomConnector(OpenAIConnector):
    """Generic OpenAI-compatible connector with configurable authentication.

    Parameters
    ----------
    auth_header:
        Header name the key is sent under. ``"authorization"`` (default) uses
        the Bearer scheme; any other value sends the raw key as that header
        (e.g. ``"x-api-key"``).
    auth_prefix:
        Prefix prepended to the key for ``authorization`` (default
        ``"Bearer "``). Ignored for non-authorization headers.
    """

    provider = "custom"

    def __init__(
        self,
        name: str,
        model: str,
        *,
        base_url: str,
        api_key: str | None = None,
        auth_header: str = "authorization",
        auth_prefix: str = "Bearer ",
        **kw: Any,
    ):
        super().__init__(name, model, base_url=base_url, api_key=api_key, **kw)
        self.auth_header = auth_header.lower()
        self.auth_prefix = auth_prefix

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.api_key:
            if self.auth_header == "authorization":
                headers["authorization"] = f"{self.auth_prefix}{self.api_key}"
            else:
                headers[self.auth_header] = self.api_key
        return headers

    def describe(self) -> dict[str, Any]:
        d = super().describe()
        d["auth_header"] = self.auth_header
        return d
