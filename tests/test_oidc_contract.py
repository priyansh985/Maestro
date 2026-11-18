"""OIDC contract tests.

The local cases map verified claims to ``Principal``/``Role``. The mock-provider
cases exercise the full JWKS/JWT path against an in-process JWKS endpoint built
with ``httpx.MockTransport``: no live identity provider is contacted.

A separate, environment-gated smoke case runs discovery + JWKS fetch against a
real provider when ``MAESTRO_OIDC_ISSUER`` is set (the Keycloak CI lane in
``.github/workflows/oidc-integration.yml``). That lane is defined but has NOT
been executed as part of authoring this suite; see the workflow header.
"""
from __future__ import annotations

import base64
import os
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from maestro.server.auth import Role
from maestro.server.oidc import (
    ClaimMappingError,
    JWKSFetchError,
    OIDCAuthService,
    OIDCClient,
    OIDCProviderConfig,
    TokenValidationError,
)

ISSUER = "https://issuer.example/realms/maestro"
CLIENT_ID = "maestro-client"
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"


def _b64u(value: int) -> str:
    """base64url-encode an unsigned RSA component for a JWK."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _new_rsa_key(kid: str) -> tuple[str, dict[str, Any]]:
    """Return (PEM private key, public JWK) for a fresh RS256 signing key."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    numbers = private.public_key().public_numbers()
    jwk_dict: dict[str, Any] = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64u(numbers.n),
        "e": _b64u(numbers.e),
    }
    return pem, jwk_dict


class MockProvider:
    """In-process JWKS endpoint with request counting and key rotation."""

    def __init__(self) -> None:
        self.keys: list[dict[str, Any]] = []
        self.private_pems: dict[str, str] = {}
        self.requests = 0

    def add_key(self, kid: str) -> str:
        pem, jwk_dict = _new_rsa_key(kid)
        self.private_pems[kid] = pem
        self.keys.append(jwk_dict)
        return pem

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        assert str(request.url) == JWKS_URI
        return httpx.Response(200, json={"keys": self.keys})

    def sign(self, kid: str, **claims: Any) -> str:
        return jwt.encode(
            claims, self.private_pems[kid], algorithm="RS256", headers={"kid": kid}
        )


@pytest.fixture
def provider() -> Iterator[tuple[MockProvider, OIDCClient]]:
    mock = MockProvider()
    mock.add_key("k1")
    with httpx.Client(transport=httpx.MockTransport(mock.handler)) as http:
        config = OIDCProviderConfig(issuer=ISSUER, jwks_uri=JWKS_URI, client_id=CLIENT_ID)
        yield mock, OIDCClient(config, http)


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-7",
        "tenant": "acme",
        "iat": now - 10,
        "exp": now + 300,
        "groups": ["maestro-admin"],
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> Iterator[OIDCAuthService]:
    monkeypatch.setenv("MAESTRO_SIGNING_KEY", "test-oidc-contract-key")
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    ) as http:
        yield OIDCAuthService(
            OIDCClient(OIDCProviderConfig(issuer="https://identity.invalid"), http),
            role_mapping={"operators": Role.OPERATOR},
        )


def test_verified_claims_map_to_the_actual_principal_schema(service):
    principal = service._map_claims_to_principal(
        {"sub": "person-1", "tenant": "tenant-a", "groups": ["operators"], "email": "p@example.invalid"})
    assert principal.subject == "person-1"
    assert principal.tenant == "tenant-a"
    assert principal.role == Role.OPERATOR
    assert principal.kind == "user"


@pytest.mark.parametrize("claims", [{"tenant": "a"}, {"sub": "person"}, {"sub": "", "tenant": "a"}])
def test_missing_subject_or_tenant_does_not_fall_into_default_authority(service, claims):
    with pytest.raises(ClaimMappingError):
        service._map_claims_to_principal(claims)


# --- Mock JWKS provider: caching, rollover, and the full validation path ---


def test_jwks_is_cached_while_fresh(provider: tuple[MockProvider, OIDCClient]) -> None:
    mock, client = provider
    client.get_signing_key("k1")
    client.get_signing_key("k1")
    assert mock.requests == 1, "a fresh cached JWKS must not be re-fetched per lookup"


def test_jwks_refreshes_after_ttl_expires(provider: tuple[MockProvider, OIDCClient]) -> None:
    mock, client = provider
    client.get_signing_key("k1")
    assert mock.requests == 1
    client._jwks_cache.fetched_at = time.time() - 7200  # force expiry deterministically
    client.get_signing_key("k1")
    assert mock.requests == 2, "an expired cache must trigger a JWKS refresh"


def test_unknown_kid_triggers_refresh_then_key_rollover_succeeds(
    provider: tuple[MockProvider, OIDCClient]
) -> None:
    mock, client = provider
    old_token = mock.sign("k1", **_claims())
    assert client.validate_id_token(old_token)["sub"] == "user-7"
    assert mock.requests == 1

    mock.add_key("k2")
    new_token = mock.sign("k2", **_claims(sub="user-8"))
    assert client.validate_id_token(new_token)["sub"] == "user-8"
    assert mock.requests == 2, "a kid miss must refresh JWKS to pick up rotated keys"


def test_valid_token_maps_to_principal_and_group_role(
    provider: tuple[MockProvider, OIDCClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MAESTRO_SIGNING_KEY", "test-oidc-contract-key")
    mock, client = provider
    auth = OIDCAuthService(client, role_mapping={"maestro-admin": Role.ADMIN})
    principal = auth.authenticate_id_token(mock.sign("k1", **_claims()))
    assert (principal.subject, principal.tenant, principal.role, principal.kind) == (
        "user-7",
        "acme",
        Role.ADMIN,
        "user",
    )


def test_unmapped_groups_fall_back_to_default_role(
    provider: tuple[MockProvider, OIDCClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MAESTRO_SIGNING_KEY", "test-oidc-contract-key")
    mock, client = provider
    auth = OIDCAuthService(client, role_mapping={}, default_role=Role.VIEWER)
    principal = auth.authenticate_id_token(mock.sign("k1", **_claims(groups=["unknown-group"])))
    assert principal.role == Role.VIEWER


def test_expired_token_is_rejected(provider: tuple[MockProvider, OIDCClient]) -> None:
    mock, client = provider
    token = mock.sign("k1", **_claims(exp=int(time.time()) - 60))
    with pytest.raises(TokenValidationError, match="expired"):
        client.validate_id_token(token)


def test_unpublished_kid_is_rejected(provider: tuple[MockProvider, OIDCClient]) -> None:
    _mock, client = provider
    rogue_pem, _ = _new_rsa_key("rogue")
    token = jwt.encode(
        _claims(), rogue_pem, algorithm="RS256", headers={"kid": "not-published"}
    )
    with pytest.raises((JWKSFetchError, TokenValidationError)):
        client.validate_id_token(token)


def test_issuer_mismatch_is_rejected(provider: tuple[MockProvider, OIDCClient]) -> None:
    mock, client = provider
    token = mock.sign("k1", **_claims(iss="https://evil.example/realms/maestro"))
    with pytest.raises(TokenValidationError, match="Invalid claims"):
        client.validate_id_token(token)


def test_audience_mismatch_is_rejected(provider: tuple[MockProvider, OIDCClient]) -> None:
    mock, client = provider
    token = mock.sign("k1", **_claims(aud="another-client"))
    with pytest.raises(TokenValidationError):
        client.validate_id_token(token)


# --- Env-gated real-provider smoke (Keycloak CI lane; skipped locally) ---


@pytest.mark.skipif(
    not os.environ.get("MAESTRO_OIDC_ISSUER"),
    reason="requires a live OIDC provider; set MAESTRO_OIDC_ISSUER (Keycloak CI lane)",
)
def test_live_provider_discovery_and_jwks_fetch() -> None:
    """Discovery + JWKS against a real provider. No token minting here yet."""
    issuer = os.environ["MAESTRO_OIDC_ISSUER"].rstrip("/")
    with httpx.Client(timeout=30.0) as http:
        discovery = http.get(f"{issuer}/.well-known/openid-configuration")
        discovery.raise_for_status()
        jwks_uri = discovery.json()["jwks_uri"]
        jwks = http.get(jwks_uri)
        jwks.raise_for_status()
        assert jwks.json()["keys"], "provider published no signing keys"

    config = OIDCProviderConfig(
        issuer=issuer,
        jwks_uri=jwks_uri,
        client_id=os.environ.get("MAESTRO_OIDC_CLIENT_ID", ""),
    )
    client = OIDCClient(config)
    try:
        assert client.fetch_jwks(), "OIDCClient could not fetch the provider JWKS"
    finally:
        client.close()
