"""OIDC/OAuth2 Integration for Enterprise Identity (BP12).

Provides JWT validation, claim mapping to Principal/Role, token exchange
for capability issuance, session management, revocation, and mTLS option.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx
from jose import exceptions as jose_exceptions
from jose import jwk, jwt

from maestro.server.auth import AuthService, Principal, Role


class OIDCError(Exception):
    """Base exception for OIDC errors."""
    pass


class JWKSFetchError(OIDCError):
    """Failed to fetch JWKS from provider."""
    pass


class TokenValidationError(OIDCError):
    """JWT validation failed."""
    pass


class ClaimMappingError(OIDCError):
    """Failed to map claims to Principal/Role."""
    pass


@dataclass
class OIDCProviderConfig:
    """Configuration for an OIDC provider."""
    issuer: str
    jwks_uri: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    client_id: str = ""
    client_secret: str = ""
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    
    def __post_init__(self):
        if not self.jwks_uri:
            self.jwks_uri = urljoin(self.issuer.rstrip("/") + "/", ".well-known/jwks.json")
        if not self.authorization_endpoint:
            self.authorization_endpoint = urljoin(self.issuer.rstrip("/") + "/", "authorize")
        if not self.token_endpoint:
            self.token_endpoint = urljoin(self.issuer.rstrip("/") + "/", "token")
        if not self.userinfo_endpoint:
            self.userinfo_endpoint = urljoin(self.issuer.rstrip("/") + "/", "userinfo")


@dataclass
class OIDCTokens:
    """OIDC token response."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str = ""


@dataclass
class JWKSCache:
    """Cached JWKS with expiry."""
    keys: list[dict] = field(default_factory=list)
    fetched_at: float = 0
    ttl: int = 3600  # 1 hour default
    
    def is_expired(self) -> bool:
        return time.time() - self.fetched_at > self.ttl
    
    def get_key(self, kid: str) -> dict | None:
        for key in self.keys:
            if key.get("kid") == kid:
                return key
        return None


class OIDCClient:
    """OIDC/OAuth2 client for enterprise identity integration."""
    
    def __init__(
        self,
        config: OIDCProviderConfig,
        http_client: httpx.Client | None = None,
        jwks_cache_ttl: int = 3600,
    ):
        self.config = config
        self._http = http_client or httpx.Client(timeout=30.0)
        self._jwks_cache = JWKSCache(ttl=jwks_cache_ttl)
        self._owns_http = http_client is None
    
    def close(self) -> None:
        if self._owns_http and self._http is not None:
            self._http.close()
            self._http = None
    
    def __enter__(self) -> OIDCClient:
        return self
    
    def __exit__(self, *args) -> None:
        self.close()
    
    # --- JWKS Management ---
    
    def fetch_jwks(self) -> list[dict]:
        """Fetch JWKS from provider."""
        try:
            response = self._http.get(self.config.jwks_uri)
            response.raise_for_status()
            jwks = response.json()
            self._jwks_cache.keys = jwks.get("keys", [])
            self._jwks_cache.fetched_at = time.time()
            return self._jwks_cache.keys
        except httpx.HTTPError as e:
            raise JWKSFetchError(f"Failed to fetch JWKS: {e}")
        except (json.JSONDecodeError, KeyError) as e:
            raise JWKSFetchError(f"Invalid JWKS response: {e}")
    
    def get_signing_key(self, kid: str) -> dict:
        """Get signing key by key ID, fetching JWKS if needed."""
        if self._jwks_cache.is_expired() or not self._jwks_cache.get_key(kid):
            self.fetch_jwks()
        
        key = self._jwks_cache.get_key(kid)
        if not key:
            raise JWKSFetchError(f"No signing key found for kid: {kid}")
        return key
    
    # --- Token Validation ---
    
    def validate_id_token(
        self,
        id_token: str,
        audience: str | None = None,
        nonce: str | None = None,
    ) -> dict:
        """Validate an OIDC ID token.
        
        Returns the decoded claims if valid.
        """
        try:
            # Get header to find key ID
            header = jwt.get_unverified_header(id_token)
            kid = header.get("kid")
            if not kid:
                raise TokenValidationError("ID token missing 'kid' in header")
            
            # Get signing key
            key = self.get_signing_key(kid)
            public_key = jwk.construct(key)
            
            # Validate token
            claims = jwt.decode(
                id_token,
                public_key.to_pem().decode(),
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                audience=audience or self.config.client_id,
                issuer=self.config.issuer,
                options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
            )
            
            # Verify nonce if provided
            if nonce and claims.get("nonce") != nonce:
                raise TokenValidationError("Nonce mismatch")
            
            return claims
        
        except jose_exceptions.ExpiredSignatureError:
            raise TokenValidationError("Token has expired")
        except jose_exceptions.JWTClaimsError as e:
            raise TokenValidationError(f"Invalid claims: {e}")
        except jose_exceptions.JWTError as e:
            raise TokenValidationError(f"JWT validation failed: {e}")
    
    def validate_access_token(self, access_token: str) -> dict:
        """Validate an access token (same as ID token but no nonce check)."""
        return self.validate_id_token(access_token, audience=self.config.client_id)
    
    # --- Token Exchange ---
    
    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> OIDCTokens:
        """Exchange authorization code for tokens."""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        
        try:
            response = self._http.post(
                self.config.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_data = response.json()
            return OIDCTokens(**token_data)
        except httpx.HTTPError as e:
            raise OIDCError(f"Token exchange failed: {e}")
    
    def refresh_tokens(self, refresh_token: str) -> OIDCTokens:
        """Refresh access tokens using refresh token."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        
        try:
            response = self._http.post(
                self.config.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_data = response.json()
            return OIDCTokens(**token_data)
        except httpx.HTTPError as e:
            raise OIDCError(f"Token refresh failed: {e}")
    
    def revoke_token(self, token: str, token_type_hint: str = "access_token") -> bool:
        """Revoke a token (RFC 7009)."""
        revocation_endpoint = urljoin(self.config.issuer.rstrip("/") + "/", "revoke")
        
        data = {
            "token": token,
            "token_type_hint": token_type_hint,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        
        try:
            response = self._http.post(
                revocation_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            return response.status_code == 200
        except httpx.HTTPError:
            return False
    
    def get_userinfo(self, access_token: str) -> dict:
        """Get user info from UserInfo endpoint."""
        try:
            response = self._http.get(
                self.config.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise OIDCError(f"UserInfo request failed: {e}")
    
    # --- Authorization URL ---
    
    def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
        scopes: list[str] | None = None,
        pkce_challenge: str | None = None,
        pkce_challenge_method: str = "S256",
    ) -> str:
        """Generate authorization URL for redirect."""
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes or self.config.scopes),
            "state": state,
            "nonce": nonce,
        }
        
        if pkce_challenge:
            params["code_challenge"] = pkce_challenge
            params["code_challenge_method"] = pkce_challenge_method
        
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self.config.authorization_endpoint}?{query}"


class OIDCAuthService:
    """AuthService wrapper that integrates OIDC with MAESTRO's Principal/Role system."""
    
    def __init__(
        self,
        oidc_client: OIDCClient,
        claim_mapping: dict[str, str] | None = None,
        role_mapping: dict[str, Role] | None = None,
        default_role: Role = Role.VIEWER,
    ):
        self.oidc = oidc_client
        self.claim_mapping = claim_mapping or {
            "sub": "subject",
            "email": "email",
            "preferred_username": "username",
            "groups": "groups",
        }
        self.role_mapping = role_mapping or {}
        self.default_role = default_role
        self._auth_service = AuthService(key=b"oidc-session-key")  # Separate key for sessions
    
    def authenticate_id_token(self, id_token: str, nonce: str | None = None) -> Principal:
        """Validate ID token and create Principal."""
        claims = self.oidc.validate_id_token(id_token, nonce=nonce)
        return self._map_claims_to_principal(claims)
    
    def authenticate_access_token(self, access_token: str) -> Principal:
        """Validate access token and create Principal."""
        claims = self.oidc.validate_access_token(access_token)
        return self._map_claims_to_principal(claims)
    
    def _map_claims_to_principal(self, claims: dict) -> Principal:
        """Map OIDC claims to MAESTRO Principal."""
        subject = claims.get(self.claim_mapping.get("sub", "sub"), claims.get("sub", "unknown"))
        email = claims.get(self.claim_mapping.get("email", "email"))
        username = claims.get(self.claim_mapping.get("preferred_username", "preferred_username"))
        groups = claims.get(self.claim_mapping.get("groups", "groups"), [])
        
        # Determine role from groups
        role = self.default_role
        for group in groups:
            if group in self.role_mapping:
                role = self.role_mapping[group]
                break
        
        # Check for role claim directly
        if "role" in claims and claims["role"] in self.role_mapping:
            role = self.role_mapping[claims["role"]]
        
        return Principal(
            subject=subject,
            tenant=claims.get("tenant", "default"),
            role=role,
            email=email,
            username=username,
            groups=groups,
        )
    
    def issue_session_token(self, principal: Principal, ttl_seconds: int = 3600) -> str:
        """Issue a MAESTRO session token for the authenticated principal."""
        return self._auth_service.issue(
            subject=principal.subject,
            tenant=principal.tenant,
            role=principal.role,
            ttl_seconds=ttl_seconds,
        )


# --- Configuration Helpers ---

def load_oidc_config_from_env(prefix: str = "MAESTRO_OIDC") -> OIDCProviderConfig:
    """Load OIDC configuration from environment variables.
    
    Expected variables:
    - {prefix}_ISSUER
    - {prefix}_CLIENT_ID
    - {prefix}_CLIENT_SECRET
    - {prefix}_JWKS_URI (optional)
    - {prefix}_SCOPES (optional, comma-separated)
    """
    import os
    
    issuer = os.environ.get(f"{prefix}_ISSUER")
    if not issuer:
        raise ConfigurationError(f"{prefix}_ISSUER not set")
    
    return OIDCProviderConfig(
        issuer=issuer,
        jwks_uri=os.environ.get(f"{prefix}_JWKS_URI"),
        client_id=os.environ.get(f"{prefix}_CLIENT_ID", ""),
        client_secret=os.environ.get(f"{prefix}_CLIENT_SECRET", ""),
        scopes=os.environ.get(f"{prefix}_SCOPES", "openid,profile,email").split(","),
    )


def create_oidc_auth_service(
    config: OIDCProviderConfig | None = None,
    role_mapping: dict[str, Role] | None = None,
) -> OIDCAuthService:
    """Create an OIDCAuthService with sensible defaults."""
    if config is None:
        config = load_oidc_config_from_env()
    
    if role_mapping is None:
        role_mapping = {
            "maestro-admin": Role.ADMIN,
            "maestro-operator": Role.OPERATOR,
            "maestro-viewer": Role.VIEWER,
        }
    
    oidc_client = OIDCClient(config)
    return OIDCAuthService(oidc_client, role_mapping=role_mapping)


# Re-export ConfigurationError for consistency
ConfigurationError = OIDCError