"""Local identity mapping contract; no live identity provider is exercised."""
import httpx
import pytest

from maestro.server.auth import Role
from maestro.server.oidc import ClaimMappingError, OIDCAuthService, OIDCClient, OIDCProviderConfig


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setenv("MAESTRO_SIGNING_KEY", "test-oidc-contract-key")
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))) as http:
        yield OIDCAuthService(OIDCClient(OIDCProviderConfig(issuer="https://identity.invalid"), http),
                              role_mapping={"operators": Role.OPERATOR})


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
