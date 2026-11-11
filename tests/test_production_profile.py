"""A research implementation must never silently boot as a production service."""
import pytest

from maestro.config import load_config
from maestro.server.app import create_app


@pytest.mark.parametrize("unsafe_flags", [False, True])
def test_production_profile_is_unavailable_until_enterprise_integrations_exist(monkeypatch, unsafe_flags):
    monkeypatch.setenv("MAESTRO_PROFILE", "production")
    config = load_config()
    config.mitigation.zero_trust_api = not unsafe_flags
    with pytest.raises(RuntimeError, match="production.*unavailable"):
        create_app(config)


def test_unknown_profile_cannot_fall_back_to_research(monkeypatch):
    monkeypatch.setenv("MAESTRO_PROFILE", "prodution")
    with pytest.raises(ValueError, match="profile"):
        create_app()


def test_research_environment_cannot_override_production_config(monkeypatch):
    monkeypatch.setenv("MAESTRO_PROFILE", "research")
    config = load_config()
    config.deployment = {"profile": "production"}
    with pytest.raises(RuntimeError, match="production.*unavailable"):
        create_app(config)
