"""Tests for ConnectorRegistry and YAML config loading."""
from __future__ import annotations

import pytest

from maestro.connectors import (
    ConnectorRegistry,
    OpenAIConnector,
    StubConnector,
    build_registry,
    default_registry,
)


def test_register_and_resolve_default():
    reg = ConnectorRegistry()
    reg.register(StubConnector("a"))
    reg.register(StubConnector("b"))
    assert reg.default_name == "a"  # first registered becomes default
    assert reg.resolve().name == "a"
    assert reg.resolve("b").name == "b"


def test_register_duplicate_raises():
    reg = ConnectorRegistry()
    reg.register(StubConnector("a"))
    with pytest.raises(ValueError):
        reg.register(StubConnector("a"))


def test_enable_disable():
    reg = ConnectorRegistry()
    reg.register(StubConnector("a"))
    reg.disable("a")
    assert reg.get("a").enabled is False
    reg.enable("a")
    assert reg.get("a").enabled is True


def test_remove_reassigns_default():
    reg = ConnectorRegistry()
    reg.register(StubConnector("a"))
    reg.register(StubConnector("b"))
    reg.remove("a")
    assert "a" not in reg.names()
    assert reg.default_name == "b"


def test_register_provider_builds_connector():
    reg = ConnectorRegistry()
    c = reg.register_provider(name="oai", provider="openai", model="gpt-4o-mini",
                              api_key="k")
    assert isinstance(c, OpenAIConnector)
    assert reg.get("oai").model == "gpt-4o-mini"


def test_register_provider_unknown_raises():
    reg = ConnectorRegistry()
    with pytest.raises(ValueError):
        reg.register_provider(name="x", provider="does-not-exist", model="m")


def test_set_default_unknown_raises():
    reg = ConnectorRegistry()
    reg.register(StubConnector("a"))
    with pytest.raises(KeyError):
        reg.set_default("nope")


def test_resolve_empty_raises():
    with pytest.raises(KeyError):
        ConnectorRegistry().resolve()


def test_list_descriptions_marks_default():
    reg = ConnectorRegistry()
    reg.register(StubConnector("a"))
    reg.register(StubConnector("b"))
    descs = {d["name"]: d for d in reg.list_descriptions()}
    assert descs["a"]["default"] is True
    assert descs["b"]["default"] is False


def test_default_registry_offline_has_stub_default():
    reg = default_registry()
    assert reg.default_name == "stub"
    assert reg.get("stub").enabled is True
    assert reg.get("ollama").enabled is False  # local, off until a server exists


def test_build_registry_from_yaml(tmp_path):
    yaml = tmp_path / "connectors.yaml"
    yaml.write_text(
        "default: stub\n"
        "connectors:\n"
        "  - name: stub\n    provider: stub\n    model: stub-1\n"
        "  - name: needs_key\n    provider: openai\n    model: gpt-4o-mini\n"
        "    api_key_env: DEFINITELY_NOT_SET_ENV\n",
        encoding="utf-8",
    )
    reg = build_registry(yaml)
    assert reg.default_name == "stub"
    # openai entry with no key present is registered but disabled
    assert reg.get("needs_key").enabled is False


def test_build_registry_custom_provider(tmp_path):
    yaml = tmp_path / "connectors.yaml"
    yaml.write_text(
        "connectors:\n"
        "  - name: mine\n    provider: custom\n    model: m\n"
        "    base_url: https://api.example.com/v1\n    api_key: inline-secret\n"
        "    auth_header: x-api-key\n",
        encoding="utf-8",
    )
    reg = build_registry(yaml)
    c = reg.get("mine")
    assert c.enabled is True  # inline key present
    assert c.describe()["auth_header"] == "x-api-key"
