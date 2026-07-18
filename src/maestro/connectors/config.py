"""Build a :class:`ConnectorRegistry` from YAML + environment.

``configs/connectors.yaml`` lists connectors declaratively; API keys are
referenced by env-var name (never stored in the file). The offline default
registry always includes the deterministic stub so the system runs with no
configuration and no network.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import httpx
from omegaconf import OmegaConf

from .registry import ConnectorRegistry

if TYPE_CHECKING:
    from omegaconf import DictConfig

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_CONNECTORS_YAML = _REPO_ROOT / "configs" / "connectors.yaml"


def _resolve_api_key(entry: dict[str, Any]) -> str | None:
    """Prefer an inline ``api_key``; else read ``api_key_env`` from the env."""
    if entry.get("api_key"):
        return str(entry["api_key"])
    env_name = entry.get("api_key_env")
    if env_name:
        return os.environ.get(str(env_name))
    return None


def build_registry(
    path: str | os.PathLike[str] | None = None,
    *,
    http_client: httpx.Client | None = None,
) -> ConnectorRegistry:
    """Construct a registry from a YAML config file.

    Entries whose provider needs a key but has none available are registered
    **disabled** (so they appear in the dashboard but never fail a live call
    until configured).
    """
    cfg_path = Path(path) if path is not None else _DEFAULT_CONNECTORS_YAML
    registry = ConnectorRegistry()
    if not cfg_path.exists():
        return default_registry(http_client=http_client)

    cfg = cast("DictConfig", OmegaConf.load(cfg_path))
    entries = OmegaConf.to_container(cfg.get("connectors", []), resolve=True) or []
    default_name = cfg.get("default")

    for raw in entries:
        entry: dict[str, Any] = dict(raw)  # type: ignore[arg-type]
        provider = str(entry["provider"])
        name = str(entry.get("name", provider))
        api_key = _resolve_api_key(entry)
        needs_key = provider in ("openai", "anthropic", "custom")
        enabled = bool(entry.get("enabled", True)) and (api_key is not None or not needs_key)
        extra = {
            k: v
            for k, v in entry.items()
            if k not in {"provider", "name", "model", "base_url", "api_key",
                         "api_key_env", "enabled", "default"}
        }
        registry.register_provider(
            name=name,
            provider=provider,
            model=str(entry.get("model", "")),
            base_url=entry.get("base_url"),
            api_key=api_key,
            default=bool(entry.get("default", False)),
            http_client=http_client,
            enabled=enabled,
            **extra,
        )

    # Never hand back a registry with no connectors (a present-but-empty
    # config would otherwise leave callers with no default and no offline
    # stub). Fall back to the always-offline default registry.
    if not registry.names():
        return default_registry(http_client=http_client)

    if default_name and default_name in registry.names():
        registry.set_default(str(default_name))
    return registry


def default_registry(*, http_client: httpx.Client | None = None) -> ConnectorRegistry:
    """A ready-to-use registry when no YAML config is present.

    Always offline-capable: the stub is the default; a local Ollama connector
    is registered (disabled by default until a server is available); cloud
    providers are added and enabled only when their API key env var is set.
    """
    registry = ConnectorRegistry()
    registry.register_provider(
        name="stub", provider="stub", model="stub-1", default=True,
    )
    registry.register_provider(
        name="ollama", provider="ollama", model="llama3",
        http_client=http_client, enabled=False,
    )
    if os.environ.get("OPENAI_API_KEY"):
        registry.register_provider(
            name="openai", provider="openai", model="gpt-4o-mini",
            api_key=os.environ["OPENAI_API_KEY"], http_client=http_client,
        )
    if os.environ.get("ANTHROPIC_API_KEY"):
        registry.register_provider(
            name="anthropic", provider="anthropic", model="claude-opus-4-8",
            api_key=os.environ["ANTHROPIC_API_KEY"], http_client=http_client,
        )
    return registry
