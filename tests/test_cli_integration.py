"""CLI integration tests (BP11) — CLI → live control plane.

Spins up the in-process FastAPI app and drives the CLI entry point
(``maestro.cli.main``) with patched ``sys.argv``-like args. The CLI must
go through ``ControlPlaneClient`` (same surface as the dashboards); these
tests prove it does, and that output formatting + auth surface work.
"""
from __future__ import annotations

import json
import sys

import pytest
from fastapi.testclient import TestClient

from maestro.server.app import create_app
from maestro.server.auth import AuthService, Role, configure_auth


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, str]:
    """Return (TestClient, bearer_token) with ADMIN principal."""
    app = create_app()
    svc = AuthService(key=b"test-cli-key")
    configure_auth(enforce=True, service=svc, control_plane_tenant="default")
    token = svc.issue("svc:cli-test", tenant="default", role=Role.ADMIN, ttl_seconds=3600)
    client = TestClient(app)
    # Prime the server: each TestClient request carries this token by default
    # via the env var the CLI resolves. The CLI under test reads MAESTRO_API_KEY.
    monkeypatch.setenv("MAESTRO_API_KEY", token)
    # Point CLI at the TestClient server via httpx MockTransport patching:
    # instead of real HTTP, we monkeypatch ControlPlaneClient to use ASGITransport.
    # The CLI builds its own ControlPlaneClient from env, so we patch its factory
    # to inject the ASGI transport. Easiest: monkeypatch httpx.Client creation
    # inside the SDK to route to the app.
    from maestro.sdk import http_client as hc

    orig_init = hc.ControlPlaneClient.__init__

    def patched_init(self, base_url, api_key=None, timeout=30.0, max_retries=3, retry_backoff=1.0):  # type: ignore[no-untyped-def]
        orig_init(self, base_url=base_url, api_key=api_key, timeout=timeout, max_retries=max_retries, retry_backoff=retry_backoff)
        # Force the internal clients to route to the in-process app
        from fastapi.testclient import TestClient

        self._sync_client = TestClient(app, headers={"Authorization": f"Bearer {token}"} if token else {})
        import httpx as _httpx

        self._async_client = _httpx.AsyncClient(
            transport=_httpx.ASGITransport(app=app),  # type: ignore[arg-type]
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"} if token else {},
        )

    monkeypatch.setattr(hc.ControlPlaneClient, "__init__", patched_init)
    # Also set control plane URL so CLI doesn't try localhost
    monkeypatch.setenv("MAESTRO_CONTROL_PLANE", "http://test")
    return client, token


def _run_cli(args: list[str], monkeypatch: pytest.MonkeyPatch, capsys) -> tuple[int, str, str]:
    from maestro.cli import main as cli_main

    monkeypatch.setattr(sys, "argv", ["maestro", *args])
    # cli_main() parses sys.argv internally; we also call _build_parser via main
    rc = cli_main()
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_cli_agent_list_json(cli_env, monkeypatch, capsys) -> None:
    _client, _token = cli_env
    rc, out, err = _run_cli(["agent", "list", "--output", "json"], monkeypatch, capsys)
    assert rc == 0
    data = json.loads(out)
    assert "agents" in data or isinstance(data, list)


def test_cli_agent_create_and_delete(cli_env, monkeypatch, capsys) -> None:
    _client, _token = cli_env
    rc, out, _err = _run_cli(["agent", "create", "--type", "generic", "--output", "json"], monkeypatch, capsys)
    assert rc == 0
    created = json.loads(out)
    agent_id = created.get("agent_id") or created.get("agentId") or created.get("id")
    assert agent_id

    # Verify it shows up in list
    rc, out, _err = _run_cli(["agent", "list", "--output", "json"], monkeypatch, capsys)
    assert rc == 0
    listing = json.loads(out)
    agents = listing.get("agents", listing) if isinstance(listing, dict) else listing
    assert any(a.get("agent_id") == agent_id for a in agents)

    # Delete
    rc, out, _err = _run_cli(["agent", "delete", agent_id, "--output", "json"], monkeypatch, capsys)
    assert rc == 0


def test_cli_ledger_verify_and_export(cli_env, monkeypatch, capsys) -> None:
    _client, _token = cli_env
    rc, out, _err = _run_cli(["ledger", "verify", "--output", "json"], monkeypatch, capsys)
    assert rc == 0
    verify = json.loads(out)
    assert "intact" in verify

    rc, out, _err = _run_cli(["ledger", "export", "--output", "json"], monkeypatch, capsys)
    assert rc == 0
    exported = json.loads(out)
    assert "events" in exported and "count" in exported


def test_cli_policy_validate(cli_env, monkeypatch, capsys, tmp_path) -> None:
    _client, _token = cli_env
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\nallowed_intents: [noop, throttle_telemetry]\n", encoding="utf-8")
    rc, out, _err = _run_cli(["policy", "validate", str(policy), "--output", "json"], monkeypatch, capsys)
    assert rc == 0
    result = json.loads(out)
    assert result["valid"] is True


def test_cli_memory_inspect(cli_env, monkeypatch, capsys) -> None:
    _client, _token = cli_env
    rc, out, _err = _run_cli(["memory", "inspect", "--limit", "10", "--output", "json"], monkeypatch, capsys)
    assert rc == 0
    data = json.loads(out)
    # control_api returns {scope, records, count}
    assert "records" in data or "count" in data


def test_cli_tenant_create_and_isolate(cli_env, monkeypatch, capsys) -> None:
    import time

    _client, _token = cli_env
    tid = f"cli-tenant-{int(time.time())}"
    rc, out, _err = _run_cli(["tenant", "create", tid, "--output", "json"], monkeypatch, capsys)
    assert rc == 0
    created = json.loads(out)
    assert created["tenant_id"] == tid

    rc, out, _err = _run_cli(["tenant", "isolate", tid, "--output", "json"], monkeypatch, capsys)
    assert rc == 0
    iso = json.loads(out)
    assert iso["isolated"] is True


def test_cli_output_table_mode(cli_env, monkeypatch, capsys) -> None:
    _client, _token = cli_env
    rc, out, _err = _run_cli(["agent", "list", "--output", "table"], monkeypatch, capsys)
    assert rc == 0
    # Table mode prints a header row with " | "
    assert " | " in out or "agent_id" in out.lower()
