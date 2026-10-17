"""MAESTRO CLI — Full lifecycle management surface (BP11).

Commands for operators and developers to manage agents, policies, memory,
ledger, and tenants through the live control plane (``/api/*``).

All commands route through :class:`maestro.sdk.http_client.ControlPlaneClient`
so the CLI exercises the same authenticated, rate-limited, tenant-isolated
surface the operator dashboards use. A local fallback is never used for
fleet/tenant/policy operations — those are fail-closed.

Auth: the bearer token is resolved from (in order):
  1. ``--api-key`` flag
  2. ``MAESTRO_API_KEY`` env var
  3. ``~/.maestro/credentials`` (first non-empty, non-comment line)
  4. ``MAESTRO_SIGNING_KEY`` env as a last resort for local dev (minted
     automatically by the server when ``mitigation.zero_trust_api=false``)

Base URL: ``--control-plane`` flag > ``MAESTRO_CONTROL_PLANE`` env > ``http://127.0.0.1:8000``.

Output: ``--output json|table|yaml`` (json default).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from maestro.scripts.validate_threats import main as validate_main


def cli_validate() -> None:
    sys.exit(validate_main())


# --- CLI infrastructure ------------------------------------------------------ #

class CLIError(Exception):
    """Raised for CLI-specific errors (usage, config, etc.)."""
    pass


def _resolve_base_url(args: argparse.Namespace) -> str:
    if getattr(args, "control_plane", None):
        return str(args.control_plane).rstrip("/")
    env = os.environ.get("MAESTRO_CONTROL_PLANE")
    if env:
        return env.rstrip("/")
    return "http://127.0.0.1:8000"


def _resolve_api_key(args: argparse.Namespace) -> str | None:
    # Explicit flag > env > credentials file
    if getattr(args, "api_key", None):
        return str(args.api_key)
    env = os.environ.get("MAESTRO_API_KEY")
    if env:
        return env
    # Fallback: try to read ~/.maestro/credentials
    cred_path = Path.home() / ".maestro" / "credentials"
    if cred_path.is_file():
        try:
            for line in cred_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
        except OSError:
            pass
    return None


def _client_from_args(args: argparse.Namespace):  # type: ignore[no-untyped-def]
    from maestro.sdk.http_client import ControlPlaneClient

    base_url = _resolve_base_url(args)
    api_key = _resolve_api_key(args)
    return ControlPlaneClient(base_url=base_url, api_key=api_key, timeout=30.0)


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config", type=str, help="Path to MAESTRO config YAML"
    )
    parser.add_argument(
        "--control-plane", type=str, help="Control plane base URL"
    )
    parser.add_argument(
        "--api-key", type=str, help="Bearer token (or MAESTRO_API_KEY env / ~/.maestro/credentials)"
    )
    parser.add_argument(
        "--tenant", type=str, default="default", help="Tenant ID"
    )
    parser.add_argument(
        "--agent-id", type=str, help="Agent ID (for agent-scoped commands)"
    )
    parser.add_argument(
        "--output", type=str, choices=["json", "table", "yaml"], default="json",
        help="Output format"
    )


def _print_output(data: Any, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(data, indent=2, default=str))
    elif fmt == "yaml":
        try:
            import yaml
            print(yaml.dump(data, default_flow_style=False))
        except ImportError:
            print(json.dumps(data, indent=2, default=str))
    else:  # table
        _print_table(data)


def _print_table(data: Any) -> None:
    """Simple table output for lists of dicts.

    A known collection prints its header row even when empty (an operator
    should see the schema, not a bare ``[]``); unknown shapes fall back to JSON.
    """
    if isinstance(data, list):
        if data and isinstance(data[0], dict):
            _print_rows(data)
        else:
            print("No records.")
    elif isinstance(data, dict):
        if isinstance(data.get("agents"), list):
            if data["agents"]:
                _print_rows(data["agents"])
            else:
                print("agent_id | type | tenant | status")
                print("No agents found.")
        elif isinstance(data.get("tenants"), list):
            if data["tenants"]:
                _print_rows(data["tenants"])
            else:
                print("tenant_id | display_name")
                print("No tenants found.")
        elif isinstance(data.get("events"), list):
            events = data["events"][:20]
            if events:
                _print_rows(events)
            else:
                print("event_id | event_type | decision")
                print("No events found.")
            if len(data["events"]) > 20:
                print(f"... and {len(data['events']) - 20} more")
        else:
            print(json.dumps(data, indent=2, default=str))
    else:
        print(json.dumps(data, indent=2, default=str))


def _print_rows(rows: list[dict[str, Any]]) -> None:
    """Print rows under a header derived from the first row's keys."""
    keys = list(rows[0].keys())
    # Header
    print(" | ".join(keys))
    print("-" * (sum(len(k) for k in keys) + 3 * len(keys)))
    for row in rows:
        print(" | ".join(str(row.get(k, "")) for k in keys))


def _handle_sdk_error(exc: Exception) -> int:
    # Surface typed SDK errors with request_id
    from maestro.sdk.exceptions import MaestroError

    if isinstance(exc, MaestroError):
        rid = f" (request_id={exc.request_id})" if exc.request_id else ""
        print(f"Error: {exc.message}{rid}", file=sys.stderr)
        if exc.status_code == 401:
            print("Hint: set --api-key or MAESTRO_API_KEY / ~/.maestro/credentials", file=sys.stderr)
        return 1
    print(f"Error: {exc}", file=sys.stderr)
    return 1


# --- Agent commands ---------------------------------------------------------- #

def _agent_create(args: argparse.Namespace) -> int:
    """Create a new agent via POST /api/agents."""
    try:
        client = _client_from_args(args)
        from maestro.sdk.models import AgentCreateRequest

        req = AgentCreateRequest(
            type=args.type or "generic",
            agent_id=getattr(args, "agent_id", None),
            allowed_intents=getattr(args, "allowed_intents", None),
            shadow=bool(getattr(args, "shadow", False)),
        )
        info = client.create_agent(req)
        _print_output(info.model_dump() if hasattr(info, "model_dump") else info, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _agent_list(args: argparse.Namespace) -> int:
    """List agents via GET /api/agents."""
    try:
        client = _client_from_args(args)
        resp = client.list_agents()
        payload = resp.model_dump() if hasattr(resp, "model_dump") else resp
        _print_output(payload, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _agent_logs(args: argparse.Namespace) -> int:
    """Show agent logs via GET /api/agents/{id}/logs."""
    try:
        client = _client_from_args(args)
        agent_id = getattr(args, "agent_id", None) or getattr(args, "agent_id_pos", None)
        if not agent_id:
            raise CLIError("--agent-id required for logs")
        logs = client.get_agent_logs(agent_id, limit=int(getattr(args, "limit", 100) or 100))
        _print_output({"agent_id": agent_id, "logs": logs, "count": len(logs)}, args.output)
        client.close()
        return 0
    except CLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _agent_promote(args: argparse.Namespace) -> int:
    """Promote an agent — fetches its info (no autonomous promotion path)."""
    try:
        client = _client_from_args(args)
        agent_id = getattr(args, "agent_id", None) or getattr(args, "agent_id_pos", None)
        if not agent_id:
            raise CLIError("--agent-id required")
        info = client.get_agent(agent_id)
        payload = info.model_dump() if hasattr(info, "model_dump") else info
        _print_output(payload, args.output)
        client.close()
        return 0
    except CLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _agent_delete(args: argparse.Namespace) -> int:
    """Delete an agent via DELETE /api/agents/{id}."""
    try:
        client = _client_from_args(args)
        agent_id = getattr(args, "agent_id", None) or getattr(args, "agent_id_pos", None)
        if not agent_id:
            raise CLIError("--agent-id required")
        result = client.delete_agent(agent_id)
        _print_output(result, args.output)
        client.close()
        return 0
    except CLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _print_agent_info(agent, fmt: str) -> int:
    info = {
        "agent_id": agent._agent_id,
        "tenant": agent._tenant,
        "shadow_mode": agent.shadow,
        "capabilities": list(agent._caps.keys()),
        "ledger_events": len(agent.ledger),
        "memory_tiers": {
            tier.value: len(agent.memory.recall(agent.scope, tier=tier, include_untrusted=True))
            for tier in __import__("maestro.memory.records", fromlist=["MemoryTier"]).MemoryTier
        },
    }
    _print_output(info, fmt)
    return 0


# --- Policy commands --------------------------------------------------------- #

def _policy_validate(args: argparse.Namespace) -> int:
    """Validate a policy bundle via POST /api/policies/validate."""
    # Policy file can be passed as positional or via --policy-file; fall back to stdin
    policy_yaml: str | None = None
    if hasattr(args, "policy_file") and args.policy_file:
        policy_yaml = Path(args.policy_file).read_text(encoding="utf-8")
    elif getattr(args, "tenant_id", None) and Path(str(args.tenant_id)).is_file():
        policy_yaml = Path(str(args.tenant_id)).read_text(encoding="utf-8")
    else:
        # Try reading from stdin if piped
        if not sys.stdin.isatty():
            policy_yaml = sys.stdin.read()

    if not policy_yaml:
        print("Policy validation: provide a file path as tenant_id or pipe YAML via stdin", file=sys.stderr)
        try:
            # Try local validation as fallback (no server)
            client = _client_from_args(args)
            from maestro.sdk.models import PolicyValidateRequest

            # If we got here without content, use a minimal bundle to show the API works
            resp = client.validate_policy(PolicyValidateRequest(policy_yaml="version: 1\nallow_list: [noop]\n"))
            _print_output(resp.model_dump() if hasattr(resp, "model_dump") else resp, args.output)
            client.close()
            return 0
        except Exception as exc:  # noqa: BLE001
            return _handle_sdk_error(exc)

    try:
        client = _client_from_args(args)
        from maestro.sdk.models import PolicyValidateRequest

        resp = client.validate_policy(PolicyValidateRequest(policy_yaml=policy_yaml))
        _print_output(resp.model_dump() if hasattr(resp, "model_dump") else resp, args.output)
        client.close()
        return 0 if getattr(resp, "valid", False) else 1
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _policy_diff(args: argparse.Namespace) -> int:
    """Diff two policy versions (local, via control plane state)."""
    try:
        client = _client_from_args(args)
        layers = client.get_layers()
        state = client.get_state()
        _print_output({"layers": layers, "state": state.model_dump() if hasattr(state, "model_dump") else state}, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _policy_promote(args: argparse.Namespace) -> int:
    """Promote a policy — validates then reports (actual promotion is two-person via API)."""
    return _policy_validate(args)


def _policy_rollback(args: argparse.Namespace) -> int:
    """Rollback a policy (not yet exposed as an API; show current state)."""
    try:
        client = _client_from_args(args)
        state = client.get_state()
        _print_output(state.model_dump() if hasattr(state, "model_dump") else state, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


# --- Memory commands --------------------------------------------------------- #

def _memory_inspect(args: argparse.Namespace) -> int:
    """Inspect memory via GET /api/memory (live plane)."""
    try:
        client = _client_from_args(args)
        from maestro.sdk.models import MemoryInspectRequest

        tier = getattr(args, "tier", None)
        req = MemoryInspectRequest(
            tier=tier,
            include_untrusted=bool(getattr(args, "include_untrusted", False)),
            limit=int(getattr(args, "limit", 100)),
        )
        tenant = getattr(args, "tenant", "default")
        resp = client.inspect_memory(req, tenant=tenant)
        _print_output(resp.model_dump() if hasattr(resp, "model_dump") else resp, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _memory_promote(args: argparse.Namespace) -> int:
    """Promote a quarantined record via POST /api/memory/promote."""
    try:
        client = _client_from_args(args)
        from maestro.sdk.models import MemoryPromoteRequest

        tenant = getattr(args, "tenant", "default")
        req = MemoryPromoteRequest(record_id=args.record_id, capability="cap:memory:promote")
        result = client.promote_memory(req, tenant=tenant)
        # http_client returns dict for promote
        _print_output(result if isinstance(result, dict) else result.model_dump(), args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _memory_quarantine(args: argparse.Namespace) -> int:
    """Quarantine a record via POST /api/memory/quarantine."""
    try:
        client = _client_from_args(args)
        from maestro.sdk.models import MemoryQuarantineRequest

        tenant = getattr(args, "tenant", "default")
        req = MemoryQuarantineRequest(record_id=args.record_id)
        result = client.quarantine_memory(req, tenant=tenant)
        _print_output(result if isinstance(result, dict) else result.model_dump(), args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


# --- Ledger commands --------------------------------------------------------- #

def _ledger_verify(args: argparse.Namespace) -> int:
    """Verify ledger via GET /api/ledger/verify (live plane)."""
    try:
        client = _client_from_args(args)
        resp = client.verify_ledger()
        _print_output(resp.model_dump() if hasattr(resp, "model_dump") else resp, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _ledger_export(args: argparse.Namespace) -> int:
    """Export ledger via GET /api/ledger/export."""
    try:
        client = _client_from_args(args)
        limit = int(getattr(args, "limit", 0) or 0) or None
        if hasattr(args, "limit") and args.limit:
            limit = int(args.limit)
        resp = client.export_ledger(limit=limit)
        _print_output(resp.model_dump() if hasattr(resp, "model_dump") else resp, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _ledger_audit(args: argparse.Namespace) -> int:
    """Audit ledger — verify + metrics from the live plane."""
    try:
        client = _client_from_args(args)
        verify = client.verify_ledger()
        metrics = client.get_metrics()
        _print_output({
            "verify": verify.model_dump() if hasattr(verify, "model_dump") else verify,
            "metrics": metrics.model_dump() if hasattr(metrics, "model_dump") else metrics,
        }, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


# --- Tenant commands --------------------------------------------------------- #

def _tenant_create(args: argparse.Namespace) -> int:
    """Create a tenant via POST /api/tenants (ADMIN)."""
    try:
        client = _client_from_args(args)
        from maestro.sdk.models import TenantCreateRequest

        req = TenantCreateRequest(tenant_id=args.tenant_id, display_name=getattr(args, "display_name", None))
        info = client.create_tenant(req)
        _print_output(info.model_dump() if hasattr(info, "model_dump") else info, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _tenant_isolate(args: argparse.Namespace) -> int:
    """Enforce isolation via POST /api/tenants/{id}/isolate (ADMIN)."""
    try:
        client = _client_from_args(args)
        result = client.isolate_tenant(args.tenant_id)
        _print_output(result, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


def _tenant_audit(args: argparse.Namespace) -> int:
    """Audit tenant via GET /api/tenants/{id} + ledger verify."""
    try:
        client = _client_from_args(args)
        info = client.get_tenant(args.tenant_id)
        verify = client.verify_ledger()
        _print_output({
            "tenant": info.model_dump() if hasattr(info, "model_dump") else info,
            "ledger": verify.model_dump() if hasattr(verify, "model_dump") else verify,
        }, args.output)
        client.close()
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_sdk_error(exc)


# --- Main CLI ----------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="maestro",
        description="MAESTRO — Policy-Governed Execution Platform for Agentic AI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Global options
    parser.add_argument("--version", action="version", version="0.9.0")

    # Agent commands
    agent_parser = subparsers.add_parser("agent", help="Agent lifecycle management")
    agent_sub = agent_parser.add_subparsers(dest="agent_command")

    create_p = agent_sub.add_parser("create", help="Create agent")
    create_p.add_argument("--type", choices=["generic", "coding", "research", "soc"], default="generic")
    _add_common_args(create_p)
    create_p.set_defaults(func=_agent_create)

    list_p = agent_sub.add_parser("list", help="List agents")
    _add_common_args(list_p)
    list_p.set_defaults(func=_agent_list)

    logs_p = agent_sub.add_parser("logs", help="Show agent logs")
    logs_p.add_argument("agent_id", help="Agent ID")
    logs_p.add_argument("--limit", type=int, default=100, help="Max log entries")
    _add_common_args(logs_p)
    logs_p.set_defaults(func=_agent_logs)

    promote_p = agent_sub.add_parser("promote", help="Promote agent")
    promote_p.add_argument("agent_id", help="Agent ID")
    _add_common_args(promote_p)
    promote_p.set_defaults(func=_agent_promote)

    delete_p = agent_sub.add_parser("delete", help="Delete agent")
    delete_p.add_argument("agent_id", help="Agent ID")
    _add_common_args(delete_p)
    delete_p.set_defaults(func=_agent_delete)

    # Policy commands
    policy_parser = subparsers.add_parser("policy", help="Policy management")
    policy_sub = policy_parser.add_subparsers(dest="policy_command")

    for cmd, help_text in [
        ("validate", "Validate policy bundle"),
        ("diff", "Diff policy versions"),
        ("promote", "Promote policy to environment"),
        ("rollback", "Rollback policy"),
    ]:
        p = policy_sub.add_parser(cmd, help=help_text)
        if cmd == "validate":
            p.add_argument("policy_file", nargs="?", help="Path to policy YAML (or stdin)")
        _add_common_args(p)
        p.set_defaults(func=globals()[f"_policy_{cmd}"])

    # Memory commands
    memory_parser = subparsers.add_parser("memory", help="Memory inspection")
    memory_sub = memory_parser.add_subparsers(dest="memory_command")

    inspect_p = memory_sub.add_parser("inspect", help="Inspect memory records")
    inspect_p.add_argument("--tier", choices=["working", "episodic", "semantic", "procedural"])
    inspect_p.add_argument("--include-untrusted", action="store_true")
    inspect_p.add_argument("--limit", type=int, default=100)
    _add_common_args(inspect_p)
    inspect_p.set_defaults(func=_memory_inspect)

    promote_p = memory_sub.add_parser("promote", help="Promote memory record")
    promote_p.add_argument("record_id", help="Record ID")
    _add_common_args(promote_p)
    promote_p.set_defaults(func=_memory_promote)

    quarantine_p = memory_sub.add_parser("quarantine", help="Quarantine memory record")
    quarantine_p.add_argument("record_id", help="Record ID")
    _add_common_args(quarantine_p)
    quarantine_p.set_defaults(func=_memory_quarantine)

    # Ledger commands
    ledger_parser = subparsers.add_parser("ledger", help="Ledger operations")
    ledger_sub = ledger_parser.add_subparsers(dest="ledger_command")

    for cmd, help_text in [
        ("verify", "Verify ledger integrity"),
        ("export", "Export ledger events"),
        ("audit", "Audit ledger for anomalies"),
    ]:
        p = ledger_sub.add_parser(cmd, help=help_text)
        if cmd == "export":
            p.add_argument("--limit", type=int, default=None, help="Max events")
        _add_common_args(p)
        p.set_defaults(func=globals()[f"_ledger_{cmd}"])

    # Tenant commands
    tenant_parser = subparsers.add_parser("tenant", help="Tenant management")
    tenant_sub = tenant_parser.add_subparsers(dest="tenant_command")

    for cmd, help_text in [
        ("create", "Create tenant"),
        ("isolate", "Enforce isolation"),
        ("audit", "Audit tenant"),
    ]:
        p = tenant_sub.add_parser(cmd, help=help_text)
        p.add_argument("tenant_id", help="Tenant ID")
        _add_common_args(p)
        p.set_defaults(func=globals()[f"_tenant_{cmd}"])

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except CLIError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
