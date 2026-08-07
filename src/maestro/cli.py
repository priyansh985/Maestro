"""MAESTRO CLI — Full lifecycle management surface (BP11).

Commands for operators and developers to manage agents, policies, memory,
ledger, and tenants across the control plane.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from maestro.validate_threats import main as validate_main


def cli_validate() -> None:
    sys.exit(validate_main())


# --- CLI infrastructure ------------------------------------------------------ #

class CLIError(Exception):
    """Raised for CLI-specific errors (usage, config, etc.)."""
    pass


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config", type=str, help="Path to MAESTRO config YAML"
    )
    parser.add_argument(
        "--control-plane", type=str, help="Control plane base URL"
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
    """Simple table output for lists of dicts."""
    if isinstance(data, list) and data and isinstance(data[0], dict):
        keys = list(data[0].keys())
        # Header
        print(" | ".join(keys))
        print("-" * (sum(len(k) for k in keys) + 3 * len(keys)))
        for row in data:
            print(" | ".join(str(row.get(k, "")) for k in keys))
    else:
        print(json.dumps(data, indent=2, default=str))


# --- Agent commands ---------------------------------------------------------- #

def _agent_create(args: argparse.Namespace) -> int:
    """Create a new agent."""
    from maestro.agents.coding import create_coding_agent
    from maestro.agents.research import create_research_agent
    from maestro.platform.agent_platform import AgentPlatform

    agent_type = args.type or "generic"

    if agent_type == "coding":
        agent = create_coding_agent(tenant=args.tenant)
    elif agent_type == "research":
        agent = create_research_agent(tenant=args.tenant)
    else:
        agent = AgentPlatform(tenant=args.tenant, agent_id=args.agent_id or "agent:generic:run")

    return _print_agent_info(agent, args.output)


def _agent_list(args: argparse.Namespace) -> int:
    """List agents (stub - would query control plane in real implementation)."""
    # In a real implementation, this would call the control plane API
    agents = [
        {"id": "agent:network-monitor:run", "type": "soc", "tenant": args.tenant, "status": "running"},
        {"id": "agent:secure-coding:run", "type": "coding", "tenant": args.tenant, "status": "idle"},
        {"id": "agent:research:run", "type": "research", "tenant": args.tenant, "status": "idle"},
    ]
    _print_output(agents, args.output)
    return 0


def _agent_logs(args: argparse.Namespace) -> int:
    """Show agent logs (stub)."""
    print(f"Logs for {args.agent_id} (not implemented - would stream from control plane)")
    return 0


def _agent_promote(args: argparse.Namespace) -> int:
    """Promote an agent (stub - would trigger promotion workflow)."""
    print(f"Promoting {args.agent_id} (not implemented - would call control plane)")
    return 0


def _agent_delete(args: argparse.Namespace) -> int:
    """Delete an agent (stub)."""
    print(f"Deleting {args.agent_id} (not implemented - would call control plane)")
    return 0


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
    """Validate a policy bundle."""
    print("Policy validation (not fully implemented)")
    return 0


def _policy_diff(args: argparse.Namespace) -> int:
    """Diff two policy versions."""
    print("Policy diff (not fully implemented)")
    return 0


def _policy_promote(args: argparse.Namespace) -> int:
    """Promote a policy to next environment."""
    print("Policy promotion (not fully implemented)")
    return 0


def _policy_rollback(args: argparse.Namespace) -> int:
    """Rollback a policy."""
    print("Policy rollback (not fully implemented)")
    return 0


# --- Memory commands --------------------------------------------------------- #

def _memory_inspect(args: argparse.Namespace) -> int:
    """Inspect memory records."""
    import os
    import secrets

    from maestro.memory import MemoryScope, MemoryStore, MemoryTier
    from maestro.security.identity import CapabilityIssuer
    from maestro.security.ledger import Ledger

    key = os.environ.get("MAESTRO_SIGNING_KEY") or secrets.token_hex(32)
    issuer = CapabilityIssuer(key=key)
    ledger = Ledger(key=key)
    store = MemoryStore(issuer=issuer, ledger=ledger)
    scope = MemoryScope(args.tenant, args.agent_id or "agent:default:run")

    tier = MemoryTier[args.tier.upper()] if args.tier else None
    include_untrusted = args.include_untrusted

    records = store.recall(scope, tier=tier, include_untrusted=include_untrusted, limit=args.limit)

    data = [r.as_dict() for r in records]
    _print_output(data, args.output)
    return 0


def _memory_promote(args: argparse.Namespace) -> int:
    """Promote a memory record."""
    print("Memory promotion (not fully implemented - requires capability)")
    return 0


def _memory_quarantine(args: argparse.Namespace) -> int:
    """Quarantine a memory record."""
    print("Memory quarantine (not fully implemented)")
    return 0


# --- Ledger commands --------------------------------------------------------- #

def _ledger_verify(args: argparse.Namespace) -> int:
    """Verify ledger integrity."""
    import os
    import secrets

    from maestro.security.ledger import Ledger

    key = os.environ.get("MAESTRO_SIGNING_KEY") or secrets.token_hex(32)
    ledger = Ledger(key=key)

    first_broken = ledger.verify_chain()
    intact = first_broken == -1

    result = {
        "intact": intact,
        "events": len(ledger),
        "head_hash": ledger.head_hash,
        "first_broken_index": None if intact else first_broken,
    }
    _print_output(result, args.output)
    return 0


def _ledger_export(args: argparse.Namespace) -> int:
    """Export ledger events."""
    import os
    import secrets

    from maestro.security.ledger import Ledger

    key = os.environ.get("MAESTRO_SIGNING_KEY") or secrets.token_hex(32)
    ledger = Ledger(key=key)

    events = [e.__dict__ for e in ledger.events]
    _print_output(events, args.output)
    return 0


def _ledger_audit(args: argparse.Namespace) -> int:
    """Audit ledger for anomalies."""
    print("Ledger audit (not fully implemented)")
    return 0


# --- Tenant commands --------------------------------------------------------- #

def _tenant_create(args: argparse.Namespace) -> int:
    """Create a new tenant."""
    print(f"Creating tenant {args.tenant_id} (not fully implemented)")
    return 0


def _tenant_isolate(args: argparse.Namespace) -> int:
    """Enforce tenant isolation."""
    print(f"Enforcing isolation for tenant {args.tenant_id} (not fully implemented)")
    return 0


def _tenant_audit(args: argparse.Namespace) -> int:
    """Audit tenant access."""
    print(f"Auditing tenant {args.tenant_id} (not fully implemented)")
    return 0


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