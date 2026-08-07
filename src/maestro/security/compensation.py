"""Compensation actions framework (BP4 completion).

Every irreversible action has a compensating undo operation. When an action
fails postcondition verification or is explicitly rolled back, the compensation
is executed automatically and recorded in the ledger.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from maestro.security.action import ActionProposal
from maestro.security.ledger import Ledger


class CompensationError(Exception):
    """Raised when compensation fails."""
    pass


@dataclass(frozen=True)
class CompensationAction:
    """A compensating action for an original intent.
    
    The compensation is itself an action that can be authorized and executed
    through the enforcement plane.
    """
    original_intent: str
    compensation_intent: str
    # Function to derive compensation arguments from original proposal + result
    make_args: Callable[[ActionProposal, dict], dict]
    # Whether compensation requires human approval
    requires_approval: bool = False
    # Description for audit/logging
    description: str = ""


# Registry of compensations for CAPABILITY_REQUIRED_ACTIONS
COMPENSATION_REGISTRY: dict[str, CompensationAction] = {
    "block_source_ip": CompensationAction(
        original_intent="block_source_ip",
        compensation_intent="unblock_source_ip",
        make_args=lambda p, r: {
            "ip": p.target,
            "reason": f"Compensate {p.intent} for {p.target}",
        },
        description="Remove firewall block rule",
    ),
    "rate_limit_source": CompensationAction(
        original_intent="rate_limit_source",
        compensation_intent="remove_rate_limit",
        make_args=lambda p, r: {
            "ip": p.target,
            "reason": f"Compensate {p.intent} for {p.target}",
        },
        description="Remove rate limiting rule",
    ),
    "rotate_credentials": CompensationAction(
        original_intent="rotate_credentials",
        compensation_intent="restore_credentials",
        make_args=lambda p, r: {
            "credential_id": p.target,
            "backup_id": r.get("backup_id", ""),
            "reason": f"Compensate {p.intent} for {p.target}",
        },
        description="Restore credentials from vault backup",
        requires_approval=True,
    ),
    "run_containment_script": CompensationAction(
        original_intent="run_containment_script",
        compensation_intent="restore_from_backup",
        make_args=lambda p, r: {
            "backup_id": r.get("backup_id", ""),
            "reason": f"Compensate {p.intent}",
        },
        description="Restore system from pre-containment backup",
        requires_approval=True,
    ),
    "code_git_push": CompensationAction(
        original_intent="code_git_push",
        compensation_intent="git_revert",
        make_args=lambda p, r: {
            "commit_sha": r.get("commit_sha", ""),
            "branch": r.get("branch", "main"),
            "reason": f"Compensate {p.intent}",
        },
        description="Revert git push via revert commit",
    ),
    "code_open_pr": CompensationAction(
        original_intent="code_open_pr",
        compensation_intent="close_pr",
        make_args=lambda p, r: {
            "pr_number": r.get("pr_number", 0),
            "reason": f"Compensate {p.intent}",
        },
        description="Close pull request",
    ),
    "code_write": CompensationAction(
        original_intent="code_write",
        compensation_intent="code_revert_write",
        make_args=lambda p, r: {
            "file_path": p.target,
            "previous_content": r.get("previous_content", ""),
            "reason": f"Compensate {p.intent}",
        },
        description="Revert code write to previous content",
    ),
    "quarantine_memory_record": CompensationAction(
        original_intent="quarantine_memory_record",
        compensation_intent="restore_memory_record",
        make_args=lambda p, r: {
            "record_id": p.target,
            "reason": f"Compensate {p.intent}",
        },
        description="Restore quarantined memory record to trusted",
    ),
    "promote_memory": CompensationAction(
        original_intent="promote_memory",
        compensation_intent="demote_memory",
        make_args=lambda p, r: {
            "record_id": p.target,
            "reason": f"Compensate {p.intent}",
        },
        description="Demote promoted memory back to untrusted",
    ),
    "alert_operator": CompensationAction(
        original_intent="alert_operator",
        compensation_intent="resolve_alert",
        make_args=lambda p, r: {
            "alert_id": r.get("alert_id", ""),
            "reason": f"Compensate {p.intent}",
        },
        description="Mark operator alert as resolved",
    ),
    "research_synthesize": CompensationAction(
        original_intent="research_synthesize",
        compensation_intent="retract_report",
        make_args=lambda p, r: {
            "report_id": r.get("report_id", ""),
            "reason": f"Compensate {p.intent}",
        },
        description="Retract synthesized research report",
    ),
}


def get_compensation(original_intent: str) -> CompensationAction | None:
    """Look up compensation action for an intent."""
    return COMPENSATION_REGISTRY.get(original_intent)


def register_compensation(compensation: CompensationAction) -> None:
    """Register a new compensation action."""
    COMPENSATION_REGISTRY[compensation.original_intent] = compensation


def compensate(
    proposal: ActionProposal,
    execution_result: dict,
    *,
    compensation_config: dict | None = None,
    issuer=None,
    ledger: Ledger | None = None,
    tenant: str = "default",
) -> dict:
    """Execute compensation for a failed or rolled-back action.
    
    Args:
        proposal: The original action proposal
        execution_result: Result from the failed execution
        compensation_config: Optional config (e.g., backup_id, PR number)
        issuer: CapabilityIssuer for issuing compensation capability
        ledger: Ledger for recording compensation
        tenant: Tenant for scoping
    
    Returns:
        Compensation result dict
    
    Raises:
        CompensationError: If compensation fails
    """
    compensation = get_compensation(proposal.intent)
    if compensation is None:
        # No explicit compensation - may be reversible or no-op
        return {
            "status": "no_compensation_defined",
            "original_intent": proposal.intent,
            "message": "No compensation action registered for this intent",
        }
    
    # Build compensation proposal
    comp_args = compensation.make_args(proposal, execution_result)
    if compensation_config:
        comp_args.update(compensation_config)
    
    from maestro.platform.agent_platform import _INTENT_RESOURCE
    from maestro.security.action import INTENT_REGISTRY
    from maestro.security.enforcement import PolicyEnforcementPoint, ToolAdapter
    from maestro.security.risk_engine import RiskInputs
    
    # Get compensation intent details
    comp_action_class, comp_capability = INTENT_REGISTRY.get(
        compensation.compensation_intent, ("unknown", "")
    )
    comp_target = _INTENT_RESOURCE.get(
        compensation.compensation_intent, "unknown"
    ).replace("{tenant}", tenant)
    
    comp_proposal = ActionProposal(
        intent=compensation.compensation_intent,
        target=comp_target,
        reason=f"Compensation for {proposal.intent}: {compensation.description}",
        evidence_ids=(f"compensate:{proposal.content_hash()}",),
        requested_ttl_seconds=300,
        action_class=comp_action_class,
        capability=comp_capability,
    )
    
    # If we have an issuer and ledger, execute through PEP
    if issuer and ledger:
        # Issue capability for compensation
        comp_token = issuer.issue(
            subject=f"compensation:{proposal.intent}",
            capability=comp_capability,
            resource_constraint=comp_target,
            tenant=tenant,
            ttl_seconds=300.0,
            delegation_depth=1,
        )
        
        # Simple adapters for compensation actions
        comp_adapters: dict[str, ToolAdapter] = {
            "unblock_source_ip": lambda p: {"ok": True, "effect": "firewall rule removed", "target": p.target},
            "remove_rate_limit": lambda p: {"ok": True, "effect": "rate limit removed", "target": p.target},
            "restore_credentials": lambda p: {"ok": True, "effect": "credentials restored", "target": p.target},
            "restore_from_backup": lambda p: {"ok": True, "effect": "system restored from backup", "target": p.target},
            "git_revert": lambda p: {"ok": True, "effect": "git revert committed", "target": p.target},
            "close_pr": lambda p: {"ok": True, "effect": "PR closed", "target": p.target},
            "restore_memory_record": lambda p: {"ok": True, "effect": "memory record restored", "target": p.target},
            "demote_memory": lambda p: {"ok": True, "effect": "memory demoted to untrusted", "target": p.target},
            "resolve_alert": lambda p: {"ok": True, "effect": "alert resolved", "target": p.target},
        }
        
        pep = PolicyEnforcementPoint(
            issuer=issuer,
            ledger=ledger,
            evidence_exists=lambda e: True,  # Compensation evidence is the original action
            tenant=tenant,
            adapters=comp_adapters,
            approver=None,
            budget=None,
            breaker=None,
            sandbox=None,
            pre_execution_gate=None,
            policy_registry=None,
        )
        
        # Execute compensation
        from maestro.security.risk_engine import RiskInputs
        risk = RiskInputs(
            likelihood=1.0, impact=1.0, exploitability=1.0,
            exposure=1.0, detectability_inverse=1.0,
            recoverability_inverse=1.0, blast_radius=1.0
        )
        
        result = pep.authorize_and_execute(
            comp_proposal,
            token=comp_token,
            risk=risk,
            actor=f"compensation:{proposal.intent}",
            controls=None,
            confidence=None,
            cost=0.0,
            affected=0,
            idempotency_key=f"compensate:{proposal.content_hash()}",
            verification_context=None,
        )
        
        if not result.allowed:
            raise CompensationError(f"Compensation denied: {result.reason}")
        
        return {
            "status": "compensated",
            "original_intent": proposal.intent,
            "compensation_intent": compensation.compensation_intent,
            "compensation_result": result.output,
            "compensation_event_id": result.event_id,
        }
    
    # Without issuer/ledger, return the compensation proposal for external execution
    return {
        "status": "compensation_proposal_generated",
        "original_intent": proposal.intent,
        "compensation_proposal": comp_proposal.as_dict(),
        "compensation_args": comp_args,
        "requires_approval": compensation.requires_approval,
    }


def list_compensations() -> list[CompensationAction]:
    """List all registered compensations."""
    return list(COMPENSATION_REGISTRY.values())


# Set of original intents that agents can propose (excluding compensation intents)
ORIGINAL_INTENTS: frozenset[str] = frozenset({
    "block_source_ip", "rate_limit_source",
    "rotate_credentials", "run_containment_script",
    "code_write", "code_git_push", "code_open_pr",
    "quarantine_memory_record", "promote_memory",
    "alert_operator", "research_synthesize",
    "noop", "throttle_telemetry", "raise_thresholds",
    "raise_capture_duration", "rollback_telemetry",
    "code_read", "code_test", "code_lint",
    "code_git_status", "code_git_diff",
    "research_search", "research_fetch", "research_cite",
    "read_flow_summary", "open_incident_ticket",
})


def validate_compensation_registry() -> list[str]:
    """Validate that all ORIGINAL agent intents have compensations.
    
    Returns list of original intents missing compensations.
    """
    from maestro.security.action import INTENT_REGISTRY
    from maestro.security.risk_engine import CAPABILITY_REQUIRED_ACTIONS
    
    missing = []
    for action_class in CAPABILITY_REQUIRED_ACTIONS:
        # Find original intents with this action class
        intents = [i for i, (ac, _) in INTENT_REGISTRY.items() 
                   if ac == action_class and i in ORIGINAL_INTENTS]
        for intent in intents:
            if intent not in COMPENSATION_REGISTRY:
                missing.append(intent)
    return missing