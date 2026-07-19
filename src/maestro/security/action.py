"""Typed action-proposal schema (Enforcement Plane).

The core architectural rule of MAESTRO-SecOps is:

    No agent-generated output may cause an external side effect unless an
    independent policy-enforcement point authorizes a *typed action* under a
    valid capability.

An LLM is never a security authority. It may only *propose* an action as
untrusted JSON; :func:`parse_proposal` deterministically validates that JSON
into a strict :class:`ActionProposal`. Anything malformed, wrongly typed, or
missing required fields is rejected here — before any policy, capability, or
executor logic runs. JSON-validity is not safety: a well-formed proposal still
has to clear the enforcement pipeline.

``capability`` and ``resource`` are derived deterministically from the intent
so the executor gateway can match them against a :class:`~maestro.security.
identity.CapabilityToken` without trusting any LLM-supplied scope string.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .risk_engine import CAPABILITY_REQUIRED_ACTIONS


class InvalidProposal(Exception):
    """Raised when raw model output fails deterministic schema validation."""


#: Maps a proposed ``intent`` to (action_class, capability). The action_class
#: feeds the risk engine's capability-required override; the capability is the
#: exact token scope the executor gateway must see. Intents absent here are
#: rejected — the executor only speaks an allow-listed vocabulary.
INTENT_REGISTRY: dict[str, tuple[str, str]] = {
    "block_source_ip": ("irreversible_network_change", "cap:firewall:block-ip"),
    "rate_limit_source": ("irreversible_network_change", "cap:firewall:rate-limit"),
    "open_incident_ticket": ("ticketing", "cap:ticketing:create"),
    "read_flow_summary": ("read_telemetry", "cap:telemetry:read"),
    "quarantine_memory_record": ("deletion", "cap:memory:quarantine"),
    "rotate_credentials": ("credential_access", "cap:secrets:rotate"),
    "run_containment_script": ("code_execution", "cap:executor:run-script"),
    # Network-monitoring mitigation actions (the reproduction's L3 allow-list,
    # Sec 5.3) — reversible operational controls, so none are in
    # CAPABILITY_REQUIRED_ACTIONS; they still require a capability once the risk
    # band rises above ALLOW. See maestro/platform.
    "noop": ("observe", "cap:agent:noop"),
    "throttle_telemetry": ("network_change", "cap:telemetry:throttle"),
    "raise_thresholds": ("config_change", "cap:detection:raise-thresholds"),
    "raise_capture_duration": ("config_change", "cap:capture:set-duration"),
    "alert_operator": ("notify", "cap:notify:operator"),
    "rollback_telemetry": ("network_change", "cap:telemetry:rollback"),
}

#: Reversible intents — used by the platform to shape risk (lower recoverability
#: cost / blast radius) and confidence (higher reversibility signal).
REVERSIBLE_INTENTS: frozenset[str] = frozenset({
    "noop", "throttle_telemetry", "raise_thresholds",
    "raise_capture_duration", "alert_operator", "rollback_telemetry",
    "read_flow_summary",
})

_REQUIRED_FIELDS: dict[str, type] = {
    "intent": str,
    "target": str,
    "reason": str,
    "evidence_ids": list,
    "requested_ttl_seconds": int,
}


@dataclass(frozen=True)
class ActionProposal:
    """A validated, typed request for an external side effect."""

    intent: str
    target: str
    reason: str
    evidence_ids: tuple[str, ...]
    requested_ttl_seconds: int
    action_class: str = field(default="")
    capability: str = field(default="")

    @property
    def resource(self) -> str:
        """The resource scope the action touches (== the target)."""
        return self.target

    def requires_capability(self) -> bool:
        """True if this action can never ride on model confidence alone."""
        return self.action_class in CAPABILITY_REQUIRED_ACTIONS

    def content_hash(self) -> str:
        payload = json.dumps(
            {
                "intent": self.intent,
                "target": self.target,
                "reason": self.reason,
                "evidence_ids": list(self.evidence_ids),
                "requested_ttl_seconds": self.requested_ttl_seconds,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def as_dict(self) -> dict[str, object]:
        return {
            "intent": self.intent,
            "target": self.target,
            "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
            "requested_ttl_seconds": self.requested_ttl_seconds,
            "action_class": self.action_class,
            "capability": self.capability,
        }


def parse_proposal(raw: object) -> ActionProposal:
    """Deterministically validate untrusted model output into an ActionProposal.

    Raises :class:`InvalidProposal` on any structural or type error, or on an
    intent outside :data:`INTENT_REGISTRY`.
    """
    if isinstance(raw, str | bytes):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            raise InvalidProposal(f"proposal is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise InvalidProposal("proposal must be a JSON object")

    for key, typ in _REQUIRED_FIELDS.items():
        if key not in raw:
            raise InvalidProposal(f"missing required field: {key!r}")
        # bool is a subclass of int — reject it where an int ttl is expected.
        if typ is int and isinstance(raw[key], bool):
            raise InvalidProposal(f"field {key!r} must be int, got bool")
        if not isinstance(raw[key], typ):
            raise InvalidProposal(
                f"field {key!r} must be {typ.__name__}, got {type(raw[key]).__name__}")

    intent = raw["intent"]
    if intent not in INTENT_REGISTRY:
        raise InvalidProposal(f"unknown intent {intent!r} (not in allow-list)")
    action_class, capability = INTENT_REGISTRY[intent]

    ttl = raw["requested_ttl_seconds"]
    if ttl <= 0:
        raise InvalidProposal("requested_ttl_seconds must be positive")

    evidence = raw["evidence_ids"]
    if not all(isinstance(e, str) and e for e in evidence):
        raise InvalidProposal("evidence_ids must be a list of non-empty strings")
    if not raw["target"]:
        raise InvalidProposal("target must be non-empty")

    return ActionProposal(
        intent=intent,
        target=raw["target"],
        reason=raw["reason"],
        evidence_ids=tuple(evidence),
        requested_ttl_seconds=ttl,
        action_class=action_class,
        capability=capability,
    )
