"""Pydantic models for MAESTRO SDK request/response types.

These mirror the actual control-plane payloads (``maestro/server/control_api.py``
and ``maestro/server/agents_api.py``). Timestamps are epoch seconds (floats);
ledger and memory shapes come straight from the framework dataclasses'
``as_dict()``/``asdict()``. Unknown response fields are ignored so the SDK
tolerates additive server changes.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    """Base: ignore extra server fields (forward compatibility)."""

    model_config = ConfigDict(extra="ignore")


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
class AlertClass(str, Enum):
    DOS = "dos"
    ANOMALY = "anomaly"
    PORT_SCAN = "port_scan"
    BRUTEFORCE = "bruteforce"
    NORMAL = "normal"


class AlertIn(_Model):
    """Submit an alert through the live control loop."""

    cls: AlertClass | str = Field("dos", description="normal|dos|port_scan|bruteforce|anomaly")
    severity: float = Field(0.9, ge=0.0, le=1.0)
    detail: str = ""


class AlertOut(_Model):
    """The outcome of one alert: the decision card and its verdict."""

    alert_id: str
    tenant: str
    created_at: float
    alert_class: str
    proposed_action: str
    allowed: bool
    decision: str
    reason: str
    shadowed: bool = False
    decision_card: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None  # set when driven through a fleet agent


# --------------------------------------------------------------------------- #
# Agents (fleet lifecycle)
# --------------------------------------------------------------------------- #
class AgentType(str, Enum):
    GENERIC = "generic"
    CODING = "coding"
    RESEARCH = "research"
    SOC = "soc"


class AgentStatus(str, Enum):
    RUNNING = "running"
    IDLE = "idle"
    HALTED = "halted"
    ERROR = "error"


class AgentCreateRequest(_Model):
    """Provision a new agent in the caller's tenant.

    The tenant is derived from the authenticated principal's token (structural
    isolation), never from the request body.
    """

    type: AgentType | str = AgentType.GENERIC
    agent_id: str | None = None
    allowed_intents: list[str] | None = Field(
        None, description="can only narrow the type's vocabulary (least privilege)")
    shadow: bool = False


class AgentInfo(_Model):
    agent_id: str
    tenant: str
    type: AgentType | str
    status: AgentStatus | str
    shadow_mode: bool
    capabilities: list[str] = Field(default_factory=list)
    intent_vocabulary: list[str] = Field(default_factory=list)
    ledger_events: int
    ledger_intact: bool = True
    memory_tiers: dict[str, int] = Field(default_factory=dict)
    created_at: float
    last_active: float | None = None
    error: str | None = None
    blast_radius: dict[str, Any] | None = None   # detail endpoint only
    policy_digest: str | None = None             # detail endpoint only


class AgentListResponse(_Model):
    agents: list[AgentInfo]
    total: int


# --------------------------------------------------------------------------- #
# Blast radius
# --------------------------------------------------------------------------- #
class BlastRadiusResponse(_Model):
    agent_id: str
    tenant: str
    capabilities: list[str]
    intent_vocabulary: list[str]
    reversible_intents: list[str]
    irreversible_intents: list[str]
    budget: dict[str, Any]
    holds_irreversible_capability: bool | None = None
    summary: str | None = None


# --------------------------------------------------------------------------- #
# Perimeter (dual-LLM injection boundary)
# --------------------------------------------------------------------------- #
class PerimeterIn(_Model):
    content: str
    source: str = "external"


class SignalOut(_Model):
    category: str
    pattern: str
    severity: float
    excerpt: str


class VariableOut(_Model):
    name: str
    kind: str
    value: str


class PerimeterResult(_Model):
    disposition: str
    trust: str
    injection_score: float
    influential: bool
    admitted: bool
    signals: list[SignalOut] = Field(default_factory=list)
    variables: list[VariableOut] = Field(default_factory=list)
    source: str
    reason: str


# --------------------------------------------------------------------------- #
# Critique (HMDC pre-execution gate)
# --------------------------------------------------------------------------- #
class CritiqueIn(_Model):
    text: str
    grounding: list[str] = Field(default_factory=list)
    intent: str | None = None
    family: str | None = None


class CritiqueOut(_Model):
    verdict: str
    reason: str
    guardrails: dict[str, Any] = Field(default_factory=dict)
    semantic_alignment: float = 0.0
    judge_scores: list[dict[str, Any]] = Field(default_factory=list)
    ensemble_mean: float = 0.0
    ensemble_variance: float = 0.0
    excluded_same_family: list[str] = Field(default_factory=list)
    task_verified: bool | None = None


class HaltResponse(_Model):
    halted: bool
    message: str = ""
    agent_id: str | None = None


# --------------------------------------------------------------------------- #
# Memory
# --------------------------------------------------------------------------- #
class MemoryTier(str, Enum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"


class TrustLabel(str, Enum):
    UNTRUSTED = "untrusted"
    TRUSTED = "trusted"
    CURATED = "curated"
    SYSTEM = "system"


class MemoryRecord(_Model):
    record_id: str
    scope: str
    tier: MemoryTier | str
    trust: TrustLabel | str
    content: str
    provenance: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: float = 0.0
    expires_at: float | None = None
    content_hash: str = ""


class MemoryInspectRequest(_Model):
    tier: MemoryTier | str | None = None
    include_untrusted: bool = True
    limit: int = 100


class MemoryInspectResponse(_Model):
    scope: str
    records: list[MemoryRecord]
    count: int
    total: int | None = None


class MemoryPromoteRequest(_Model):
    record_id: str
    capability: str = Field(
        default="cap:memory:promote",
        description="the asserted capability; the scoped token is minted "
        "server-side under the OPERATOR role and ledgered")


class MemoryQuarantineRequest(_Model):
    record_id: str


# --------------------------------------------------------------------------- #
# Ledger
# --------------------------------------------------------------------------- #
class LedgerEvent(_Model):
    """One tamper-evident audit event (hash-chained + HMAC-signed)."""

    event_id: str
    timestamp_utc: float
    event_type: str
    actor_identity: str
    decision: str
    input_hash: str
    policy_digest: str
    risk_before: float | None = None
    risk_after: float | None = None
    prev_event_hash: str
    event_hash: str
    hmac: str
    detail: dict[str, Any] = Field(default_factory=dict)


class LedgerVerifyResponse(_Model):
    intact: bool
    events: int
    head_hash: str
    first_broken_index: int | None = None


class LedgerExportResponse(_Model):
    events: list[LedgerEvent]
    count: int


# --------------------------------------------------------------------------- #
# Tenants
# --------------------------------------------------------------------------- #
class TenantCreateRequest(_Model):
    tenant_id: str
    display_name: str | None = None
    quotas: dict[str, Any] | None = None


class TenantInfo(_Model):
    tenant_id: str
    display_name: str | None = None
    created_at: float | None = None
    quotas: dict[str, Any] = Field(default_factory=dict)
    agents: int = 0
    ledger_events: int = 0
    isolated: bool = False
    isolated_at: float | None = None


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #
class PolicyValidateRequest(_Model):
    policy_yaml: str


class PolicyValidateResponse(_Model):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    digest: str | None = None
    bundle: dict[str, Any] | None = None


# --------------------------------------------------------------------------- #
# Control plane state & metrics
# --------------------------------------------------------------------------- #
class ControlPlaneState(_Model):
    tenant: str
    shadow: bool
    halted: bool
    blast_radius: BlastRadiusResponse
    ledger_events: int
    ledger_intact: bool


class MetricsResponse(_Model):
    """Ledger-derived operational metrics (not self-reported counters)."""

    total_actions: int = 0
    authorized: int = 0
    denied: int = 0
    authorization_rate: float = 0.0
    denials_by_stage: dict[str, int] = Field(default_factory=dict)
    unsafe_action_rate: float = 0.0
    tool_failure_rate: float = 0.0
    policy_block_count: int = 0
    ledger_intact: bool = True


class ErrorResponse(_Model):
    error: str
    message: str
    request_id: str | None = None
    details: dict[str, Any] | None = None
