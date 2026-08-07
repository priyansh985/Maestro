"""Pydantic models for MAESTRO SDK request/response types."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AlertClass(str, Enum):
    DOS = "dos"
    ANOMALY = "anomaly"
    PORT_SCAN = "port_scan"
    BRUTEFORCE = "bruteforce"
    NORMAL = "normal"


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertIn(BaseModel):
    cls: AlertClass
    severity: float
    detail: str
    src_ip: str | None = None
    dst_ip: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertOut(BaseModel):
    alert_id: str
    cls: AlertClass
    severity: float
    detail: str
    src_ip: str | None = None
    dst_ip: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    tenant: str


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


class AgentCreateRequest(BaseModel):
    type: AgentType = AgentType.GENERIC
    tenant: str = "default"
    agent_id: str | None = None
    allowed_intents: list[str] | None = None
    shadow: bool = False


class AgentInfo(BaseModel):
    agent_id: str
    tenant: str
    type: AgentType
    status: AgentStatus
    shadow_mode: bool
    capabilities: list[str]
    ledger_events: int
    memory_tiers: dict[str, int]
    created_at: datetime


class AgentListResponse(BaseModel):
    agents: list[AgentInfo]
    total: int


class BlastRadiusResponse(BaseModel):
    agent_id: str
    tenant: str
    capabilities: list[str]
    intent_vocabulary: list[str]
    reversible_intents: list[str]
    irreversible_intents: list[str]
    budget: dict[str, Any]
    holds_irreversible_capability: bool


class PerimeterIn(BaseModel):
    content: str
    source: str = "external"


class VariableOut(BaseModel):
    name: str
    kind: str
    value: str


class SignalOut(BaseModel):
    category: str
    pattern: str
    severity: float
    excerpt: str


class PerimeterResult(BaseModel):
    disposition: str
    trust: str
    injection_score: float
    influential: bool
    admitted: bool
    signals: list[SignalOut]
    variables: list[VariableOut]
    source: str
    reason: str


class CritiqueIn(BaseModel):
    text: str
    grounding: list[str]


class CritiqueOut(BaseModel):
    verdict: str
    judge_scores: dict[str, float]


class HaltResponse(BaseModel):
    halted: bool
    message: str


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


class MemoryRecord(BaseModel):
    record_id: str
    scope: str
    tier: MemoryTier
    trust: TrustLabel
    content: str
    provenance: dict[str, Any]
    attributes: dict[str, Any]
    created_at: float
    expires_at: float | None = None
    content_hash: str
    influential: bool


class MemoryInspectRequest(BaseModel):
    tier: MemoryTier | None = None
    include_untrusted: bool = False
    limit: int = 100


class MemoryInspectResponse(BaseModel):
    records: list[MemoryRecord]
    total: int


class MemoryPromoteRequest(BaseModel):
    record_id: str
    capability: str


class MemoryQuarantineRequest(BaseModel):
    record_id: str


class LedgerEvent(BaseModel):
    event_type: str
    actor_identity: str
    decision: str
    input_hash: str
    policy_digest: str
    detail: dict[str, Any]
    timestamp: float
    prev_hash: str
    seq: int


class LedgerVerifyResponse(BaseModel):
    intact: bool
    events: int
    head_hash: str
    first_broken_index: int | None = None


class LedgerExportResponse(BaseModel):
    events: list[LedgerEvent]
    count: int


class TenantCreateRequest(BaseModel):
    tenant_id: str
    display_name: str | None = None
    quotas: dict[str, Any] | None = None


class TenantInfo(BaseModel):
    tenant_id: str
    display_name: str | None = None
    created_at: datetime
    quotas: dict[str, Any]
    agents: int
    ledger_events: int


class PolicyValidateRequest(BaseModel):
    policy_yaml: str


class PolicyValidateResponse(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ControlPlaneState(BaseModel):
    tenant: str
    shadow: bool
    halted: bool
    blast_radius: BlastRadiusResponse
    ledger_events: int
    ledger_intact: bool


class MetricsResponse(BaseModel):
    total_actions: int
    allowed_actions: int
    denied_actions: int
    ledger_intact: bool
    avg_residual_risk: float
    avg_latency_ms: float


class ErrorResponse(BaseModel):
    error: str
    message: str
    request_id: str | None = None
    details: dict[str, Any] | None = None