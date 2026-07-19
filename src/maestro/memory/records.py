"""Typed records for the four-tier memory architecture (Phase 3).

The blueprint's ⚑ correction to a flat "global memory" is a **four-tier** model
with an explicit *trust* dimension, because the paper's validated TC2 attack
(injecting fake high-severity entries into ``history.json``) is only survivable
if newly ingested content cannot influence behavior until it is *independently*
authorized. Every record therefore carries:

* a :class:`MemoryScope` — the ``(tenant, agent)`` isolation key. Reads and
  writes never cross a scope (the row-level-security analog);
* a :class:`MemoryTier` — working / episodic / semantic / procedural;
* a :class:`TrustLabel` — whether the record may influence the agent. Content
  ingested into episodic memory lands ``UNTRUSTED`` (quarantined) and is
  excluded from recall until promoted; procedural memory is ``SYSTEM`` and
  read-only to the agent.

Records are frozen; a trust change produces a *new* record (via
``dataclasses.replace``), so a record's content hash stays bound to its content.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum

#: Working-tier records expire; keep the session scratch bounded.
DEFAULT_WORKING_TTL_S = 900.0


class MemoryTier(str, Enum):
    WORKING = "working"        # ephemeral per-session scratch (Redis analog)
    EPISODIC = "episodic"      # append-only events; quarantine-on-ingest
    SEMANTIC = "semantic"      # curated knowledge; citation-backed retrieval
    PROCEDURAL = "procedural"  # skills / policies / tools; read-only to the agent


class TrustLabel(str, Enum):
    UNTRUSTED = "untrusted"    # quarantined on ingest; excluded from recall by default
    TRUSTED = "trusted"        # promoted from quarantine via independent authorization
    CURATED = "curated"        # human/system-curated semantic knowledge
    SYSTEM = "system"          # procedural, immutable


#: Trust labels that may influence agent behavior — the set recall surfaces by
#: default. UNTRUSTED (quarantine) is deliberately absent: that is the whole
#: point of quarantine-on-ingest.
INFLUENTIAL_TRUST: frozenset[TrustLabel] = frozenset(
    {TrustLabel.TRUSTED, TrustLabel.CURATED, TrustLabel.SYSTEM})


class MemoryScopeError(ValueError):
    """Raised when a scope is malformed."""


@dataclass(frozen=True)
class MemoryScope:
    """The ``(tenant, agent)`` isolation key. Reads/writes never cross it."""

    tenant: str
    agent: str

    def __post_init__(self) -> None:
        if not self.tenant or not self.agent:
            raise MemoryScopeError("memory scope requires non-empty tenant and agent")

    @property
    def key(self) -> str:
        return f"{self.tenant}/{self.agent}"


@dataclass(frozen=True)
class MemoryRecord:
    """One scoped, trust-labeled memory record."""

    record_id: str
    scope: MemoryScope
    tier: MemoryTier
    trust: TrustLabel
    content: str
    provenance: dict[str, object] = field(default_factory=dict)
    attributes: dict[str, object] = field(default_factory=dict)
    created_at: float = 0.0
    expires_at: float | None = None
    content_hash: str = ""

    def digest(self) -> str:
        """Content hash — binds the record's integrity to its content + scope."""
        payload = json.dumps(
            {
                "scope": self.scope.key,
                "tier": self.tier.value,
                "content": self.content,
                "attributes": self.attributes,
                "created_at": round(self.created_at, 6),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def is_expired(self, now: float | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) >= self.expires_at

    @property
    def influential(self) -> bool:
        """True if this record may influence the agent (is surfaced by recall)."""
        return self.trust in INFLUENTIAL_TRUST

    def as_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "scope": self.scope.key,
            "tier": self.tier.value,
            "trust": self.trust.value,
            "content": self.content,
            "provenance": self.provenance,
            "attributes": self.attributes,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "content_hash": self.content_hash,
        }
