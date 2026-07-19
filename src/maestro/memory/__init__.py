"""Four-tier agent memory with quarantine, promotion, and isolation (Phase 3).

The blueprint's memory corrections, made concrete:

* four tiers — **working** (ephemeral scratch), **episodic** (append-only events,
  quarantine-on-ingest), **semantic** (curated, citation-backed), **procedural**
  (read-only to the agent);
* a **trust** dimension on every record, so newly ingested content cannot
  influence behavior until *independently* authorized — the structural defense
  against the reproduction's TC2 memory-poisoning attack;
* strict **tenant/agent isolation** (the row-level-security analog);
* a **capability-gated promotion pipeline** recorded in the tamper-evident
  ledger.

This package is intentionally separate from ``maestro.agent.memory`` (the
paper's file-backed ``history.json`` episodic store, which TC2 deliberately
poisons): this is the *secure-by-construction* memory the poisoning attack is
designed to survive.
"""
from __future__ import annotations

from .records import (
    DEFAULT_WORKING_TTL_S,
    INFLUENTIAL_TRUST,
    MemoryRecord,
    MemoryScope,
    MemoryScopeError,
    MemoryTier,
    TrustLabel,
)
from .store import (
    CROSS_TENANT_READ_CAPABILITY,
    PROMOTE_CAPABILITY,
    MemoryIsolationError,
    MemoryStore,
    MemoryWriteDenied,
    memory_resource,
)

__all__ = [
    "DEFAULT_WORKING_TTL_S",
    "INFLUENTIAL_TRUST",
    "MemoryRecord",
    "MemoryScope",
    "MemoryScopeError",
    "MemoryTier",
    "TrustLabel",
    "CROSS_TENANT_READ_CAPABILITY",
    "PROMOTE_CAPABILITY",
    "MemoryIsolationError",
    "MemoryStore",
    "MemoryWriteDenied",
    "memory_resource",
]
