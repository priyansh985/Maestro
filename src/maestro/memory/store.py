"""The four-tier memory store — quarantine, promotion, isolation (Phase 3).

:class:`MemoryStore` is the security boundary for agent memory. It encodes the
blueprint's memory corrections as *structure*, not policy prose:

* **Tenant/agent isolation (RLS analog).** Every read and write is scoped; a
  query under one :class:`~maestro.memory.records.MemoryScope` can never see or
  mutate another scope's records. Cross-scope promotion is refused outright.
* **Quarantine-on-ingest.** Anything the agent *remembers* into episodic memory
  lands ``UNTRUSTED`` and is excluded from recall — so the TC2 poisoning attack
  (inject fake high-severity entries) cannot influence behavior. A poisoned
  write sits in quarantine, inert.
* **Independent write authorization.** Promoting a quarantined record to
  ``TRUSTED`` requires a signed, scoped capability (``cap:memory:promote``) —
  the agent cannot launder its own untrusted writes into the trusted set. Every
  promotion is recorded in the tamper-evident ledger.
* **Read-only procedural memory.** The agent's *procedures* (skills, policies,
  tools) are loaded from a privileged, system-trusted bundle and cannot be
  written by the agent — an indirect injection cannot rewrite the agent's own
  operating rules.
* **Curated semantic memory.** Trusted knowledge is written only through
  :meth:`curate` (a privileged path), carrying a citation for grounded recall.

The store builds an ephemeral :class:`~maestro.security.identity.CapabilityIssuer`
and :class:`~maestro.security.ledger.Ledger` if none are supplied, so it runs
offline out of the box; pass shared instances to integrate it with a wider
control plane.
"""
from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable
from dataclasses import replace

from ..security.identity import SIGNING_KEY_ENV, CapabilityIssuer, CapabilityToken
from ..security.ledger import Ledger
from .records import (
    DEFAULT_WORKING_TTL_S,
    MemoryRecord,
    MemoryScope,
    MemoryTier,
    TrustLabel,
)

#: The single capability that authorizes moving a record out of quarantine.
PROMOTE_CAPABILITY = "cap:memory:promote"
#: Cross-tenant memory access has *no autonomous path* — it requires this
#: capability, and every access is audited (blueprint §4.3).
CROSS_TENANT_READ_CAPABILITY = "cap:memory:cross-tenant-read"


class MemoryWriteDenied(Exception):
    """Raised when a write violates a tier's write policy (read-only / curated)."""


class MemoryIsolationError(Exception):
    """Raised when an operation crosses a tenant/agent scope boundary."""


def memory_resource(scope: MemoryScope) -> str:
    """The capability resource scope a promotion token must be bound to."""
    return f"memory:{scope.tenant}"


class MemoryStore:
    """Four-tier, scoped, trust-labeled memory with a promotion pipeline."""

    def __init__(
        self,
        *,
        issuer: CapabilityIssuer | None = None,
        ledger: Ledger | None = None,
        key: bytes | str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved_key = key or os.environ.get(SIGNING_KEY_ENV) or secrets.token_hex(32)
        self._issuer = issuer if issuer is not None else CapabilityIssuer(key=resolved_key)
        self._ledger = ledger if ledger is not None else Ledger(key=resolved_key)
        self._records: dict[str, MemoryRecord] = {}
        self._seq = 0
        self._clock = clock

    # -- introspection ------------------------------------------------------- #
    @property
    def issuer(self) -> CapabilityIssuer:
        return self._issuer

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def _new_id(self, tier: MemoryTier) -> str:
        self._seq += 1
        return f"mem:{tier.value}:{self._seq:06d}"

    def _store(self, record: MemoryRecord) -> MemoryRecord:
        record = replace(record, content_hash=record.digest())
        self._records[record.record_id] = record
        return record

    # -- writes -------------------------------------------------------------- #
    def remember(
        self,
        scope: MemoryScope,
        tier: MemoryTier,
        content: str,
        *,
        source: str = "agent",
        attributes: dict[str, object] | None = None,
        ttl_seconds: float | None = None,
        record_id: str | None = None,
    ) -> MemoryRecord:
        """Agent-facing write. Only working and episodic tiers are writable.

        * ``WORKING``  → ``TRUSTED`` but ephemeral (session scratch, TTL'd).
        * ``EPISODIC`` → ``UNTRUSTED`` **always** — quarantine-on-ingest,
          regardless of what the caller claims. This is the poisoning defense.

        Pass ``record_id`` to record a detection under a *deterministic* id
        (get-or-create): re-ingesting the same detection returns the existing
        record instead of duplicating it, which lets a stable evidence reference
        back the enforcement point's evidence gate. Semantic and procedural
        writes are refused here (see :meth:`curate` and :meth:`load_procedural`).
        """
        if tier is MemoryTier.PROCEDURAL:
            raise MemoryWriteDenied(
                "procedural memory is read-only to the agent; load via load_procedural()")
        if tier is MemoryTier.SEMANTIC:
            raise MemoryWriteDenied(
                "semantic memory accepts curated writes only; use curate()")

        if record_id is not None:
            existing = self._records.get(record_id)
            if existing is not None:
                if existing.scope != scope:
                    raise MemoryIsolationError(
                        "record id belongs to a different scope (cross-tenant/agent write denied)")
                return existing  # idempotent ingest of the same detection

        now = self._clock()
        if tier is MemoryTier.WORKING:
            trust = TrustLabel.TRUSTED
            expires: float | None = now + (ttl_seconds or DEFAULT_WORKING_TTL_S)
        else:  # EPISODIC — quarantine on ingest, no exceptions.
            trust = TrustLabel.UNTRUSTED
            expires = None

        return self._store(MemoryRecord(
            record_id=record_id if record_id is not None else self._new_id(tier),
            scope=scope,
            tier=tier,
            trust=trust,
            content=content,
            provenance={"source": source, "ingested_at": now},
            attributes=attributes or {},
            created_at=now,
            expires_at=expires,
        ))

    def curate(
        self,
        scope: MemoryScope,
        content: str,
        *,
        source: str,
        citation: str | None = None,
        attributes: dict[str, object] | None = None,
    ) -> MemoryRecord:
        """Privileged semantic write — trusted knowledge with a citation.

        Represents human/system curation (a knowledge-base ingest that has
        already cleared review). The ``citation`` is surfaced by
        :meth:`citations` so grounded answers can attribute their sources.
        """
        now = self._clock()
        provenance: dict[str, object] = {"source": source, "curated_at": now}
        if citation:
            provenance["citation"] = citation
        return self._store(MemoryRecord(
            record_id=self._new_id(MemoryTier.SEMANTIC),
            scope=scope,
            tier=MemoryTier.SEMANTIC,
            trust=TrustLabel.CURATED,
            content=content,
            provenance=provenance,
            attributes=attributes or {},
            created_at=now,
        ))

    def load_procedural(
        self,
        scope: MemoryScope,
        content: str,
        *,
        source: str,
        attributes: dict[str, object] | None = None,
    ) -> MemoryRecord:
        """Privileged, system-trusted load of a procedural record (read-only).

        Procedural memory is changed *only* here (the governed policy pipeline),
        never through :meth:`remember`. This is what stops an injection from
        rewriting the agent's own skills/policies.
        """
        now = self._clock()
        return self._store(MemoryRecord(
            record_id=self._new_id(MemoryTier.PROCEDURAL),
            scope=scope,
            tier=MemoryTier.PROCEDURAL,
            trust=TrustLabel.SYSTEM,
            content=content,
            provenance={"source": source, "loaded_at": now},
            attributes=attributes or {},
            created_at=now,
        ))

    # -- reads --------------------------------------------------------------- #
    def recall(
        self,
        scope: MemoryScope,
        *,
        tier: MemoryTier | None = None,
        include_untrusted: bool = False,
        query: str | None = None,
        limit: int | None = None,
        now: float | None = None,
    ) -> list[MemoryRecord]:
        """Return scope-matched, non-expired records, oldest first.

        By default only *influential* records (trusted/curated/system) are
        returned — quarantined content is excluded so it cannot influence the
        agent. Pass ``include_untrusted=True`` to inspect quarantine explicitly.
        """
        at = now if now is not None else self._clock()
        out: list[MemoryRecord] = []
        for record in self._records.values():
            if record.scope != scope:                    # strict isolation
                continue
            if tier is not None and record.tier is not tier:
                continue
            if record.is_expired(at):
                continue
            if not include_untrusted and not record.influential:
                continue
            if query is not None and query.lower() not in record.content.lower():
                continue
            out.append(record)
        out.sort(key=lambda r: r.created_at)
        return out[:limit] if limit is not None else out

    def quarantined(
        self, scope: MemoryScope, *, tier: MemoryTier = MemoryTier.EPISODIC
    ) -> list[MemoryRecord]:
        """The untrusted (quarantined) records awaiting promotion for a scope."""
        return [
            r for r in self._records.values()
            if r.scope == scope and r.tier is tier and r.trust is TrustLabel.UNTRUSTED
        ]

    def get(self, record_id: str, scope: MemoryScope) -> MemoryRecord:
        """Fetch a single record, enforcing scope isolation."""
        record = self._records.get(record_id)
        if record is None:
            raise MemoryIsolationError(f"no such record {record_id!r}")
        if record.scope != scope:
            raise MemoryIsolationError(
                "record belongs to a different scope (cross-tenant/agent read denied)")
        return record

    def exists(self, record_id: str, scope: MemoryScope) -> bool:
        """True iff a record with this id exists *in this scope* (isolation-aware).

        The evidence gate uses this to resolve an action's evidence reference:
        existence proves the citation is real (anti-hallucination), independent
        of the record's *trust* — a quarantined detection is still real evidence.
        """
        record = self._records.get(record_id)
        return record is not None and record.scope == scope

    def recall_cross_scope(
        self,
        target_scope: MemoryScope,
        *,
        token: CapabilityToken,
        tier: MemoryTier | None = None,
        now: float | None = None,
    ) -> list[MemoryRecord]:
        """Read *another* scope's influential records — only under a capability.

        The blueprint's §4.3 rule: cross-tenant access has no autonomous path.
        There is no way to obtain another scope's memory except by presenting a
        valid ``cap:memory:cross-tenant-read`` bound to the target, and every
        such access is recorded in the tamper-evident ledger (cross-tenant reads
        are exactly the events an auditor needs to see). Fails closed.
        """
        at = now if now is not None else self._clock()
        self._issuer.verify(
            token,
            capability=CROSS_TENANT_READ_CAPABILITY,
            resource_constraint=memory_resource(target_scope),
            tenant=target_scope.tenant,
            now=at,
        )
        records = self.recall(target_scope, tier=tier, now=at)
        self._ledger.append(
            event_type="cross_tenant_memory_read",
            actor_identity=token.subject,
            decision="allow",
            input_hash="",
            policy_digest=CROSS_TENANT_READ_CAPABILITY,
            detail={"target_scope": target_scope.key, "records_returned": len(records)},
        )
        return records

    @staticmethod
    def citations(records: list[MemoryRecord]) -> list[str]:
        """Citation strings for a recall result (for citation-backed grounding)."""
        cites: list[str] = []
        for r in records:
            cite = r.provenance.get("citation") or r.provenance.get("source")
            if isinstance(cite, str) and cite:
                cites.append(cite)
        return cites

    # -- promotion (the independent write authorization) --------------------- #
    def promote(
        self,
        record_id: str,
        scope: MemoryScope,
        *,
        token: CapabilityToken,
        now: float | None = None,
    ) -> MemoryRecord:
        """Move a quarantined record to ``TRUSTED`` under a scoped capability.

        Fails closed unless:
        * the record exists and belongs to ``scope`` (no cross-scope promotion);
        * ``token`` is an authentic, unexpired ``cap:memory:promote`` bound to
          this scope's tenant and memory resource;
        * the record is actually quarantined (``UNTRUSTED``).

        On success the record is re-labeled, provenance records who promoted it,
        and the promotion is appended to the tamper-evident ledger.
        """
        at = now if now is not None else self._clock()
        record = self.get(record_id, scope)              # scope isolation first
        # Independent authorization — the agent cannot self-promote its own
        # untrusted writes without a delegated capability.
        self._issuer.verify(
            token,
            capability=PROMOTE_CAPABILITY,
            resource_constraint=memory_resource(scope),
            tenant=scope.tenant,
            now=at,
        )
        if record.trust is not TrustLabel.UNTRUSTED:
            raise MemoryWriteDenied(
                f"record is {record.trust.value}; only quarantined records are promoted")

        promoted = replace(
            record,
            trust=TrustLabel.TRUSTED,
            provenance={**record.provenance, "promoted_by": token.subject, "promoted_at": at},
        )
        self._records[record_id] = self._store(promoted)
        self._ledger.append(
            event_type="memory_promotion",
            actor_identity=token.subject,
            decision="promote",
            input_hash=record.content_hash,
            policy_digest=PROMOTE_CAPABILITY,
            detail={"record_id": record_id, "scope": scope.key, "tier": record.tier.value},
        )
        return self._records[record_id]
