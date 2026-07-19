"""Tamper-evident audit ledger (Enforcement Plane / L5).

Replaces the stubbed ``forensic_logging`` with an append-only event log where
each record is chained to the previous one's hash and carries an HMAC over its
own content. This gives the property the research calls for: you can *detect*
deletion, insertion, or modification of any event and reconstruct the decision
chain — "we logged it" is not enough, the log must be non-repudiable.

Chaining:  ``event_hash = sha256(canonical(fields) + prev_event_hash)``
Signing:   ``hmac = HMAC-SHA256(key, event_hash)``

:func:`Ledger.verify_chain` recomputes both and returns the index of the first
broken link (``-1`` == intact). The HMAC key lives outside the agent process
(``MAESTRO_SIGNING_KEY``); an attacker who can edit the log file still cannot
forge a valid HMAC without it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .identity import _load_key

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp_utc: float
    event_type: str
    actor_identity: str
    decision: str
    input_hash: str
    policy_digest: str
    risk_before: float
    risk_after: float
    prev_event_hash: str
    event_hash: str = ""
    hmac: str = ""
    detail: dict[str, object] = field(default_factory=dict)

    def _signed_fields(self) -> dict[str, object]:
        """Everything except the derived ``event_hash`` / ``hmac``."""
        d = asdict(self)
        d.pop("event_hash")
        d.pop("hmac")
        return d

    def compute_hash(self) -> str:
        payload = json.dumps(
            self._signed_fields(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload + self.prev_event_hash.encode("utf-8")).hexdigest()


class Ledger:
    """An append-only, hash-chained, HMAC-signed audit ledger.

    Backed by a JSONL file when ``path`` is given (each line is one event);
    purely in-memory otherwise. Appends are atomic per event.
    """

    def __init__(self, path: str | Path | None = None, *, key: bytes | str | None = None) -> None:
        self._key = _load_key(key)
        self._path = Path(path) if path is not None else None
        self._events: list[AuditEvent] = []
        if self._path is not None and self._path.exists():
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                self._events.append(AuditEvent(**json.loads(line)))

    @property
    def head_hash(self) -> str:
        return self._events[-1].event_hash if self._events else GENESIS_HASH

    def append(
        self,
        *,
        event_type: str,
        actor_identity: str,
        decision: str,
        input_hash: str,
        policy_digest: str = "",
        risk_before: float = 0.0,
        risk_after: float = 0.0,
        detail: dict[str, object] | None = None,
    ) -> AuditEvent:
        base = AuditEvent(
            event_id="evt-" + uuid.uuid4().hex[:16],
            timestamp_utc=time.time(),
            event_type=event_type,
            actor_identity=actor_identity,
            decision=decision,
            input_hash=input_hash,
            policy_digest=policy_digest,
            risk_before=round(risk_before, 4),
            risk_after=round(risk_after, 4),
            prev_event_hash=self.head_hash,
            detail=detail or {},
        )
        event_hash = base.compute_hash()
        signature = hmac.new(self._key, event_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        event = AuditEvent(**{**asdict(base), "event_hash": event_hash, "hmac": signature})
        self._events.append(event)
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")
        return event

    def verify_chain(self) -> int:
        """Return the index of the first tampered/broken event, or ``-1`` if intact."""
        prev = GENESIS_HASH
        for i, ev in enumerate(self._events):
            if ev.prev_event_hash != prev:
                return i
            if ev.compute_hash() != ev.event_hash:
                return i
            expected = hmac.new(
                self._key, ev.event_hash.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, ev.hmac):
                return i
            prev = ev.event_hash
        return -1

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def __len__(self) -> int:
        return len(self._events)
