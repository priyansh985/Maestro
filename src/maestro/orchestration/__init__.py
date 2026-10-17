"""Durable execution — the Orchestration Engine (blueprint §2).

An offline, deterministic, stdlib realization of the durable-workflow semantics
Temporal.io provides in production: an event-sourced :class:`Journal`, a
:class:`DurableEngine` that replays completed activities after a crash so side
effects are **exactly-once**, and a :class:`RetryPolicy` for bounded activity
retries. It pairs with the enforcement point's idempotency keys — durable retry
and exactly-once execution are two halves of the same guarantee.
"""
from __future__ import annotations

from .engine import (
    DEFAULT_RETRY,
    ActivityFailed,
    DurableEngine,
    NonDeterministicError,
    RetryPolicy,
    Workflow,
    WorkflowContext,
)
from .journal import ActivityRecord, Journal, JournalError

try:
    from .temporal_backend import (
        TemporalConfig,
        TemporalJournal,
        TemporalNotAvailableError,
        create_temporal_journal,
        load_temporal_config,
    )
    _TEMPORAL_AVAILABLE = True
except ImportError:
    _TEMPORAL_AVAILABLE = False

__all__ = [
    "DEFAULT_RETRY",
    "ActivityFailed",
    "ActivityRecord",
    "DurableEngine",
    "Journal",
    "JournalError",
    "NonDeterministicError",
    "RetryPolicy",
    "Workflow",
    "WorkflowContext",
]

if _TEMPORAL_AVAILABLE:
    __all__ += [
        "TemporalConfig",
        "TemporalJournal",
        "TemporalNotAvailableError",
        "create_temporal_journal",
        "load_temporal_config",
    ]
