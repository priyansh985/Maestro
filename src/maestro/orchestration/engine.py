"""Durable execution engine — offline Temporal-semantics (the Orchestration Engine).

An agent run is long-lived, does external I/O, and must survive a crash *without
re-executing side effects*. Temporal.io provides this in production; this module
provides the same **semantics** offline and deterministically:

* **Event-sourced replay.** A workflow is a deterministic function of its input
  and its journaled activity results. Re-running it after a crash replays
  completed activities from the :class:`~maestro.orchestration.journal.Journal`
  rather than re-executing them — so a side effect (a firewall rule, a payment)
  happens **exactly once** across the crash.
* **Activities carry the non-determinism.** All I/O, time, and randomness live
  in activities (``ctx.activity(...)`` / ``ctx.now()``); workflow code stays
  deterministic, or replay is meaningless. A divergence at replay is caught
  (:class:`NonDeterministicError`), not silently tolerated.
* **Retries with backoff** on activity failure, bounded by a
  :class:`RetryPolicy`.
* **Timeouts.** An activity that runs past its budget fails and retries.

**Practitioner caveat (stated honestly):** a timeout retries the activity, and a
timeout cannot prove the activity did *not* complete — so retried/timed-out
activities must be **idempotent**. That is exactly why the enforcement point
carries idempotency keys: durable retry and exactly-once side effects are two
halves of the same guarantee.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from .journal import ActivityRecord, Journal

#: Type of a workflow: ``(ctx, payload) -> result``.
Workflow = Callable[["WorkflowContext", object], object]


class ActivityFailed(Exception):
    """Raised when an activity exhausts its retries (terminal failure)."""


class NonDeterministicError(Exception):
    """Raised when workflow replay diverges from the journaled history."""


class _ActivityTimeout(Exception):
    """Internal: an activity ran past its timeout budget (retryable)."""


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded exponential backoff for activity retries."""

    max_attempts: int = 3
    initial_backoff_s: float = 0.1
    backoff_multiplier: float = 2.0
    max_backoff_s: float = 30.0

    def backoff(self, attempt: int) -> float:
        """Backoff before the ``attempt``-th retry (1-indexed)."""
        delay = self.initial_backoff_s * (self.backoff_multiplier ** (attempt - 1))
        return min(delay, self.max_backoff_s)


DEFAULT_RETRY = RetryPolicy()


class WorkflowContext:
    """Handed to a workflow; the only way to run activities durably.

    Activities are identified by the deterministic order in which the workflow
    schedules them (a monotonic sequence number). That is why the workflow must
    schedule the same activities in the same order on replay.
    """

    def __init__(
        self,
        run_id: str,
        journal: Journal,
        *,
        clock: Callable[[], float],
        sleeper: Callable[[float], None],
        default_retry: RetryPolicy,
    ) -> None:
        self.run_id = run_id
        self._journal = journal
        self._clock = clock
        self._sleeper = sleeper
        self._default_retry = default_retry
        self._seq = -1

    def now(self) -> float:
        """A journaled timestamp — deterministic across replay (unlike ``time``)."""
        return float(self.activity("__now__", self._clock))  # type: ignore[arg-type]

    def activity(
        self,
        name: str,
        fn: Callable[..., object],
        *args: object,
        retry: RetryPolicy | None = None,
        timeout_s: float | None = None,
        **kwargs: object,
    ) -> object:
        """Run ``fn`` durably: replay its result if already recorded, else execute.

        On first execution the result is journaled (exactly-once); on replay the
        journaled result is returned and ``fn`` is never called again.
        """
        self._seq += 1
        seq = self._seq

        recorded = self._journal.lookup(self.run_id, seq)
        if recorded is not None:
            # Replay path — never re-execute. Guard against code that changed
            # under a running workflow (the classic durable-execution footgun).
            if recorded.name != name:
                raise NonDeterministicError(
                    f"replay diverged at seq {seq}: journal has {recorded.name!r}, "
                    f"workflow scheduled {name!r}")
            if recorded.status == "failed":
                raise ActivityFailed(f"activity {name!r} previously failed: {recorded.error}")
            return recorded.result

        policy = retry or self._default_retry
        attempt = 0
        while True:
            attempt += 1
            started = self._clock()
            try:
                result = fn(*args, **kwargs)
                elapsed = self._clock() - started
                if timeout_s is not None and elapsed > timeout_s:
                    raise _ActivityTimeout(
                        f"activity {name!r} exceeded timeout {timeout_s}s (took {elapsed}s)")
            except Exception as exc:  # noqa: BLE001 - retry/terminal boundary
                if attempt >= policy.max_attempts:
                    self._journal.record(ActivityRecord(
                        self.run_id, seq, name, "failed", None, str(exc), attempt))
                    raise ActivityFailed(
                        f"activity {name!r} failed after {attempt} attempt(s): {exc}") from exc
                self._sleeper(policy.backoff(attempt))
                continue
            self._journal.record(ActivityRecord(
                self.run_id, seq, name, "completed", result, "", attempt))
            return result


class DurableEngine:
    """Runs workflows to completion with replay-based crash recovery."""

    def __init__(
        self,
        *,
        journal: Journal | None = None,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
        retry: RetryPolicy = DEFAULT_RETRY,
    ) -> None:
        self._journal = journal if journal is not None else Journal()
        self._clock = clock
        self._sleeper = sleeper
        self._retry = retry

    @property
    def journal(self) -> Journal:
        return self._journal

    def execute(self, workflow: Workflow, run_id: str, payload: object = None) -> object:
        """Run (or resume) ``workflow`` under ``run_id``.

        Calling this again with the same ``run_id`` after a crash resumes from
        the journal: completed activities replay, the workflow continues from
        where it stopped. This is the entire point — it is safe to retry.
        """
        ctx = WorkflowContext(
            run_id, self._journal,
            clock=self._clock, sleeper=self._sleeper, default_retry=self._retry)
        return workflow(ctx, payload)
