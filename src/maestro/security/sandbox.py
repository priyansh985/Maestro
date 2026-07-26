"""Executor sandbox — confining the side effect at the boundary (L3 / BP4).

The Policy Enforcement Point *authorizes* an action; an allow-listed **adapter**
performs the side effect. Between "authorized" and "recorded" sits the one place
a bug or a compromised adapter could still do harm on the live loop: it could
return unbounded data into the audit trail, claim it touched a resource *other*
than the one the action was authorized for, or block forever. In production this
gap is closed by an OS-level sandbox (gVisor / Firecracker) and a durable
workflow engine (Temporal.io). This module is the **in-process, offline,
deterministic** realization of the two guarantees that do not require the OS to
be honest, wired onto the executor by default:

* **Scope + result confinement (default-on).** The adapter's result must be a
  JSON-serializable ``dict``, must fit a byte budget, and must not claim a
  ``target`` other than the one the proposal was authorized for. Any breach
  fails closed — the action is denied and audited — so a rogue or buggy adapter
  cannot smuggle a different target or an oversized payload past the boundary.
* **Durable exactly-once (mechanism default-on; persistence opt-in).** Execution
  is a journaled activity keyed by the action's idempotency key. If that key is
  already journaled — e.g. the process crashed *after* the side effect but
  *before* recording, then retried — the journaled result is **replayed** and the
  adapter is not called again. With an in-memory journal the guard is
  process-scoped; with a file-backed :class:`~maestro.orchestration.journal.Journal`
  (pass ``journal_path`` to :class:`~maestro.platform.AgentPlatform`) it survives
  a real process death.

**Honest boundary of the claim** (see docs/audit/trust_boundaries.md, TB5): an
in-process wrapper cannot force-kill a runaway thread or truly isolate syscalls.
The optional timeout bounds the *caller's wait* and fails the action closed; it
does not terminate the offending thread, and true host isolation remains the
documented OS-sandbox seam. What is enforced here is real and deterministic —
scope/result confinement and exactly-once replay on the live loop — not a claim
of kernel-level containment.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass

from ..orchestration.journal import ActivityRecord, Journal
from .action import ActionProposal

#: The result of one sandboxed execution: ``(output, replayed)`` where
#: ``replayed`` is True when the output came from the durable journal (the
#: adapter was NOT invoked — exactly-once across a crash).
SandboxOutput = tuple[dict, bool]

#: Journal sequence used for a single-activity "run" keyed by idempotency key.
_SEQ = 0


class SandboxViolation(Exception):
    """The adapter breached the sandbox policy. Always fails closed (deny)."""


@dataclass(frozen=True)
class SandboxPolicy:
    """Deterministic confinement budget applied to every adapter result.

    ``timeout_s <= 0`` runs the adapter inline (no worker thread) — the default,
    which keeps the live loop deterministic and thread-free for the bounded,
    pure stand-in adapters. A positive value bounds the caller's wait (see the
    module docstring for the honest limit of an in-process timeout).
    """

    max_output_bytes: int = 64 * 1024
    timeout_s: float = 0.0


class ExecutionSandbox:
    """Confines an adapter's execution + result at the side-effect boundary."""

    def __init__(
        self,
        *,
        policy: SandboxPolicy | None = None,
        journal: Journal | None = None,
    ) -> None:
        self._policy = policy if policy is not None else SandboxPolicy()
        self._journal = journal

    @property
    def journal(self) -> Journal | None:
        return self._journal

    def run(
        self,
        adapter,  # ToolAdapter; kept untyped to avoid an enforcement import cycle
        proposal: ActionProposal,
        *,
        idempotency_key: str | None = None,
    ) -> SandboxOutput:
        """Execute ``adapter`` under confinement, returning ``(output, replayed)``.

        Raises :class:`SandboxViolation` (fail-closed) on any policy breach. On a
        durable replay the adapter is not invoked and ``replayed`` is True.
        """
        # 1. Durable replay — exactly-once across a crash. A key already in the
        #    journal means a prior process already performed this side effect;
        #    return the recorded result rather than doing it again.
        if idempotency_key is not None and self._journal is not None:
            recorded = self._journal.lookup(idempotency_key, _SEQ)
            if recorded is not None:
                if recorded.status != "completed":
                    raise SandboxViolation(
                        f"prior sandboxed execution failed: {recorded.error}")
                # Re-confine on the way out: the journal is trusted for the fact
                # of execution, but the scope invariant is cheap to reassert.
                return self._confine(recorded.result, proposal), True

        # 2. First execution — run the adapter under the timeout budget.
        output = self._invoke(adapter, proposal)
        confined = self._confine(output, proposal)

        # 3. Journal the confined result so a future retry replays it.
        if idempotency_key is not None and self._journal is not None:
            self._journal.record(ActivityRecord(
                idempotency_key, _SEQ, proposal.intent, "completed", confined, "", 1))
        return confined, False

    # -- internals ----------------------------------------------------------- #
    def _invoke(self, adapter, proposal: ActionProposal) -> object:
        """Run the adapter, optionally bounded by a wall-clock timeout."""
        if self._policy.timeout_s <= 0:
            return adapter(proposal)          # inline: deterministic + thread-free
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(adapter, proposal)
            try:
                return future.result(timeout=self._policy.timeout_s)
            except FuturesTimeout as exc:
                # The thread may keep running (Python cannot kill it) — but its
                # result is discarded and the action fails closed. See docstring.
                raise SandboxViolation(
                    f"adapter for {proposal.intent!r} exceeded "
                    f"{self._policy.timeout_s}s timeout") from exc

    def _confine(self, output: object, proposal: ActionProposal) -> dict:
        """Assert the result is a bounded, in-scope JSON dict, or fail closed."""
        if not isinstance(output, dict):
            raise SandboxViolation(
                f"adapter result is not a dict: {type(output).__name__}")
        try:
            payload = json.dumps(output)
        except (TypeError, ValueError) as exc:
            raise SandboxViolation(f"adapter result is not JSON-serializable: {exc}") from exc
        size = len(payload.encode("utf-8"))
        if size > self._policy.max_output_bytes:
            raise SandboxViolation(
                f"adapter result {size} bytes exceeds "
                f"{self._policy.max_output_bytes}-byte cap")
        # Scope confinement: an adapter may not claim a resource outside the one
        # the proposal was authorized against. (An adapter that reports no target
        # — e.g. noop — is in scope by construction.)
        claimed = output.get("target")
        if claimed is not None and claimed != proposal.target:
            raise SandboxViolation(
                f"adapter claimed target {claimed!r} outside authorized scope "
                f"{proposal.target!r}")
        return output
