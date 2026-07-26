"""Executor sandbox tests (BP4) — scope/output confinement + durable exactly-once.

These prove the two guarantees the sandbox adds at the side-effect boundary:
a rogue or buggy adapter cannot smuggle an out-of-scope target or an oversized
payload past the executor (it fails closed), and a journaled execution is
replayed exactly-once across a simulated crash rather than re-run.
"""
from __future__ import annotations

import time

import pytest

from maestro.orchestration.journal import ActivityRecord, Journal
from maestro.security.action import ActionProposal
from maestro.security.sandbox import ExecutionSandbox, SandboxPolicy, SandboxViolation


def _proposal(intent: str = "throttle_telemetry", target: str = "telemetry:ws-stream") -> ActionProposal:
    return ActionProposal(
        intent=intent,
        target=target,
        reason="test",
        evidence_ids=("e1",),
        requested_ttl_seconds=900,
    )


# --- scope + output confinement -------------------------------------------- #
def test_in_scope_result_passes_through() -> None:
    sb = ExecutionSandbox()
    out, replayed = sb.run(
        lambda p: {"ok": True, "effect": "throttled", "target": p.target}, _proposal())
    assert out["ok"] is True and replayed is False


def test_adapter_claiming_a_different_target_is_denied() -> None:
    sb = ExecutionSandbox()
    rogue = lambda p: {"ok": True, "target": "telemetry:OTHER-stream"}  # noqa: E731
    with pytest.raises(SandboxViolation, match="outside authorized scope"):
        sb.run(rogue, _proposal())


def test_adapter_with_no_target_is_in_scope_by_construction() -> None:
    sb = ExecutionSandbox()
    out, _ = sb.run(lambda p: {"ok": True, "effect": "no-op"}, _proposal("noop", "agent:self"))
    assert out["ok"] is True


def test_non_dict_result_is_denied() -> None:
    sb = ExecutionSandbox()
    with pytest.raises(SandboxViolation, match="not a dict"):
        sb.run(lambda p: "just a string", _proposal())  # type: ignore[arg-type,return-value]


def test_oversized_result_is_denied() -> None:
    sb = ExecutionSandbox(policy=SandboxPolicy(max_output_bytes=128))
    fat = lambda p: {"ok": True, "blob": "x" * 1000}  # noqa: E731
    with pytest.raises(SandboxViolation, match="exceeds"):
        sb.run(fat, _proposal())


def test_non_serializable_result_is_denied() -> None:
    sb = ExecutionSandbox()
    with pytest.raises(SandboxViolation, match="not JSON-serializable"):
        sb.run(lambda p: {"ok": True, "obj": object()}, _proposal())


# --- timeout (opt-in) ------------------------------------------------------- #
def test_timeout_fails_closed() -> None:
    sb = ExecutionSandbox(policy=SandboxPolicy(timeout_s=0.05))

    def slow(_p: ActionProposal) -> dict:
        time.sleep(0.5)
        return {"ok": True}

    with pytest.raises(SandboxViolation, match="timeout"):
        sb.run(slow, _proposal())


# --- durable exactly-once --------------------------------------------------- #
def test_journaled_result_replays_without_reinvoking_the_adapter() -> None:
    journal = Journal()
    calls = {"n": 0}

    def adapter(p: ActionProposal) -> dict:
        calls["n"] += 1
        return {"ok": True, "target": p.target}

    sb = ExecutionSandbox(journal=journal)
    out1, replayed1 = sb.run(adapter, _proposal(), idempotency_key="k1")
    assert replayed1 is False and calls["n"] == 1

    # A fresh sandbox over the SAME journal (simulating a new process) replays.
    sb2 = ExecutionSandbox(journal=journal)
    out2, replayed2 = sb2.run(adapter, _proposal(), idempotency_key="k1")
    assert replayed2 is True and out2 == out1
    assert calls["n"] == 1                       # adapter NOT re-invoked


def test_file_backed_journal_replays_across_a_simulated_restart(tmp_path) -> None:
    jpath = tmp_path / "sandbox.jsonl"
    side: list[str] = []

    def adapter(p: ActionProposal) -> dict:
        side.append(p.target)                    # the irreversible side effect
        return {"ok": True, "target": p.target}

    # "Process 1" executes once and journals to disk.
    ExecutionSandbox(journal=Journal(jpath)).run(adapter, _proposal(), idempotency_key="inc-1")
    assert side == ["telemetry:ws-stream"]

    # "Process 2" — fresh sandbox + journal reloaded from disk — replays.
    out, replayed = ExecutionSandbox(journal=Journal(jpath)).run(
        adapter, _proposal(), idempotency_key="inc-1")
    assert replayed is True
    assert side == ["telemetry:ws-stream"]       # NOT executed a second time


def test_a_previously_failed_journaled_activity_fails_closed() -> None:
    journal = Journal()
    journal.record(ActivityRecord("k-bad", 0, "throttle_telemetry", "failed", None, "boom", 1))
    sb = ExecutionSandbox(journal=journal)
    with pytest.raises(SandboxViolation, match="prior sandboxed execution failed"):
        sb.run(lambda p: {"ok": True}, _proposal(), idempotency_key="k-bad")
