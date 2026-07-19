"""Durable execution tests — the exactly-once-across-a-crash guarantee.

These prove the Orchestration Engine's core property: re-running a workflow
after a crash replays completed activities from the journal instead of
re-executing them, so a side effect happens exactly once even across process
death. Plus retries, timeouts, replay-divergence detection, and file-backed
recovery.
"""
from __future__ import annotations

import itertools

import pytest

from maestro.orchestration import (
    ActivityFailed,
    ActivityRecord,
    DurableEngine,
    Journal,
    JournalError,
    NonDeterministicError,
    RetryPolicy,
)

_NO_SLEEP = lambda _s: None  # noqa: E731 - deterministic backoff, no real sleeping


# --------------------------------------------------------------------------- #
# The headline guarantee
# --------------------------------------------------------------------------- #
def test_exactly_once_across_a_crash():
    side_effects: list[str] = []
    crashed = {"yet": False}

    def send_firewall_rule(rule: str) -> dict:
        side_effects.append(rule)                 # the irreversible side effect
        return {"applied": rule}

    def workflow(ctx, _payload):
        out = ctx.activity("send", send_firewall_rule, "block-1.2.3.4")
        if not crashed["yet"]:
            crashed["yet"] = True
            raise RuntimeError("process died mid-workflow")   # crash AFTER the effect
        return {"status": "done", "applied": out}

    engine = DurableEngine()
    with pytest.raises(RuntimeError):
        engine.execute(workflow, "run-1")
    assert side_effects == ["block-1.2.3.4"]      # ran exactly once

    # Crash recovery: same run_id resumes from the journal.
    result = engine.execute(workflow, "run-1")
    assert result == {"status": "done", "applied": {"applied": "block-1.2.3.4"}}
    assert side_effects == ["block-1.2.3.4"]      # NOT re-executed on replay


def test_completed_workflow_returns_its_result():
    def wf(ctx, payload):
        a = ctx.activity("double", lambda x: x * 2, payload)
        return ctx.activity("inc", lambda x: x + 1, a)

    assert DurableEngine().execute(wf, "r", 10) == 21


# --------------------------------------------------------------------------- #
# Retries + timeouts
# --------------------------------------------------------------------------- #
def test_retries_until_success():
    attempts = {"n": 0}

    def flaky() -> dict:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ValueError("transient")
        return {"ok": True}

    def wf(ctx, _):
        return ctx.activity("flaky", flaky,
                            retry=RetryPolicy(max_attempts=5, initial_backoff_s=0.0))

    engine = DurableEngine(sleeper=_NO_SLEEP)
    assert engine.execute(wf, "r") == {"ok": True}
    assert attempts["n"] == 3


def test_terminal_failure_after_exhausting_retries_is_deterministic():
    def always_fail():
        raise ValueError("permanent")

    def wf(ctx, _):
        return ctx.activity("x", always_fail,
                            retry=RetryPolicy(max_attempts=2, initial_backoff_s=0.0))

    engine = DurableEngine(sleeper=_NO_SLEEP)
    with pytest.raises(ActivityFailed):
        engine.execute(wf, "r")
    # The failure is journaled; a re-run replays it rather than re-attempting.
    with pytest.raises(ActivityFailed):
        engine.execute(wf, "r")


def test_timeout_fails_the_activity():
    clock = {"v": 0.0}

    def slow() -> dict:
        clock["v"] += 5.0                 # the activity "took 5 seconds"
        return {"ok": True}

    def wf(ctx, _):
        return ctx.activity("slow", slow, timeout_s=1.0,
                            retry=RetryPolicy(max_attempts=1))

    engine = DurableEngine(clock=lambda: clock["v"], sleeper=_NO_SLEEP)
    with pytest.raises(ActivityFailed):
        engine.execute(wf, "r")


# --------------------------------------------------------------------------- #
# Determinism + journal integrity
# --------------------------------------------------------------------------- #
def test_replay_divergence_is_caught():
    def wf_a(ctx, _):
        ctx.activity("step-a", lambda: {"v": 1})
        raise RuntimeError("crash")

    def wf_b(ctx, _):
        ctx.activity("step-DIFFERENT", lambda: {"v": 2})   # code changed under us
        return "done"

    engine = DurableEngine()
    with pytest.raises(RuntimeError):
        engine.execute(wf_a, "r")
    with pytest.raises(NonDeterministicError):
        engine.execute(wf_b, "r")


def test_now_is_journaled_and_stable_across_replay():
    counter = itertools.count(1.0)
    crashed = {"yet": False}
    seen: dict[str, float] = {}

    def wf(ctx, _):
        seen["t"] = ctx.now()
        if not crashed["yet"]:
            crashed["yet"] = True
            raise RuntimeError("die")
        return seen["t"]

    engine = DurableEngine(clock=lambda: next(counter))
    with pytest.raises(RuntimeError):
        engine.execute(wf, "r")
    first = seen["t"]
    # On replay, now() returns the journaled instant, not a fresh clock read.
    assert engine.execute(wf, "r") == first


def test_journal_is_append_only():
    j = Journal()
    j.record(ActivityRecord("r", 0, "a", "completed", {"x": 1}))
    with pytest.raises(JournalError):
        j.record(ActivityRecord("r", 0, "a", "completed", {"x": 1}))


def test_file_backed_journal_recovers_across_process(tmp_path):
    jpath = tmp_path / "wf.jsonl"
    side: list[str] = []
    crashed = {"yet": False}

    def act() -> dict:
        side.append("x")
        return {"n": 1}

    def wf(ctx, _):
        r = ctx.activity("act", act)
        if not crashed["yet"]:
            crashed["yet"] = True
            raise RuntimeError("die")
        return {"done": True, "r": r}

    # "Process 1" crashes after the activity ran.
    with pytest.raises(RuntimeError):
        DurableEngine(journal=Journal(jpath)).execute(wf, "run")
    assert side == ["x"]

    # "Process 2" — a fresh engine + journal loaded from disk — resumes.
    result = DurableEngine(journal=Journal(jpath)).execute(wf, "run")
    assert result == {"done": True, "r": {"n": 1}}
    assert side == ["x"]                    # activity not re-run — recovered from disk


# --------------------------------------------------------------------------- #
# Integration: a durable agent run does not double-execute a mitigation
# --------------------------------------------------------------------------- #
def test_durable_agent_run_does_not_double_execute_a_mitigation():
    from maestro.platform import AgentPlatform
    from maestro.telemetry.detection import Alert, AlertClass

    platform = AgentPlatform()
    crashed = {"yet": False}

    def mitigate(_payload) -> dict:
        r = platform.handle_alert(Alert(1000.0, AlertClass.DOS, 0.95, "flood"))
        return {"allowed": r.allowed, "decision": r.decision, "action": r.proposed_action}

    def workflow(ctx, _):
        out = ctx.activity("mitigate", mitigate, None)
        if not crashed["yet"]:
            crashed["yet"] = True
            raise RuntimeError("crash after the mitigation executed")
        return out

    engine = DurableEngine()
    with pytest.raises(RuntimeError):
        engine.execute(workflow, "incident-1")
    assert len(platform.ledger) == 1        # the mitigation was recorded once

    out = engine.execute(workflow, "incident-1")
    assert out["allowed"] and out["action"] == "throttle_telemetry"
    # If durability were broken, handle_alert would run again and its idempotency
    # gate would append a *denial*, making this 2. It stays 1 — exactly once.
    assert len(platform.ledger) == 1
