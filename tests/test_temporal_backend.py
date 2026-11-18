"""Temporal backend tests — mocked client only, no live Temporal server.

These exercise the first concrete step of roadmap item 2: the journal must read
activity outcomes from Temporal workflow *history* (``get_workflow_handle(...)
.fetch_history()``), not from a private in-memory cache. A minimal fake
``temporalio`` package is injected so the workflow/activity definitions can be
imported without installing the optional dependency; no server is contacted.

``NOT_RUN`` honesty: this module never exercises a real Temporal server.
"""
from __future__ import annotations

import importlib
import json
import sys
import types
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from maestro.orchestration.engine import DurableEngine
from maestro.orchestration.journal import ActivityRecord

_MODULE = "maestro.orchestration.temporal_backend"
_MISSING = object()

_FAKE_NAMES = (
    "temporalio",
    "temporalio.activity",
    "temporalio.client",
    "temporalio.workflow",
    "temporalio.common",
)


def _fake_temporalio() -> dict[str, types.ModuleType]:
    """A tiny stand-in for the optional ``temporalio`` package."""
    package = types.ModuleType("temporalio")
    activity = types.ModuleType("temporalio.activity")
    client = types.ModuleType("temporalio.client")
    workflow = types.ModuleType("temporalio.workflow")
    common = types.ModuleType("temporalio.common")

    def passthrough(obj: Any) -> Any:
        return obj

    activity.defn = passthrough  # type: ignore[attr-defined]
    workflow.defn = passthrough  # type: ignore[attr-defined]
    workflow.run = passthrough  # type: ignore[attr-defined]

    class Client:  # noqa: D101 - test double
        @staticmethod
        async def connect(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("connect() must not be called with a supplied client")

    client.Client = Client  # type: ignore[attr-defined]

    @dataclass
    class RetryPolicy:  # noqa: D101 - test double
        initial_interval: Any = None
        backoff_coefficient: float = 1.0
        maximum_interval: Any = None
        maximum_attempts: int = 0

    common.RetryPolicy = RetryPolicy  # type: ignore[attr-defined]

    async def execute_activity(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("execute_activity must be replaced by each test")

    workflow.execute_activity = execute_activity  # type: ignore[attr-defined]

    package.activity = activity  # type: ignore[attr-defined]
    package.client = client  # type: ignore[attr-defined]
    package.workflow = workflow  # type: ignore[attr-defined]
    package.common = common  # type: ignore[attr-defined]
    return {
        "temporalio": package,
        "temporalio.activity": activity,
        "temporalio.client": client,
        "temporalio.workflow": workflow,
        "temporalio.common": common,
    }


@pytest.fixture()
def temporal_backend() -> Any:
    """Reload the backend against a fake temporalio, then fully restore state."""
    saved = {name: sys.modules.get(name, _MISSING) for name in _FAKE_NAMES}
    fakes = _fake_temporalio()
    try:
        sys.modules.update(fakes)
        module = importlib.reload(importlib.import_module(_MODULE))
        yield module, fakes
    finally:
        for name, original in saved.items():
            if original is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original  # type: ignore[assignment]
        importlib.reload(importlib.import_module(_MODULE))


@pytest.fixture()
def backend_without_temporalio() -> Any:
    """Reload the backend with temporalio unavailable (None blocks imports)."""
    saved = {name: sys.modules.get(name, _MISSING) for name in _FAKE_NAMES}
    try:
        for name in _FAKE_NAMES:
            sys.modules[name] = None  # type: ignore[assignment]
        yield importlib.reload(importlib.import_module(_MODULE))
    finally:
        for name, original in saved.items():
            if original is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original  # type: ignore[assignment]
        importlib.reload(importlib.import_module(_MODULE))


# --------------------------------------------------------------------------- #
# Fake Temporal history / client
# --------------------------------------------------------------------------- #
def _scheduled(event_id: int, name: str, idempotency_key: str | None = None) -> Any:
    fields: dict[str, Any] = {}
    if idempotency_key is not None:
        fields["idempotency_key"] = SimpleNamespace(data=json.dumps(idempotency_key).encode())
    return SimpleNamespace(
        event_id=event_id,
        activity_task_scheduled_event_attributes=SimpleNamespace(
            activity_id=str(event_id),
            activity_type=SimpleNamespace(name=name),
            header=SimpleNamespace(fields=fields),
        ),
    )


def _completed(event_id: int, scheduled_event_id: int, result: Any) -> Any:
    return SimpleNamespace(
        event_id=event_id,
        activity_task_completed_event_attributes=SimpleNamespace(
            scheduled_event_id=scheduled_event_id,
            result=SimpleNamespace(payloads=[SimpleNamespace(data=json.dumps(result).encode())]),
        ),
    )


def _failed(event_id: int, scheduled_event_id: int, message: str) -> Any:
    return SimpleNamespace(
        event_id=event_id,
        activity_task_failed_event_attributes=SimpleNamespace(
            scheduled_event_id=scheduled_event_id,
            failure=SimpleNamespace(message=message),
        ),
    )


class _FakeHandle:
    def __init__(self, events: list[Any]) -> None:
        self._events = events

    async def fetch_history(self) -> Any:
        return SimpleNamespace(events=self._events)


class _FakeClient:
    def __init__(self, events: list[Any]) -> None:
        self._events = events
        self.handles: list[Any] = []

    def get_workflow_handle(self, workflow_id: str | None = None, **_kwargs: Any) -> _FakeHandle:
        self.handles.append(workflow_id)
        return _FakeHandle(self._events)


def _history_with_one_completed_activity() -> list[Any]:
    return [
        _scheduled(1, "send"),
        _completed(2, 1, {"applied": True}),
    ]


# --------------------------------------------------------------------------- #
# Workflow replay — history, not the private cache, is the source of truth
# --------------------------------------------------------------------------- #
async def test_sync_from_temporal_replays_history_into_journal(temporal_backend: Any) -> None:
    module, _ = temporal_backend
    events = [
        _scheduled(1, "send"),
        _completed(2, 1, {"applied": "rule"}),
        _scheduled(3, "verify"),
        _completed(4, 3, {"verified": True}),
    ]
    client = _FakeClient(events)
    journal = module.TemporalJournal(module.TemporalConfig(), client=client)

    assert await journal.sync_from_temporal("run-1") == 2
    assert client.handles == ["run-1"]  # get_workflow_handle(workflow_id=run_id)

    first = journal.lookup("run-1", 0)
    assert first == ActivityRecord("run-1", 0, "send", "completed", {"applied": "rule"}, "", 1)
    second = journal.lookup("run-1", 1)
    assert second is not None and second.name == "verify"
    assert second.result == {"verified": True}


async def test_replay_after_crash_does_not_reexecute_activity(temporal_backend: Any) -> None:
    module, _ = temporal_backend
    client = _FakeClient(_history_with_one_completed_activity())
    config = module.TemporalConfig()
    side_effects: list[str] = []
    crashed = {"yet": False}

    def send(rule: str) -> dict:
        side_effects.append(rule)
        return {"applied": True}

    def workflow(ctx: Any, _payload: Any) -> Any:
        result = ctx.activity("send", send, "block-rule")
        if not crashed["yet"]:
            crashed["yet"] = True
            raise RuntimeError("process died after the side effect")
        return {"result": result}

    # Process 1: the activity runs, the process dies before the workflow returns.
    with pytest.raises(RuntimeError, match="process died"):
        DurableEngine(journal=module.TemporalJournal(config, client=client)).execute(
            workflow, "run-2"
        )
    assert side_effects == ["block-rule"]

    # Process 2: a *fresh* journal has an empty cache; history must restore it.
    replay_journal = module.TemporalJournal(config, client=client)
    assert await replay_journal.sync_from_temporal("run-2") == 1
    result = DurableEngine(journal=replay_journal).execute(workflow, "run-2")

    assert result == {"result": {"applied": True}}
    assert side_effects == ["block-rule"]  # replayed, never re-executed


async def test_history_failure_becomes_a_failed_record(temporal_backend: Any) -> None:
    module, _ = temporal_backend
    events = [_scheduled(1, "send"), _failed(2, 1, "adapter exploded")]
    journal = module.TemporalJournal(module.TemporalConfig(), client=_FakeClient(events))

    assert await journal.sync_from_temporal("run-fail") == 1
    assert journal.is_complete("run-fail") is True
    rec = journal.lookup("run-fail", 0)
    assert rec is not None and rec.status == "failed"
    assert rec.error == "adapter exploded"


# --------------------------------------------------------------------------- #
# Idempotency key dedupe — duplicate history events collapse to one outcome
# --------------------------------------------------------------------------- #
async def test_idempotency_key_dedupes_duplicate_history_events(temporal_backend: Any) -> None:
    module, _ = temporal_backend
    events = [
        _scheduled(1, "send", idempotency_key="side-effect-once"),
        _completed(2, 1, {"applied": True}),
        _scheduled(3, "send", idempotency_key="side-effect-once"),
        _completed(4, 3, {"applied": True}),
    ]
    journal = module.TemporalJournal(module.TemporalConfig(), client=_FakeClient(events))

    assert await journal.sync_from_temporal("run-3") == 1
    assert journal.records_for("run-3") == [
        ActivityRecord("run-3", 0, "send", "completed", {"applied": True}, "", 1)
    ]
    assert len(journal) == 1


async def test_resync_is_idempotent_append_only(temporal_backend: Any) -> None:
    module, _ = temporal_backend
    journal = module.TemporalJournal(
        module.TemporalConfig(), client=_FakeClient(_history_with_one_completed_activity())
    )

    assert await journal.sync_from_temporal("run-4") == 1
    assert await journal.sync_from_temporal("run-4") == 0  # no duplicates on re-sync
    assert len(journal) == 1


# --------------------------------------------------------------------------- #
# Workflow: activity retry policy + compensation on failure
# --------------------------------------------------------------------------- #
def _action_input() -> dict:
    return {
        "proposal": {"id": "proposal-1"},
        "sandbox_config": {},
        "adapter_module": "adapters.example",
        "adapter_name": "apply",
        "compensation_config": {"mode": "undo"},
        "verifier_config": {},
    }


async def test_activity_retry_policy_and_compensation_on_failure(temporal_backend: Any) -> None:
    module, fake = temporal_backend
    calls: list[dict] = []

    async def dispatch(activity: Any, *, args: Any, start_to_close_timeout: Any,
                       retry_policy: Any = None, **_kwargs: Any) -> Any:
        calls.append({
            "name": activity.__name__,
            "args": args,
            "retry_policy": retry_policy,
            "timeout": start_to_close_timeout,
        })
        if activity is module.execute_adapter_activity:
            raise RuntimeError("adapter exploded")
        if activity is module.compensate_activity:
            return {"undone": True}
        raise AssertionError(f"unexpected activity {activity}")

    fake["temporalio.workflow"].execute_activity = dispatch
    result = await module.ActionWorkflow().execute(_action_input())

    assert result["status"] == "compensated"
    assert result["error"] == "adapter exploded"
    assert result["compensation_result"] == {"undone": True}

    adapter_call, compensation_call = calls[0], calls[-1]
    assert adapter_call["name"] == "execute_adapter_activity"
    assert adapter_call["retry_policy"].maximum_attempts == 3
    assert adapter_call["retry_policy"].backoff_coefficient == 2.0

    assert compensation_call["name"] == "compensate_activity"
    assert compensation_call["retry_policy"] is not None  # bounded compensation retries
    assert compensation_call["retry_policy"].maximum_attempts == 2
    assert compensation_call["args"][0] == {"id": "proposal-1"}


async def test_workflow_completes_without_compensation_on_success(temporal_backend: Any) -> None:
    module, fake = temporal_backend
    calls: list[str] = []

    async def dispatch(activity: Any, *, args: Any, start_to_close_timeout: Any,
                       retry_policy: Any = None, **_kwargs: Any) -> Any:
        calls.append(activity.__name__)
        if activity is module.execute_adapter_activity:
            return {"applied": True}
        if activity is module.verify_postcondition_activity:
            return {"verified": True}
        raise AssertionError("compensation must not run on success")

    fake["temporalio.workflow"].execute_activity = dispatch
    result = await module.ActionWorkflow().execute(_action_input())

    assert result["status"] == "completed"
    assert calls == ["execute_adapter_activity", "verify_postcondition_activity"]


async def test_failed_postcondition_triggers_compensation(temporal_backend: Any) -> None:
    module, fake = temporal_backend
    calls: list[str] = []

    async def dispatch(activity: Any, *, args: Any, start_to_close_timeout: Any,
                       retry_policy: Any = None, **_kwargs: Any) -> Any:
        calls.append(activity.__name__)
        if activity is module.execute_adapter_activity:
            return {"applied": True}
        if activity is module.verify_postcondition_activity:
            return {"verified": False}
        if activity is module.compensate_activity:
            return {"undone": True}
        raise AssertionError(f"unexpected activity {activity}")

    fake["temporalio.workflow"].execute_activity = dispatch
    result = await module.ActionWorkflow().execute(_action_input())

    assert result["status"] == "compensated"
    assert "Postcondition verification failed" in result["error"]
    assert calls[-1] == "compensate_activity"


# --------------------------------------------------------------------------- #
# Graceful degradation when the optional dependency is absent
# --------------------------------------------------------------------------- #
def test_missing_temporalio_fails_with_clear_error(backend_without_temporalio: Any) -> None:
    module = backend_without_temporalio
    assert module.TEMPORAL_AVAILABLE is False
    with pytest.raises(module.TemporalNotAvailableError, match="pip install temporalio"):
        module.TemporalJournal(module.TemporalConfig())


def test_constructor_guard_when_flag_disabled(temporal_backend: Any, monkeypatch: Any) -> None:
    module, _ = temporal_backend
    monkeypatch.setattr(module, "TEMPORAL_AVAILABLE", False)
    with pytest.raises(module.TemporalNotAvailableError, match="pip install temporalio"):
        module.TemporalJournal(module.TemporalConfig())
