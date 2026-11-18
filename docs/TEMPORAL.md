# Temporal.io backing (opt-in adapter)

MAESTRO's default durable engine is the file-backed, offline journal in
`maestro.orchestration` (`Journal` / `DurableEngine`). Temporal is an **opt-in**
backing for the same `Journal` contract — it is not required to run MAESTRO and
nothing enables it automatically.

This page describes the first concrete step of
[roadmap item 2](V1_1_ROADMAP.md#2-temporalio-live-backing): the journal now
reads activity outcomes from Temporal **workflow event history** via
`client.get_workflow_handle(workflow_id=run_id).fetch_history()`, instead of
serving lookups from a private in-memory cache. That makes replay, idempotent
re-sync, retry policy, and compensation testable against a mocked client.

## Opting in

`temporalio` is an optional dependency and is **not** installed by the default
or `dev` extras. Install it explicitly:

```bash
pip install temporalio
```

Then create a journal backed by Temporal and pass it to the durable engine:

```python
from maestro.orchestration.engine import DurableEngine
from maestro.orchestration.temporal_backend import (
    TemporalConfig,
    TemporalJournal,
    create_temporal_client,
)

journal = TemporalJournal(
    TemporalConfig(host="localhost", port=7233, namespace="default"),
    client=await create_temporal_client("localhost", 7233, "default"),
)
engine = DurableEngine(journal=journal)

# Before replaying a run in a fresh process, hydrate the cache from history:
await journal.sync_from_temporal("run-id")
result = engine.execute(workflow, "run-id")
```

`sync_from_temporal(run_id)` is the bridge from Temporal history to the local
replay cache. Completed/failed activity events become `ActivityRecord`s, ordered
by their scheduled event sequence — the same ordering the offline engine uses
for `ctx.activity(...)`. Re-syncing is append-only: already-journaled
`(run_id, seq)` entries are never overwritten. Activities that carry an
`idempotency_key` header are de-duplicated, so duplicate/retried events cannot
double-journal a side effect.

## Configuration

`TemporalConfig` (frozen dataclass) fields:

| Field | Default | Purpose |
| --- | --- | --- |
| `host` | `localhost` | Temporal frontend host |
| `port` | `7233` | Temporal frontend port |
| `namespace` | `default` | Temporal namespace |
| `task_queue` | `maestro-actions` | Worker task queue |
| `workflow_timeout_s` | `3600.0` | Workflow run timeout budget |
| `activity_timeout_s` | `300.0` | Default activity start-to-close budget |

`load_temporal_config(path)` reads a YAML file with a top-level `temporal:`
mapping of the same keys:

```yaml
temporal:
  host: localhost
  port: 7233
  namespace: default
  task_queue: maestro-actions
  workflow_timeout_s: 3600.0
  activity_timeout_s: 300.0
```

`create_temporal_journal(host, port, namespace, task_queue)` is the convenience
factory (it creates a journal whose client is connected lazily on first history
fetch).

### Retry and compensation

`ActionWorkflow.execute` schedules the adapter activity with a bounded
exponential-backoff policy (`maximum_attempts=3`, coefficient `2.0`). The
postcondition verification activity reuses that policy, and the compensation
activity uses a shorter bounded policy (`maximum_attempts` configurable via the
workflow input's `compensation_max_attempts`, default `2`). Any adapter failure
or failed postcondition routes through `compensate_activity` and returns
`{"status": "compensated", ...}`.

### Graceful degradation

Importing `maestro.orchestration.temporal_backend` never fails when
`temporalio` is absent: the optional imports are guarded, `TEMPORAL_AVAILABLE`
is `False`, and constructing a `TemporalJournal` (or a client) raises
`TemporalNotAvailableError` with a clear `pip install temporalio` message. The
default offline journal is unaffected.

## NOT_RUN — no live Temporal server was exercised

**Honesty note (per the roadmap's evidence standard):** no live Temporal server,
`WorkflowEnvironment`, or CI `temporal-integration` lane was run as part of this
step. `tests/test_temporal_backend.py` uses a hand-written **mock Temporal
client** and a fake `temporalio` package injected into `sys.modules`; it makes
no network connections and does not validate real Temporal event shapes, worker
determinism, or server-side retry behavior.

Consequently:

- `temporal` remains listed in `NOT_RUN` in
  `src/maestro/scripts/validation_evidence.py` — not promoted to `passed`.
- The live-server acceptance criteria (real exactly-once replay suite,
  end-to-end compensation, `temporal-integration` CI lane with `TEMPORAL_ADDRESS`
  gating) are **still open** work items in the roadmap.
- The mock tests here cover the *contract* of the first step only: history is
  fetched through the client, replay reuses recorded outcomes, idempotency keys
  dedupe, retry policies are attached, and compensation runs on failure.
