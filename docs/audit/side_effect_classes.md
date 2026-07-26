# Side-Effect Classes (BP0)

A **side-effect boundary** is a point where execution leaves pure computation and
changes state the system — or the world — can observe. The core security claim of
MAESTRO is that *no model output reaches such a boundary except through a typed,
authorized, allow-listed proposal*. To make that claim checkable, every boundary
is classified by the **kind** of state it changes.

The concrete, curated map of boundaries lives in
[`side_effect_boundaries.json`](side_effect_boundaries.json) (8 boundaries,
`SEB-01`…`SEB-08`). This document defines the class vocabulary those entries use.

## Class vocabulary

| Class | Definition | Reversibility posture | Boundaries |
|---|---|---|---|
| `NONE` | Pure computation; no observable state change. | n/a | (implicit — the default) |
| `INTERNAL_STATE` | Mutates MAESTRO's own persistent/in-process state (ledger, memory, capabilities). | Audited; ledger is append-only by design, memory promotion is reversible + recorded. | SEB-02, SEB-03, SEB-04, SEB-08 |
| `SIMULATED_EXTERNAL` | The domain "tool" actions (SOC mitigations). In this offline reproduction they *model* the effect; in production they call a firewall/SOAR/capture control. | Varies; `rollback_telemetry` is the compensating action. | SEB-01 |
| `EXTERNAL_NETWORK` | Outbound request off the host (model/provider HTTP). | n/a (read of an external model). | SEB-05 |
| `HOST_ENVIRONMENT` | Touches the host OS/network directly (real packet send, filesystem). | Packet send is irreversible; result files are overwritable. | SEB-06, SEB-07 |

## The one that matters: `SIMULATED_EXTERNAL` (SEB-01)

The consequential boundary is **operational tool execution** —
[`default_tool_adapters()`](../../src/maestro/platform/agent_platform.py). This is
the single place a decision becomes an action (`throttle_telemetry`,
`raise_thresholds`, `raise_capture_duration`, `alert_operator`,
`rollback_telemetry`, `noop`). Every path to it is gated:

- **CTRL-L3-01** — the intent must be in the `INTENT_REGISTRY` allow-list.
- **CTRL-L3-02** — the action must carry a signed, scoped, short-lived capability
  and execute through the PEP gateway (fail-closed).
- **CTRL-L3-03** — the autonomy budget and idempotency key must permit it.

There is **no bypass path** from model output to this boundary: the model
proposes, the platform authorizes/executes/verifies/records.

## Classes that are *off* the agent control plane

Two classes exist in the repo but are **not reachable from an agent action**, and
BP0 records that explicitly so they are not mistaken for governed capabilities:

- **`HOST_ENVIRONMENT` (SEB-06, SEB-07)** — the TC1 packet replay and result/log
  file writes are developer/experiment tooling, invoked explicitly, never from a
  proposal. TC1's *reported metric* is the modeled saturation curve (assumption
  A13), not the best-effort send.
- **`EXTERNAL_NETWORK` (SEB-05)** — the only egress off the box. It is off the
  default offline loop (which uses the deterministic stub reasoner); when used it
  authenticates per-provider (keys from env, never persisted) and fails closed
  rather than downgrading a request's trust tier.

## Superseded boundary (SEB-08)

`AgentMemory` / `history.json` is the paper's poisonable memory file. It is
retained **only** for the TC2 reproduction; the *enforced* memory path is
[`memory/store.py`](../../src/maestro/memory/store.py) (SEB-03), which is
tamper-evident and quarantine-on-ingest. Do not build new features against SEB-08.

## Rule for adding a boundary

Any new sink that changes observable state **must** be added to
`side_effect_boundaries.json` with its class, reversibility, and gating control —
in the same change that introduces it. An ungated `SIMULATED_EXTERNAL`,
`EXTERNAL_NETWORK`, or `HOST_ENVIRONMENT` boundary reachable from a model proposal
is a **stop-condition** (see `TRUTH_AUDIT.md` §Stop conditions).
