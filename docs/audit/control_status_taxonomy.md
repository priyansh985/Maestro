# Control-Status Taxonomy (BP0)

The central thesis of MAESTRO-SecOps is the **declaration–enforcement gap**: a
mitigation named in a catalogue is not the same as a control *enforced at a
side-effect boundary* and *proven by a test*. BP0 makes that gap measurable by
classifying every control this repository actually has into one of five honest
states. The taxonomy is defined and enforced in code at
[`src/maestro/security/control_status.py`](../../src/maestro/security/control_status.py);
this document is its human-readable specification.

## The five-rung ladder

Each rung **requires every rung below it**. When in doubt, a control is rated
*down*.

| Rung | Meaning | Evidence required (enforced by `audit_invariants`) |
|---|---|---|
| `declared` | Named in a catalogue / doc only; no code path. | — |
| `implemented` | Code exists that performs the control. | an `implementation` reference (`file:symbol`) |
| `enforced` | Invoked at a real boundary **and non-optional** (not default-off). | an `enforcement_point`; `default_state != "disabled"` |
| `tested` | Covered by an automated test. | a `test_id` |
| `verified` | Covered by an **adversarial / bypass** test. | a `test_id` exercising a bypass attempt |

## Machine-checked invariants

`audit_invariants()` **fails the build** if any control claims more than its
evidence supports. The guards are:

1. `implemented`+ requires a non-null `implementation`.
2. `tested`/`verified` requires a non-null `test_id`.
3. `enforced`+ requires a non-null `enforcement_point`.
4. `enforced`+ **cannot** have `default_state == "disabled"` — *default-off is
   not enforcement*. This is the guard that stops the audit from overstating.
5. No duplicate `control_id`.

Current status: **0 violations** (see `control_status.json`).

## `enforced` vs. `boundary_enforced` — the distinction that matters

`enforced_or_above` counts controls that run and are non-optional *anywhere*.
But a control enforced only in a unit test harness is weaker than one that gates
a **real side effect on the live loop**. `boundary_enforced()` counts only
controls whose `enforcement_point` is the
[`AgentPlatform`](../../src/maestro/platform/agent_platform.py) execution path —
i.e. it gates an actual tool call, not a component exercised in isolation.

Report these two numbers separately and never conflate them:

- **enforced_or_above** — the honest upper bound of "control that does something".
- **boundary_enforced** — the honest count of "control on the one path to a side
  effect".

Current snapshot: `enforced_or_above = 19` (ratio 0.594 of 32),
`boundary_enforced = 10`. Note `by_status.enforced == 0` because every control
that reaches the boundary is also *tested* or *verified*, so it is counted at the
higher rung — `enforced` here is a floor, not a bucket.

## How to change a control's rung

Raising a rung is a code change, never a doc edit:

- `declared → implemented`: land the code and reference it in `implementation`.
- `implemented → enforced`: wire it into a non-optional boundary (ideally the
  `AgentPlatform` path) and set `default_state` to `enabled`.
- `enforced → tested`: add an automated test and reference it in `test_id`.
- `tested → verified`: add an adversarial/bypass test that proves it blocks the
  forbidden behavior.

Regenerate the artifact after any change:

```
python -m maestro.scripts.bp0_audit      # or: maestro-bp0-audit
```
