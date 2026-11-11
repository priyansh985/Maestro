# Control Gap Report (BP0)

This report names every gap between what MAESTRO *declares* and what it
*enforces at a real boundary*, so the gap drives the roadmap instead of hiding in
it. Numbers are generated from
[`control_status.json`](control_status.json); regenerate with
`python -m maestro.scripts.bp0_audit`.

## Headline numbers

| Metric | Value | (BP0 → BP3.1 → BP3.2 → BP3.3 → BP4 → BP7 → BP-gov) |
|---|---|---|
| Total controls | 35 | 32 → 33 → 34 → **35** (added L4-07, L4-08, L3-04) |
| `verified` (adversarial/bypass tested) | 7 | 2 → 3 → 4 → 5 → 6 → **7** |
| `tested` | 21 | 17 → 18 → 19 → 20 → **21** |
| `implemented` (not on a live boundary) | 7 | 10 → 9 → **7** |
| `declared` (no code path) | 0 | 3 → 2 → 1 → **0** |
| **enforced_or_above** | 28 (ratio **0.800**) | 0.594 → 0.686 → 0.743 → 0.771 → **0.800** |
| **boundary_enforced** (on the AgentPlatform live loop) | **16** | 10 → 12 → 14 → 15 → **16** (CTRL-L1-01) |
| Audit invariant violations | **0** | — |

The honest read: **15 controls actually gate a real side effect**; another 10 run
and are non-optional (incl. the `verified` API front door + rate limiter +
multi-tenant isolation, which gate the `/api` surface / data partition rather than
the PEP boundary); 7 are built-but-not-wired-to-the-boundary; 1 is
catalogue-only. The enforcement ratio (0.771) is real, not aspirational — the
`audit_invariants()` build guard makes overstatement fail CI.

> **BP3.1 + BP3.2 + BP3.3 landed:** CTRL-L4-03 is `verified` and covers the
> **whole `/api` surface** (control plane + connectors, previously `auth=NONE`) —
> signed bearer token + role, fail-closed. **CTRL-L4-07** adds a deterministic
> per-principal rate limiter (429). **CTRL-L4-08** adds **structural multi-tenant
> isolation** — each principal is routed to its own per-tenant
> `AgentPlatform`+ledger+memory, so one tenant cannot read or reset another's
> state via any route (`tests/test_tenant_isolation.py`). **0 `/api` endpoints
> unauthenticated.**
>
> **BP4 landed:** the side-effect boundary (TB5) is hardened with **two**
> `boundary_enforced` controls. **CTRL-L3-04** wraps every side effect in an
> in-process **executor sandbox** (scope + output confinement, fail-closed;
> `tests/test_sandbox.py`). **CTRL-L4-05** (durable exactly-once) is now **on the
> live loop**: the executor journals every side effect and replays it exactly-once
> across a crash (`tests/test_platform.py`, file-backed simulated restart).
> Kernel-level isolation (gVisor/Firecracker) and Temporal.io remain seams.
>
> **BP7 landed:** the evaluation stack moved onto the boundary — a
> **pre-execution critique gate** runs before every side effect. **CTRL-L5-08**
> (`verified`): a deterministic **environmental verifier** vetoes a mitigation
> inappropriate/unsafe for the observed alert (e.g. raising detection thresholds
> mid-DoS, which blinds the detector) at the executor. **CTRL-L5-06** (`tested`):
> the full **HMDC gated critique** runs on the loop — deterministic guardrails +
> the verifier deny autonomously, judge uncertainty routes to a human. The
> offline lexical judge/embedder mean the operative hard gate is the
> guardrail + verifier pair; a connector-backed cross-family judge is the seam.
>
> **BP-gov landed:** governance moved onto the boundary too. **CTRL-L6-03**
> (`verified`, `declared → verified`): the executor's effective intent allow-list
> is now a **signed, versioned policy bundle** rather than static code. A change
> to it requires a **two-person rule** (the proposer may not approve their own
> change); activation HMAC-signs the bundle and is recorded in the ledger, and
> the active bundle's signature is **re-verified at the side-effect boundary**
> before every action (a tampered/absent bundle or a de-listed intent fails
> closed). This closes the last-but-one `declared` gap (`declared` 2 → 1). The
> seam is external signer identities (OIDC/KMS key per approver) instead of one
> shared HMAC key.

## Gap A — `declared` only (no code path). Highest leverage.

| Control | Layer | What's missing | Maps to |
|---|---|---|---|
| ~~**CTRL-L4-03** Server auth / zero-trust API~~ | L4 | **CLOSED (BP3.1+BP3.2)** — the whole `/api` surface (control plane + connectors) requires a signed bearer token + role, tenant-confined, fail-closed, rate-limited per principal (CTRL-L4-07). Remaining as prod seams: OIDC/SSO, external RBAC store, Postgres RLS. | ✅ done |
| ~~**CTRL-L6-03** Signed policy bundles / two-person change~~ | L6 | **CLOSED (BP-gov)** — the executor allow-list is a signed, versioned bundle; changes need a two-person rule; the active bundle is verified at the side-effect boundary (fail-closed). Seam: external signer identities (OIDC/KMS per approver). | ✅ done |
| ~~**CTRL-L1-01** LLM guardrails + output validators~~ | L1 | **CLOSED (v1.1)** — runtime output policy validator on the model→proposal path, wired into AgentPlatform (default-on); failing outputs are quarantined and audited. Adversarially tested (injected outputs blocked on the live loop). | ✅ done |

## Gap B — `implemented` but not on the live side-effect boundary

These are built and (mostly) unit-tested, but do not yet gate a real action on
the `AgentPlatform` loop. Promotion to `boundary_enforced` is a wiring task.

| Control | Why it's not boundary-enforced | Maps to |
|---|---|---|
| CTRL-L5-07 Shadow-mode evaluation | A mode, not the default | BP7 |
| CTRL-L5-03 Residual-risk scoring | Library exists; not wired to gate any action | BP4 |
| CTRL-L2-05 Cap-gated cross-tenant memory | Capability-gated admin path, not the automatic loop | BP5 |
| CTRL-L7-03 Secure-by-inheritance provisioning | Component; no live provider-registration loop drives it | BP7/BP11 |
| CTRL-L1-02 Deterministic reasoner | A safe *default*, not an enforcement point (by design) | — |
| CTRL-L2-01 Memory freeze | Best-effort POSIX chmod, **default-off**; superseded by SEB-03 | superseded |
| CTRL-L5-05 Ledger-derived metrics | Observability, not a gate | — |

## Gap C — production hardening below the application layer

The enforced controls are enforced *in-process*. These move enforcement beneath
an application bug — the difference between a demo and a platform:

| Gap | Today | Target | Maps to |
|---|---|---|---|
| Tenant isolation | **structural per-tenant control planes** (CTRL-L4-08) + `MemoryStore` scope checks | Postgres **row-level security** (single-DB variant) | **BP3 done in-repo**; RLS seam |
| Identity / RBAC | bearer token + RBAC + rate limit on all `/api` (in-process) | OIDC/SSO + service accounts + external RBAC/ABAC + shared rate-limit store | **BP3** (auth done; OIDC/RLS seams) |
| Tool sandboxing | **in-process executor sandbox** (scope + output confinement, CTRL-L3-04) | OS isolation: Docker → gVisor/Firecracker | **BP4 done in-repo**; OS seam |
| Durable runtime | **exactly-once journal on the live loop** (CTRL-L4-05, file-backed) | Temporal.io | **BP4 done in-repo**; Temporal seam |
| Verticals | none | secure coding agent, research agent | **BP8/BP9** |

## What is *not* a gap (don't rebuild these)

`verified` (adversarial-tested): **CTRL-L3-02** capability gateway,
**CTRL-L3-04** executor sandbox, **CTRL-L5-02** tamper-evident ledger,
**CTRL-L5-08** environmental verifier veto, **CTRL-L6-03** signed policy bundles
/ two-person change, **CTRL-L4-03** zero-trust `/api` front door, **CTRL-L4-08**
structural multi-tenant isolation. Plus 15
`boundary_enforced` controls on the live loop (allow-list, signed policy bundle,
budget+idempotency, breaker, quarantine-on-ingest, scope isolation, decision
card, kill switch, executor sandbox, durable exactly-once, environmental
verifier, HMDC gated critique, …). This core
is the reason the BP0 decision was **build-in-place, not greenfield** — see
[`module_disposition.json`](module_disposition.json).

## Prioritized next targets

1. ~~**BP3.1 — CTRL-L4-03 auth + RBAC.**~~ **Done.**
2. ~~**BP3.2 — extend the boundary + per-principal rate limiting (CTRL-L4-07).**~~
   **Done.** 0 unauthenticated `/api` endpoints.
3. ~~**BP3.3 — structural multi-tenant isolation (CTRL-L4-08).**~~ **Done.**
   Per-tenant `AgentPlatform`+ledger+memory; one tenant cannot read/reset
   another's state via any route (`tests/test_tenant_isolation.py`).
   → **BP3 is in-discipline complete.** The only remaining BP3 items are external
   infrastructure that cannot live in an offline/stdlib repo without becoming
   fakes, correctly held as **production seams**: Postgres row-level security
   (single-DB variant of CTRL-L4-08), OIDC/SSO login, external RBAC/ABAC store,
   shared (Redis) rate-limit store.
4. ~~**BP4 — sandbox + durable-by-default.**~~ **Done.** Every side effect runs
   inside an in-process executor sandbox (CTRL-L3-04, scope + output confinement)
   and as a durable exactly-once journaled activity (CTRL-L4-05, now on the live
   loop) — both `boundary_enforced`. What makes `SIMULATED_EXTERNAL` safe to
   become real external below the app layer stays a seam: **OS isolation**
   (gVisor/Firecracker) and **Temporal.io** as the durable backend.
5. ~~**BP7 — wire HMDC/verifiers into the live gate.**~~ **Done.** A
   pre-execution critique gate runs the HMDC engine + a deterministic
   environmental verifier before every side effect: **CTRL-L5-08** (`verified`)
   vetoes a mitigation inappropriate/unsafe for the observed alert, and
   **CTRL-L5-06** (`tested`) puts the full gated critique on the loop
   (deterministic stages deny autonomously; judge uncertainty routes to a human).
   Both `boundary_enforced`. Remaining BP7 items held as seams / later work: a
   **connector-backed cross-family judge** (the offline lexical judge is a
   stand-in) and promoting **shadow mode** (CTRL-L5-07) from a mode to a default
   evaluation lane.
6. ~~**BP-gov — signed policy bundles / two-person change (CTRL-L6-03).**~~
   **Done.** The executor allow-list is now a signed, versioned policy bundle;
   a change requires a two-person rule (proposer ≠ approver) and is recorded in
   the ledger; the active bundle is signature-verified at the side-effect
   boundary and fails closed on tamper/absence or a de-listed intent
   (`verified`, `boundary_enforced`; `tests/test_policy_bundle.py` +
   `tests/test_platform.py`). Seam: external signer identities (OIDC/KMS key per
   approver) instead of one shared HMAC key.
7. ~~**Next in-discipline target — BP5 (a SOC/network-monitoring vertical).**~~
   **Done.** A concrete SOC/Network Monitoring vertical now exercises the full
   enforcement and governance spine (TB0→TB6). The live `AgentPlatform` loop natively
   builds an Evidence Graph for the reasoner by querying trusted memory, and
   memory promotion (`promote_memory`) is securely wired through the PEP boundary
   (CTRL-L2-03, CTRL-L5-02).
8. **Next in-discipline target — CTRL-L1-01 (LLM output validators).** The last `declared`-only
   control is CTRL-L1-01 (a runtime *output* policy validator on the model→
   proposal path).
