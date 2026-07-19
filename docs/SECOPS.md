# MAESTRO-SecOps — security control plane (direction + status)

This document records the strategic repositioning of the project and, crucially,
**what is actually built today vs. what is planned**, so a reader can always
tell whether a control is (a) described in the paper, (b) simulated in an
experiment, (c) implemented but disabled, or (d) actually enforced.

## Positioning

The project is **not** a competing agent framework. It is a *security-control
plane, reference implementation, and evaluation harness* for agentic
network-monitoring systems: it provides the security envelope around agents
(identity, capabilities, policy decisions, evidence, containment, recovery,
human accountability) rather than orchestrating agents itself.

### Provenance (be precise)

- The reproduced work, **arXiv:2508.10043**, is an **arXiv preprint** — not
  described here as peer-reviewed unless/until a named venue is verified.
- The **seven-layer "MAESTRO" taxonomy is the Cloud Security Alliance's**
  framework (Multi-Agent Environment, Security, Threat, Risk & Outcome; Huang,
  CSA, 2025). The paper *uses* CSA MAESTRO (its reference [14]); this repo's
  L1–L7 are CSA MAESTRO's layers, not an original taxonomy. The "collision" is a
  citation, not a coincidence.

## Core architectural principle (target)

> No agent-generated output may cause an external side effect unless an
> independent policy-enforcement point authorizes a **typed action** under a
> **valid capability**.

An LLM is never a security authority: it *proposes* typed actions; a
deterministic executor gateway validates schema, evidence, policy, capability,
blast radius, and approval before any side effect, and appends an audit record.

## What is implemented now (this increment)

| Piece | Module | Status |
|---|---|---|
| Operational residual-risk model | `maestro/security/risk_engine.py` | implemented + tested |
| Phase-0 control-status truth audit | `maestro/security/control_status.py` | implemented + tested |
| Audit CLI (CI-gating) | `maestro/security/audit.py` → `maestro-audit` | implemented + tested |
| **Typed action schema** | `maestro/security/action.py` | implemented + adversarially tested |
| **Capability tokens / workload identity** | `maestro/security/identity.py` | implemented + adversarially tested |
| **Tamper-evident audit ledger** | `maestro/security/ledger.py` | implemented + adversarially tested |
| **Policy enforcement point (executor gateway)** | `maestro/security/enforcement.py` | implemented + adversarially tested; **wired into the live loop** (see agent platform) |
| **Agent platform (live control loop)** | `maestro/platform/agent_platform.py` → `maestro-agent` | implemented + end-to-end tested; **the only path from a model output to a side effect** |
| **Action confidence profile** (independent signals) | `maestro/security/confidence.py` | implemented + tested; **enforced on the platform path** |
| **Autonomy budget + rate limiting + idempotency** | `maestro/security/budget.py` + gateway | implemented + tested; **default-on on the platform path** |
| **Circuit breaker** (runaway-loop detection) | `maestro/security/circuit_breaker.py` + gateway | implemented + tested; **default-on on the platform path** |
| **Operational metrics** (ledger-derived) | `maestro/security/metrics.py` | implemented + tested |
| **Four-tier memory** (quarantine / promotion / isolation) | `maestro/memory/` | implemented + adversarially tested; **TC2 poisoning defense** (component; live-loop wiring pending) |
| **Durable execution** (exactly-once orchestration) | `maestro/orchestration/` | implemented + adversarially tested; offline Temporal-semantics (component; durable mode not yet default) |
| **Secure-by-inheritance provisioning** + cross-tenant capability gate | `maestro/platform/provisioning.py` + `memory/store.py` | implemented + tested; least-privilege envelopes, audited provisioning; cross-tenant memory read has no autonomous path |
| **HMDC critique** (4-stage gated evaluation) + shadow mode | `maestro/critique/` + `platform/agent_platform.py` | implemented + tested; deterministic gate dispositive, cross-family judges, variance→human, verbosity/position bias countered; shadow mode withholds execution for evaluation |
| **Multi-model routing / resilience** (§6) | `maestro/connectors/{routing,policy_fallback,moa}.py` | tested; latency-aware routing, **policy-aware fail-closed fallback**, Mixture-of-Agents (disagreement = uncertainty) |
| **Cross-domain packs + environmental verifiers** (§7) | `maestro/domains/` | implemented + tested; tests/reconcile/citation/safety verifiers wired into HMDC as a task_gate (closes the §5 gap) |
| **Dual-LLM injection perimeter** (§1, L1 boundary) | `maestro/security/perimeter.py` | implemented + tested; untrusted content is scanned, instruction-shaped content quarantined (inert), active tool/exfiltration attempts blocked, and only typed variables cross to the privileged path (component; standalone boundary, not yet on the live loop) |
| **Operator control panel + REST API** (§3) | `maestro/server/control_api.py` + `control_panel.py` (`/control`) | implemented + tested; a self-contained offline SPA whose every action drives the real control plane (live loop, ledger, memory, perimeter, HMDC, truth audit) |
| Legacy `P × I × E` score (paper) | `maestro/maestro/risk_score.py` | unchanged |

The **model connector system** (`maestro/connectors/`, `/playground`) provides
the backend-agnostic LLM path the control plane sits in front of. The **agent
platform** (`maestro/platform/`) is the keystone that makes the enforcement
point *the* execution path: a telemetry alert → the reasoner (connector-backed
model or the offline stub) *proposes* a typed action → the
`PolicyEnforcementPoint` authorizes, executes, verifies, and records it. There
is no code path from a model output to a side effect that bypasses the gateway,
which is what lets the truth audit grade these controls `enforced` rather than
merely `implemented`. Run `maestro-agent` for an offline demo.

### Operational risk model

Legacy `R = P × I × E` (1–27) is preserved for reproduction. The operational
model decides whether an autonomous action may run, on a 1–5 scale:

```
R_base      = 0.20·L + 0.25·I + 0.15·E + 0.10·X + 0.10·D + 0.10·Rc + 0.10·B
R_uncertain = R_base · (1 + 0.20·U)                     # penalize weak evidence
C_effective = min(0.85, Σ  w_j · e_j · v_j)             # evidence-weighted controls
R_residual  = R_uncertain · (1 − C_effective)
```

`e_j` (enforcement) is `1.0` at the side-effect boundary, `0.5` planner-only,
`0.0` declared-but-unwired; `v_j` (verification) is `1.0` adversarial-tested,
`0.5` unit-tested, `0.0` untested. **A declared or untested control contributes
zero** — this makes the declaration-enforcement gap quantitative. Residual risk
maps to a runtime decision:

| Residual | Decision |
|---:|---|
| 1.00–1.49 | allow |
| 1.50–2.49 | allow with safeguards |
| 2.50–3.49 | require approval |
| 3.50–4.24 | deny autonomous execution |
| 4.25–5.00 | emergency containment |

Override rule: any action in `CAPABILITY_REQUIRED_ACTIONS` (credential access,
code execution, exfiltration, deletion, irreversible network change,
cross-tenant access, sub-agent delegation) always requires an explicit
capability, regardless of the numeric score.

Worked TC2 example (`tests/test_risk_engine.py`): `R_base = 4.15`,
`R_uncertain = 4.36`; unmitigated `R_residual = 4.36` → *emergency containment*;
with an enforced, adversarially-tested control (`C = 0.65`),
`R_residual = 1.53` → *allow with safeguards*.

### Enforcement plane (executor gateway)

The keystone of the target principle above is now built as a self-contained,
fail-closed component. An LLM proposes; `PolicyEnforcementPoint` decides:

```
raw model output
  → parse_proposal()          typed, allow-listed intent (action.py) — bad JSON/type/intent → deny
  → evidence check            every evidence_id must exist            — ghost evidence → deny
  → residual_risk() → decide  risk band (risk_engine.py)              — deny_autonomous / emergency → deny
  → capability verify         signed, scoped, unexpired token         — capability-required or non-allow band needs a valid cap
  → approval gate             require_approval band needs an approver
  → allow-listed adapter      executor speaks a bounded vocabulary    — unknown adapter / raise / bad postcondition → deny
  → ledger.append()           tamper-evident audit event (allow AND deny)
```

- **Capabilities** (`identity.py`) are HMAC-signed claims binding subject,
  capability, resource, tenant, delegation depth, and a short TTL. Verification
  fails closed on a forged signature, wrong key, expiry, or any scope mismatch.
  Delegation strictly narrows scope, cannot outlive its parent, and is
  depth-capped (`MAX_DELEGATION_DEPTH`) — this defeats the confused-deputy and
  runaway-delegation problems.
- **Typed proposals** (`action.py`) turn untrusted model JSON into a strict
  object; `capability`/`action_class` are derived from an allow-listed intent
  registry, never from an LLM-supplied scope string.
- **Ledger** (`ledger.py`) is append-only, hash-chained, and HMAC-signed;
  `verify_chain()` pinpoints the first tampered event (tested against in-memory
  and on-disk edits).
- **Kill switch**: `pep.halt()` denies everything until `resume()`.

Every path is adversarially tested in `tests/test_enforcement.py` (forged/
expired/out-of-scope capabilities, ghost evidence, tampered ledger links,
missing tokens on capability-required actions, high-risk hard-deny, adapter
failure, kill switch).

**The live-loop wiring is now done** (`maestro/platform/agent_platform.py`,
`tests/test_platform.py`). `AgentPlatform` composes the reasoner and the gateway
into a single secure-by-default path: it registers the alert as evidence, lets
the reasoner *propose* an intent, deterministically assembles the typed proposal
(the model does **not** choose scope — resource and TTL come from the platform),
derives risk + independent-signal confidence, and submits to the
`PolicyEnforcementPoint` under a capability delegated from the human controller.
`tests/test_platform.py` proves end-to-end that a legitimate reversible
mitigation is authorized and executed, an out-of-scope proposal is denied at the
capability gate, an unknown intent is quarantined by the schema, and every
outcome — allow *and* deny — is recorded, so the ledger-derived
`unsafe_action_rate` is `0.0` (the bypass proof). Because the gateway is now
non-optional on this path, the capability/schema/ledger controls are graded
`enforced`+ in the truth audit.

### Gateway hardening (decision quality, budget, idempotency, observability)

Four corrections harden the gateway beyond bare authorization. Each is opt-in on
the bare `PolicyEnforcementPoint`, but the **agent platform turns them on by
default** — secure-by-default budget, breaker, per-alert idempotency key, and a
decision card per outcome — so on the live path they are enforced, not optional:

- **Action confidence** (`confidence.py`): `C_action = 0.30·E + 0.25·V +
  0.20·P + 0.15·A + 0.10·H` from *independently observed* signals (evidence
  quality, validator agreement, policy compatibility, reversibility, history) —
  **not** the model's self-reported confidence, which is not calibrated. It
  only *raises* scrutiny: a low band denies or escalates an otherwise-permissive
  risk decision; a high band can never override a hard rule (capability-required
  actions, risk hard-deny).
- **Autonomy budget** (`budget.py`): bounds tool calls, spend, blast radius, and
  a sliding-window call rate — the `BudgetAvailable` conjunct in the `Allow`
  predicate. Consumed only on executed actions; a denial costs nothing.
- **Idempotency / exactly-once**: an `idempotency_key` recorded only on success,
  so a retry cannot duplicate a firewall rule; a *denied* attempt stays
  retryable.
- **Decision observability** (`_decision_card`): every outcome emits a
  structured card — identity, the *validated* proposal, evidence references,
  policy result, risk, confidence, outcome — and a terminal lifecycle state
  (`COMPLETED / DENIED / ESCALATED / QUARANTINED`). Raw chain-of-thought,
  prompts, and scratchpad are **never** recorded (tested): reasoning traces are
  neither reliable explanations nor safe to retain. The full action lifecycle
  (CREATED → … → AUTHORIZED → EXECUTING → COMPLETED) forbids a direct
  `PLAN_PROPOSED → EXECUTING` transition.

Tested in `tests/test_enforcement_hardening.py`.

### Operational safety (circuit breaker + metrics)

- **Circuit breaker** (`circuit_breaker.py`): trips when one `(intent, args)`
  signature repeats ≥ N times within a window, halting a runaway reasoning
  loop and escalating — the deterministic version of "same tool, same args,
  three times → stop". Complements idempotency (which stops re-executing a
  *success*; the breaker stops a *looping retry*).
- **Operational metrics** (`metrics.py`): authorization rate, denials-by-stage,
  **unsafe-action rate** (executed actions in a hard-deny band — must be 0, a
  bypass proof), tool-failure rate, and ledger integrity are all derived from
  the tamper-evident ledger, not from self-reported dashboard counters. Metrics
  that need goal labels or a memory subsystem (task-completion, grounded-answer,
  memory-contamination) are omitted rather than faked.

Tested in `tests/test_operational_safety.py`.

> **Note on the source blueprint.** The enterprise blueprint that requested a
> raw "Cognitive Logs" chain-of-thought viewer, model-self-reported confidence,
> "deterministic" Llama-Guard, a flat global memory, transparent fallback, and a
> fixed-weight `0.2·semantic + 0.8·judge` critique is intentionally **not**
> implemented as written — each conflicts with a correction already applied here
> (decision cards without CoT, independent-signal confidence, deterministic
> policy separated from probabilistic classifiers, tiered/procedural memory as a
> roadmap item, policy-aware fallback, environmental verification over judge
> weighting).

### Truth audit (Phase 0)

`maestro-audit` (or `python -m maestro.security.audit`) writes
`results/control_status.json` and classifies every control the repo actually has
into a strict ladder `declared → implemented → enforced → tested → verified`
(each rung requires those below it). It **fails the build** if a control claims
more than its evidence supports — including the key guard that a control at
`enforced` or higher may **not** be default-off or lack an enforcement point.

Today's honest picture (of 29 inventoried controls):
- **10 controls are now enforced at the side-effect boundary on the live loop**
  (`maestro-audit` reports the count directly): the capability/typed-schema
  gateway and tamper-evident ledger (both `verified`, adversarially bypass-tested),
  the action allow-list, action confidence, autonomy budget + idempotency,
  circuit breaker, CoT-free decision card, delegation/kill-switch, and — new —
  **memory isolation and quarantine-on-ingest**: every authorized action is now
  grounded in a scoped, provenance-tagged memory record, and every detection is
  quarantined on ingest, so the TC2 poisoning attack is inert on the *running*
  agent. Every one routes through `AgentPlatform`, the only path that executes a
  tool action.
- Several more **operational** controls are default-on and tested (connector
  fallback and auth, request logging, threat-catalogue consistency, poisoning
  detection, operator verification, the truth audit itself).
- The remaining **catalogue** controls (zero-trust API, output validators, policy
  bundles, cross-tenant admin reads, durable-mode-by-default, the HMDC harness)
  are `implemented`/`declared` and **default-off, component-level, or unbuilt** —
  so they are honestly *not* live-enforced. The legacy planner-side toggle
  (`agent/planner.py:validate_plans`) stays default-off and is superseded by the
  executor-boundary allow-list.

The audit exists precisely so this gap is measured, not implied. The former gap
between "the gateway exists and is tested" and "the running system uses it" is
now closed for the platform path; what remains is honestly enumerated above.

## Roadmap (not yet built — do not treat as enforced)

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Control-status truth audit + risk engine | **done** |
| 1 | Secure-by-default server (auth, rate limits, fail-closed config) | **partial** — opt-in bearer auth + SSRF guard shipped; rate limits / fail-closed config planned |
| 2 | Enforcement plane: typed action schema, capability tokens, executor gateway, sandbox, kill switch | **done** — schema, capabilities, gateway, kill switch, adversarial tests, **and live-loop wiring** (`AgentPlatform`); real sandbox/SOAR adapters (vs. the bounded stand-ins) pending |
| 3 | Integrity + transparency: append-only HMAC hash-chain memory, quarantine/promotion, tamper-evident ledger, evidence graph | **partial** — tamper-evident ledger done; **four-tier memory store with quarantine-on-ingest, capability-gated promotion, read-only procedural memory, and tenant/agent isolation done** (`maestro/memory/`, component; the TC2 poisoning defense is now structural); live-loop wiring / Postgres RLS / evidence graph planned |
| 4 | Operational monitoring: isolated packet capture, Prometheus/OTel, connector circuit breakers | planned |
| 5 | Adversarial evaluation: TC3–TC15 corpus, ablations, confidence intervals, ATLAS/OWASP/NIST mappings | planned |

External vocabularies to map against as the corpus grows: OWASP Agentic AI,
NIST AI 100-2 (adversarial ML), MITRE ATLAS. Use real technique IDs only once
mapped to a current release — never invent an ID to look complete.

## Design rules carried forward

- Put enforcement at the **side-effect boundary**, not only the planner.
- Hashes detect change only when the key/trust boundary is protected; they do
  not authorize a write. Pair cryptographic integrity with **semantic** trust.
- An LLM guard is a signal, not the policy authority.
- Risk is not static; recompute with exposure, connector health, and incident
  state.
- Human approval is not automatic safety — surface blast radius and
  contradictory evidence.
