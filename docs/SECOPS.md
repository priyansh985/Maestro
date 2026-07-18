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
| Legacy `P × I × E` score (paper) | `maestro/maestro/risk_score.py` | unchanged |

The **model connector system** (`maestro/connectors/`, `/playground`) provides
the backend-agnostic LLM path the control plane sits in front of.

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

### Truth audit (Phase 0)

`maestro-audit` (or `python -m maestro.security.audit`) writes
`results/control_status.json` and classifies every control the repo actually has
into a strict ladder `declared → implemented → enforced → tested → verified`
(each rung requires those below it). It **fails the build** if a control claims
more than its evidence supports — including the key guard that a control at
`enforced` or higher may **not** be default-off or lack an enforcement point.

Today's honest picture:
- ~7 **operational** controls are default-on and tested (connector fallback and
  auth, request logging, threat-catalogue consistency, poisoning detection,
  operator verification, the truth audit itself).
- The **security mitigation catalogue** controls (memory isolation, planner
  validation, zero-trust API) are `implemented`/`declared` and **default-off or
  planner-side** — so they are *not* enforced.
- **Side-effect-boundary security enforcement = 0**: there is no executor
  gateway yet, so no agent-proposed action is gated by an independent policy
  decision. Closing this is Phase 2 — and it is the whole point.

The audit exists precisely so this gap is measured, not implied.

## Roadmap (not yet built — do not treat as enforced)

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Control-status truth audit + risk engine | **done (this increment)** |
| 1 | Secure-by-default server (auth, rate limits, fail-closed config) | planned |
| 2 | Enforcement plane: typed action schema, capability tokens, executor gateway, sandbox, kill switch | planned |
| 3 | Integrity + transparency: append-only HMAC hash-chain memory, quarantine/promotion, tamper-evident ledger, evidence graph | planned |
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
