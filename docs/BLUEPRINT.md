# Master Implementation Blueprint — A Policy-Governed Execution Platform for Agentic AI

> **Scope and stance.** This is the architecture document for turning the
> MAESTRO-SecOps reproduction (arXiv:2508.10043, CSA MAESTRO L1–L7) into an
> enterprise agent **control plane**. It is deliberately *opinionated* and, where
> it diverges from the originating brief, says so and why. Six requested design
> choices are **corrected** rather than reproduced — raw chain-of-thought
> observability, model-self-reported confidence, "deterministic" guardrail
> models, a flat global memory, transparent fallback, and the fixed-weight
> `0.2·semantic + 0.8·judge` critique — because each is a known failure mode in
> production agentic systems. Divergences are marked **⚑ Correction**.
>
> Wherever a component already exists in this repository it is cited by module
> (`security/enforcement.py`, etc.); the platform is defined against real code so
> the *declaration-enforcement gap* — the central thesis of this project — is not
> reintroduced at the blueprint layer.

The organizing principle, non-negotiable, from which every section derives:

> **An LLM proposes intentions; deterministic services authorize, execute,
> verify, and record consequences.** The model is never the source of truth for
> authorization, identity, risk acceptance, policy interpretation, or factual
> verification.

---

## 1. Agentic Risk Taxonomy & Defense-in-Depth Mitigation

Risk in agentic systems is three-dimensional and must be mitigated
simultaneously; a system strong on security but weak on operational containment
still fails catastrophically (a prompt-injected agent that also lacks a budget
cap exhausts an account before anyone reviews a log).

### 1.1 Behavioral / alignment risk

*Goal misgeneralization* (the agent satisfies the literal instruction while
violating intent), *reward hacking*, and *hallucination that drives a real
action* are the failure modes. The architectural error is trying to fix these
inside the model. They are contained *around* it:

- **Constrain the output surface.** The model never emits free-form actions; it
  emits a typed proposal against an allow-listed intent registry
  (`security/action.py:parse_proposal`). Malformed JSON, wrong types, or an
  unknown intent are rejected before any policy runs. This converts "the model
  said something dangerous" into "the model produced an invalid proposal," which
  is a parse error, not an incident.
- **An independent critic that is not a model.** The decisive check is a
  deterministic policy-enforcement point (`security/enforcement.py`), not a
  second LLM. A critic *model* is a useful signal but can itself be injected; it
  must never be the authority (see §5).
- **⚑ Correction — epistemic uncertainty.** The brief asks the agent to "output
  a confidence score" and gate on it. A model's self-reported confidence is
  *not* calibrated probability of correctness — it collapses under missing
  information, injection, and distribution shift. We instead compute an **action
  confidence profile from independently observable signals**
  (`security/confidence.py`): `C_action = 0.30·E + 0.25·V + 0.20·P + 0.15·A +
  0.10·H` over evidence quality, validator agreement, policy compatibility,
  reversibility, and historical reliability. Crucially it **only raises
  scrutiny** — a low band downgrades a permissive decision to approval-required
  or deny; a high band can *never* override a hard rule.

### 1.2 Operational / runaway risk

Infinite reasoning loops, cost/compute exhaustion, and cascading multi-agent
failures. These are bounded deterministically:

- **Hard budgets.** `security/budget.py:AutonomyBudget` caps tool calls, spend,
  blast radius (hosts/records), and a sliding-window call rate. Budget is the
  `BudgetAvailable` conjunct of the authorization predicate and is consumed only
  on executed actions — a denied action costs nothing.
- **Circuit breakers.** `security/circuit_breaker.py` trips when one
  `(intent, arguments)` signature repeats ≥ N times in a window, halting a
  runaway loop and escalating. This is complementary to idempotency: idempotency
  stops re-executing a *success*; the breaker stops a *looping retry* that never
  succeeds.
- **Idempotency / exactly-once intent.** An `idempotency_key`, recorded only on
  success, guarantees a retry cannot create a duplicate firewall rule or refund.
- **Checkpoint + compensation (roadmap).** A durable action state machine
  (`CREATED → CONTEXT_VALIDATED → PLAN_PROPOSED → POLICY_EVALUATED →
  APPROVAL_PENDING → AUTHORIZED → EXECUTING → POSTCONDITION_VERIFIED →
  COMPLETED`) with compensating actions on failure. The lifecycle enum exists
  (`security/enforcement.py:ActionState`); full compensation is Phase 2.

### 1.3 Security / adversarial risk

Direct prompt injection, *indirect* injection (malicious instructions in
retrieved context/tool output), and data exfiltration.

- **Treat all external content as untrusted instruction-bearing data.** Packet
  metadata, SIEM descriptions, tickets, RAG documents, tool outputs, and other
  agents' messages are data, never control. External content must not acquire
  control-plane privilege because the model read it.
- **Privilege separation.** The agent holds no ambient authority. Every side
  effect requires a signed, scoped, short-lived **capability**
  (`security/identity.py`) bound to subject, capability, resource, tenant, and
  delegation depth. This defeats the confused deputy: a low-trust input may
  influence a plan, but it cannot inherit the firewall administrator's rights.
- **SSRF / egress control.** Connector base URLs are validated against
  link-local/metadata/reserved ranges (`connectors/providers/http_base.py`);
  tool execution belongs behind egress allow-lists and sandboxes (Phase 2).
- **⚑ Correction — "dual-LLM security perimeter" / "deterministic guardrail
  models."** A small classifier (Llama Guard, a PII NER, an injection detector)
  is **probabilistic**, not deterministic, and must not be the only barrier to a
  consequential tool. Classifiers *raise scrutiny, reduce privilege, quarantine
  input, or escalate*; deterministic policy + cryptographic capability are what
  actually authorize. Conflating the two is the most common security-theater
  mistake in this space.

> **Implementation status (`security/perimeter.py`).** Built: a
> `DualLLMPerimeter` realizes the offline, deterministic form of the dual-LLM
> pattern. Untrusted external content is scanned for injection (category-tagged:
> instruction-override / delimiter-breakout / obfuscation / tool-invocation /
> exfiltration) and ruled on — `ADMIT` clean data, `QUARANTINE` instruction-
> shaped content as *inert* `UNTRUSTED` data (it can be stored and cited but can
> never influence the agent), or `BLOCK` active tool/exfiltration attempts. The
> **only** thing permitted to cross into the privileged path is a list of typed,
> validated `SymbolicVariable`s (IP, port, count, CVE, hash) — never free-form
> text. True to the correction above, the scanner only *raises scrutiny /
> quarantines*; deterministic policy + capabilities still authorize. Tested in
> `tests/test_perimeter.py`; graded `tested` (a standalone boundary, not yet
> wired into the live loop, whose alerts are detector-internal). Exposed on the
> control panel's **Injection Perimeter** tab.

---

## 2. Core Platform Architecture & System Components

### 2.1 Foundational pattern — event-driven modular monolith

**Choice: a modular monolith with durable workflow execution, not microservices,
for the first two phases.** Agent execution is a tightly-coupled, stateful
transaction (plan → policy → capability → execute → verify → audit). Splitting
that across network boundaries prematurely buys nothing but latency, distributed
tracing complexity, and partial-failure states that are hard to reason about.
The monolith keeps transaction boundaries intact and debugging tractable;
extract a service only when a component earns an independent authority, data, or
scaling boundary (the same rule that governs adding an agent — §8).

State is *not* held in the orchestrator. It is delegated to a durable workflow
engine (Temporal.io or equivalent) so the orchestration logic stays stateless
and horizontally scalable, and so recovery from a provider outage resumes with
authorization state intact rather than re-deciding from scratch.

### 2.2 Core components

| Component | Responsibility | In this repo |
|---|---|---|
| API gateway / ingress | AuthN/Z, rate limiting, routing | opt-in bearer auth (`server/connectors_api.py`); full gateway is Phase 1 |
| Orchestration engine | Durable state machine, retries, recovery | **`orchestration/` — offline durable engine: event-sourced journal, exactly-once activities across a crash, retries, timeouts**; Temporal.io is the production backing |
| Provider Abstraction Layer | Canonical request/response across providers | `connectors/` (adapter per provider, registry, fallback) |
| **Policy & guardrail engine** | The side-effect boundary: authorize typed actions | `security/enforcement.py:PolicyEnforcementPoint` (live via `platform/`) |
| Risk engine | Residual-risk scoring → runtime decision | `security/risk_engine.py` |
| Memory & state store | Tiered, isolated persistence | **`memory/` — four-tier, quarantine/promotion, isolation** (§4) |
| Blast-radius descriptor | Enumerate an agent's bounded reach | `platform/blast_radius.py:BlastRadius` (§2.3) |
| Observability pipeline | Tamper-evident ledger + metrics + traces | `security/ledger.py`, `security/metrics.py`; OTel Phase 4 |
| Truth audit | Honest control-status inventory | `security/control_status.py` (`maestro-audit`) |

**Trade-off.** Centralized policy enforcement is a potential bottleneck and a
single point of failure. Mitigation: the enforcement point is pure and
in-process (no network hop), state lives in the durable engine, and the ledger
append is the only I/O on the hot path.

### 2.3 Defining and constraining blast radius

Blast radius is the *first* architectural decision, made before code: the
worst-case financial, data, or physical damage if the agent goes rogue. It is
constrained by construction, not by prompt:

- **Capabilities** bound *what* (action class), *where* (resource), *for whom*
  (tenant), *how deep* (delegation), and *for how long* (TTL).
- **Autonomy budget** bounds *how much* (calls, spend, affected entities, rate).
- **Risk-to-action bands** bound *how autonomously* (`security/risk_engine.py`):
  irreversible / high-impact actions require approval or are denied outright;
  `CAPABILITY_REQUIRED_ACTIONS` (credential access, code execution, exfiltration,
  deletion, irreversible network change, cross-tenant, sub-agent delegation) can
  never ride on model confidence alone.

---

## 3. Control Plane, Dashboard, and **Decision** Observability

### 3.1 UI/UX

Stack: Next.js (React) + Tailwind + a state store (Zustand) + WebSockets for
streaming + a high-performance grid for event review. The repo ships a
self-contained operator surface today (`server/playground.py` at `/playground`,
`server/dashboard.py` at `/`) as the seed; the production control plane adds:

- **Provider onboarding wizard** — API-key injection (into a secret manager, not
  the DB), capability mapping (vision? tool-calling? structured output?
  data-residency? retention mode?), and a live connectivity health check.
- **Agent configuration canvas** — system prompt, attached tools, memory scope,
  assigned policies, and a rendered **blast-radius panel** (write targets, egress
  scope, spend ceiling, delegation depth, approval thresholds, rollback
  availability).
- **Policy versioning UI** — Git-like signed diffs of policy bundles, mandatory
  reviewers, environment promotion, and expiry dates on exceptions. A policy
  change that widens tool scope, tenant reach, egress, or delegation must compute
  a *capability delta* and demand stronger approval + adversarial regression.

### 3.2 ⚑ Correction — Cognitive Observability → **Decision Observability**

The brief specifies a "Live Cognitive Logs Viewer" streaming the agent's raw
chain-of-thought. **Do not build this, and do not store raw CoT as a normal
production artifact.** Raw reasoning traces (a) carry secrets, PII, and
proprietary context; (b) create a high-value exfiltration target; (c) are often
post-hoc rationalizations, not faithful causes of action; (d) are inconsistently
or not exposed across providers. Monitoring reasoning traces is a legitimate
*safety-research signal*, but the raw trace is neither a reliable explanation nor
safe to retain by default.

Replace it with the **decision card** the enforcement point already emits
(`security/enforcement.py:_decision_card`): identity, the *validated* proposal,
evidence references (source IDs + hashes + trust labels), policy result, risk
score and band, action confidence, execution status, and a concise reason
summary — and **never** raw CoT, prompts, or scratchpad (asserted by test).

| Do **not** log by default | Log and retain |
|---|---|
| Raw chain-of-thought / scratchpad | Agent identity, session/trace ID |
| Hidden reasoning tokens | Selected-plan summary |
| Unredacted retrieved documents | Retrieval source IDs, trust labels, hashes |
| Secrets embedded in prompts | Policy version + authorization decision |
| Raw credentials / tokens | Risk score, confidence, escalation reason |
| System-prompt contents | Model/version, latency, cost, token counts |

The dashboard offers a **human-readable decision view** by default with a "raw
payload" toggle for deep debugging (redacted), never raw CoT as the front door.

> **Implementation status (`server/control_api.py`, `server/control_panel.py`).**
> Built: an operator **control panel** served at **`/control`** — a
> self-contained, offline single-page app (no build step, no CDN, all
> HTML/CSS/JS inline, in keeping with the codebase) backed by a `/api/*` REST
> router. It is deliberately thin: every action drives the *real* control plane.
> Tabs — **Overview** (mode, kill switch, ledger integrity, truth-audit
> coverage), **Live Loop** (feed an alert → decision card; halt/resume/shadow/
> reset), **Truth Audit** (the declared→verified ladder), **Ledger** (the
> hash-chained events + integrity badge), **Memory** (quarantined episodic
> records), **Injection Perimeter** (§1 tester), **HMDC Critique** (§5), and
> **MAESTRO Layers** (the 7-layer model + Table-4 matrix). The decision view is
> the CoT-free decision card described above. Tested via `TestClient` in
> `tests/test_control_api.py`. This is the concrete build of §3 (a Next.js SPA
> was descoped in favor of the offline discipline the rest of the repo holds to).

---

## 4. Agent Orchestration, State, and Memory Management

### 4.1 ⚑ Correction — three tiers is not enough; use **five, including
procedural**

A flat "global memory" accessible to all agents is a cross-contamination and
poisoning hazard. Separate memory by *authority*, not just lifetime:

| Class | Store | Lifetime | Write authority | Retrieval rule |
|---|---|---|---|---|
| Working | process / workflow state | current step | system only | session-bound |
| Session | Redis (TTL) | ephemeral | agent via gateway | same tenant + session |
| Episodic | append-only Postgres event store | retention policy | gateway-approved | scoped by agent/tenant/purpose |
| Semantic | versioned vector store + source store | managed | curated ingestion only | filtered by tenant/trust/source/classification |
| **Procedural** | signed policy/config repo | versioned | human-approved CI/CD only | **read-only to agents** |

Procedural memory is the critical addition: an agent must never be able to
rewrite the policies, tool definitions, thresholds, or safety rules that govern
it. This is the memory analog of the executor boundary.

### 4.2 The memory write rule (poisoning defense — the project's TC2)

Every persistent write must satisfy:

```
WriteAllowed = TenantMatch ∧ SchemaValid ∧ SourceProvenanceValid
             ∧ ContentRiskAcceptable ∧ RetentionDefined ∧ PromotionAuthorized
```

Externally sourced content defaults to `trust=untrusted`, `zone=quarantine`,
`eligible_for_planning=false`, `eligible_for_long_term_promotion=false`. This
closes the exact failure the reproduction demonstrates in TC2, where injected
`history.json` entries inflate downstream behavior. Integrity must be
**authenticated** (HMAC hash-chain, key held outside the agent process — the
mechanism in `security/ledger.py`), because a plain hash is worthless if the
attacker who edits the file can recompute it. And integrity is not enough:
provenance says *who supplied the bytes*; a semantic trust stage decides
*whether those bytes should influence planning*.

> **Implementation status (`maestro/memory/`).** This is now **built** as a
> **four-tier** realization of the model above — the conceptual *Working*
> (system-only) and *Session* (agent-writable, ephemeral) rows are both served
> by a single ephemeral **working** tier for now; the security-critical tiers
> are distinct. `MemoryStore` enforces, and `tests/test_memory_integrity.py`
> proves adversarially: **quarantine-on-ingest** (episodic writes land
> `UNTRUSTED` and are excluded from recall — the TC2 defense), **read-only
> procedural** memory, **curated-only semantic** writes, **capability-gated
> promotion** (`cap:memory:promote`, recorded in the ledger), and strict
> **tenant/agent isolation**. **Now wired into the live loop**: `AgentPlatform`
> grounds every authorized action's evidence in a scoped memory record and
> quarantines every detection on ingest, so isolation + quarantine-on-ingest are
> graded `tested` (enforced at the boundary) and the TC2 attack is inert on the
> *running* agent (`tests/test_platform.py`). The remaining refinement is
> Postgres RLS (moving isolation below the application layer); the store also
> shares the platform's ledger, giving one unified tamper-evident trail.

### 4.3 Isolation

Mandatory `tenant_id` + `agent_id` filters at the database layer, enforced by
Row-Level Security in Postgres — not by application code that can be bypassed.
Cross-tenant access is a `CAPABILITY_REQUIRED_ACTION`; there is no autonomous
path to it.

> **Implementation status.** The `MemoryStore` enforces `(tenant, agent)`
> scoping so ordinary reads/writes never cross a scope, and cross-tenant reads
> go through **`recall_cross_scope`**, which requires an explicit
> `cap:memory:cross-tenant-read` bound to the target and records every access in
> the ledger — the "no autonomous path" rule, built and adversarially tested
> (`tests/test_memory_integrity.py`). The isolation is enforced in the store's
> API today; **Postgres RLS is the production hardening** that moves it below the
> application layer.

### 4.4 Automatic provisioning

Registering a provider publishes an event; a listener generates baseline agent
templates matched to that provider's *capabilities* (enabling vision tools only
if the provider is multimodal, structured-output mode only if supported). The
capability contract is normalized in the PAL (§6). Provisioning must inherit the
secure defaults (fail-closed config, planner validation on, egress off), never a
permissive template.

> **Implementation status (`platform/provisioning.py`).** Built: an
> `AgentProvisioner` stands up an `AgentPlatform` by instantiating a bounded
> `PolicyEnvelope` — same tenant, intent vocabulary, budget, and TTLs as the
> cohort — under a capability delegated from the human controller (**secure by
> inheritance**, not a permissive default). Least privilege is structural:
> `allowed_intents` narrows the vocabulary and the gateway then denies
> out-of-envelope actions; provisioning is health-gated (an unavailable provider
> is refused) and audited (`tests/test_provisioning.py`). The
> provider-registration *event listener* that would call this on registry
> changes is the remaining wiring; capability-matched templates (vision/
> structured-output) build on the PAL's capability contract (§6).

---

## 5. Testing, Validation, and the Critique Algorithm

### 5.1 Multi-environment sandboxes

- **Unit** — mocked tool responses (this repo tests the entire connector +
  enforcement stack offline via `httpx.MockTransport`, no network).
- **Integration / edge** — staging APIs with synthetic, anonymized data; mock
  servers (WireMock/Dockerized) that inject 429/503/malformed-JSON to prove
  retry, fallback, and error handling.
- **Shadow mode** — the agent runs in parallel with the incumbent, emitting
  *proposed* actions to the ledger without executing, so behavior is measured
  before it is trusted. **Built**: `AgentPlatform(shadow=True)` runs the full
  decision pipeline and records outcomes but withholds side effects.

### 5.2 Parameterized prompt testing

A view that fans one prompt to 3–5 models and renders outputs side by side with
token counts, latency, and cost — enabling empirical model selection. The
connector registry already backs this (`/api/compare`).

### 5.3 ⚑ Correction — the HMDC algorithm, fixed

The requested HMDC (deterministic-guardrail *models*, prompt↔response cosine
similarity, a fixed `0.2·semantic + 0.8·judge` weight, forced judge CoT) has
four defects: (1) classifiers are not deterministic; (2) semantic similarity
proves neither factuality nor policy compliance nor task completion; (3) fixed
weights do not generalize across domains; (4) forcing judge CoT is unnecessary
and often unavailable. **For agentic systems the highest-quality signal is
environmental verification, not a judge model.** The corrected pipeline:

```
Candidate action / response
 1. Structural validity   — JSON schema, typed action contract, allowed tool     (deterministic)
 2. Deterministic policy  — identity, capability, tenant, egress, budget          (deterministic)
 3. Evidence & grounding  — provenance, freshness, citation entailment, contradiction
 4. Task-specific verifier— tests pass (code) · reconciled totals (finance)
                            · source-supported (health/legal) · simulation (network/robotics)
 5. Probabilistic ensemble— independent critic model + injection/unsafe classifiers  (signals only)
 6. Risk-based decision   — allow · allow+monitor · require approval · deny · quarantine
```

Gates 1–2 are hard and deterministic; gate 4 (environmental verification) is the
strongest correctness signal; gate 5 is *advisory* — a cross-family judge and
classifiers **raise scrutiny**, they do not authorize. Weights within any
scoring stage are calibrated from a labelled evaluation set per task class, not
hard-coded. **Verbosity / self-preference bias** is handled by (a) preferring
environmental verification over judging, (b) using a *different-family* judge to
reduce correlated bias, (c) a conciseness-normalized rubric, and (d) periodic
human-audit calibration — model diversity alone does not eliminate correlated
bias.

`security/metrics.py` already computes the objective half of this from the
ledger: authorization rate, denials-by-stage, **unsafe-action rate** (executed
actions in a hard-deny band — must be 0, a bypass proof), tool-failure rate, and
ledger integrity.

> **Implementation status (`critique/`, `platform/agent_platform.py`).** Built:
> the **HMDCEngine** realizes the corrected pipeline as four *gated* stages —
> deterministic guardrails (dispositive `REJECT`), a semantic-alignment *floor*
> (not a weighted term), **cross-family judges only** (a same-family judge is
> excluded → route to human), and a **variance-aware ensemble** that routes
> disagreement to a human. There is no fixed `0.2·semantic + 0.8·judge`
> weighting; the judge is evidence, never the verdict. Verbosity bias is handled
> by length-normalization in the `RubricJudge`, position bias by
> `compare_pairwise` (both orders). The offline judge/embedder are deterministic
> stand-ins for connector-backed cross-family models. **Shadow mode**
> (`AgentPlatform(shadow=True)`) is the §5.1 sandbox tier — the full decision
> pipeline runs and records but side effects are withheld. Both are graded
> `implemented` (evaluation harness / mode, not wired to gate live actions);
> `tests/test_critique.py`, `tests/test_platform.py`.

---

## 6. Multi-Model Routing, Resilience, and Provider Abstraction

### 6.1 PAL via the adapter pattern

A canonical `ChatRequest`/`ChatResponse` plus a per-provider adapter that
translates to/from native wire formats (`connectors/base.py` +
`connectors/providers/*`). The contract must expose **more than text I/O** — a
capability descriptor (vision, tool-calling, structured output, JSON-schema mode,
streaming, context window, **data residency**, **retention mode**, max output)
and cost/health probes — so routing can respect compliance, not just latency.

### 6.2 Routing

Route on a composite score, not latency alone:

```
S_m = α·Quality_m − β·Latency_p95_m − γ·Cost_m − δ·Risk_m + ε·Availability_m
```

Using p95 latency (not mean) and remaining rate-limit headroom. The common
failure is routing the most sensitive request to the fastest model even though
it lacks the required residency, retention, or safety posture.

### 6.3 ⚑ Correction — fallback must be **policy-aware**, not "transparent"

`connectors/fallback.py` gives health-gated failover today. Silent fallback is
*dangerous* when providers differ in privacy posture or capability. A fallback
request must preserve tenant identity, the original policy requirements, data
residency, the tool-call/schema contract, redaction rules, safety tier, and
audit lineage. Never silently fail over from an enterprise-private deployment to
a public endpoint for a request carrying customer data, source code, or PHI.

### 6.4 Mixture of Agents (MoA)

For high-stakes queries, fan out to N models and have a synthesizer reconcile and
cite consensus. **Trade-off:** ~N× cost and latency; justified only for
critical decision-support where the synthesizer is *itself* subject to the same
enforcement boundary (its output is a proposal, not an authorization). MoA
reduces variance, not adversarial risk — a coordinated indirect injection can
poison all members that share the same retrieved context.

> **Implementation status (`connectors/{routing,policy_fallback,moa}.py`).** All
> three are built over the PAL and tested (`tests/test_multimodel.py`):
> **`LatencyAwareRouter`** explores unmeasured connectors then routes to the
> lowest-p95 healthy one; **`PolicyAwareFallback`** degrades only within a
> request's `min_tier` and raises `PolicyDegradationRefused` (fail closed)
> rather than silently downgrading a high-stakes request — the §6.3 correction
> made concrete; **`MixtureOfAgents`** returns a medoid/aggregator consensus and
> surfaces proposer **disagreement** as a `route_to_human` signal, gated to
> high-stakes bands by `moa_recommended` so its N× cost is a targeted
> escalation. These are connector-layer capabilities (the offline default agent
> uses the deterministic stub reasoner, so they are graded `tested` at the
> connector boundary, not on the live agent loop). Concurrent tail-latency
> *hedging* remains a future async extension of the same p95 signal.

---

## 7. Cross-Domain Architectural Patterns

The framework is one control plane; the *policy pack, verifier, and autonomy
envelope* change per domain. Domain dictates architecture.

- **Software engineering — ReAct + sandbox.** The environment feedback loop
  (write → execute → stack trace → revise) needs a persistent, stateful,
  *isolated* filesystem. The verifier is tests + static analysis + dependency
  scan. Pitfall: broad CI/CD credentials because local tests passed — "patch
  passed tests" and "deploy to prod" are different blast radii requiring
  different capabilities and approvals.

- **Finance / enterprise — Plan-and-Execute + deterministic guardrails.**
  Autonomous execution is permitted *only inside a pre-approved risk envelope*:
  `TradeAllowed = InstrumentAllowed ∧ PositionLimit ∧ LossLimit ∧ Liquidity ∧
  MarketHours ∧ CompliancePass ∧ KillSwitchInactive`. The LLM produces research
  and bounded proposals; a deterministic risk engine owns exposure, margin,
  suitability, and execution limits.

- **Healthcare / legal — strict RAG + citation-backed grounding.** Grounding is
  necessary but insufficient: require provenance and document-version checks,
  jurisdiction/effective-date validation (legal), patient-specific structured
  constraints (health), citation *entailment*, uncertainty disclosure, and a
  hard architectural line between decision *support* and autonomous decision.
  If no verifiable source is retrieved, the system is forced to say "I don't
  know," not extrapolate.

- **Robotics / embodied — HTN + brain/spinal-cord split.** The LLM does semantic
  goal decomposition only; a symbolic planner produces a constraint-checked
  plan; a safety monitor enforces hard motion/force/workspace limits; a verified
  low-level controller (PID/MPC/RL) executes; an **independent** hardware/software
  e-stop sits outside the LLM loop. The LLM must never emit raw motor commands.

> **Implementation status (`domains/`).** Built: four `DomainPack`s, each pairing
> a reasoning pattern with its **environmental verifier** — the deterministic
> correctness signal that is stronger than any judge: `TestSuiteVerifier`
> (tests pass), `ReconciliationVerifier` (double-entry balances + limits),
> `CitationVerifier` (source-grounded, uncited claim hard-fails),
> `SafetyEnvelopeVerifier` (the spinal-cord veto on out-of-envelope motion).
> Crucially this **closes the §5 gap**: each verifier is wired into `HMDCEngine`
> as a `task_gate` that runs *before* the probabilistic judges and
> short-circuits a verification failure (`tests/test_domains.py`). The packs are
> reference specializations; a production deployment maps each domain's actions
> into the `INTENT_REGISTRY` and issues the matching capabilities.

---

## 8. Strategic Implementation Roadmap & Practitioner Pitfalls

### 8.1 Phased roadmap (security-critical ordering)

- **Phase 0 — Truth audit & threat model.** Enumerate assets, trust boundaries,
  tools, data classes, side-effect boundaries, and agent risk tiers. Classify
  every control `declared → implemented → enforced → tested → verified` and fail
  the build on overstatement. **Done** (`security/control_status.py`,
  `maestro-audit`, `security/risk_engine.py`).
- **Phase 1 — Secure execution foundation.** Agent identity + lifecycle,
  capability tokens, the policy-enforcement point, secrets abstraction, tenant
  isolation, durable action state machine, signed policies, tamper-evident
  audit, fail-closed config. **Partially done** (enforcement point, capabilities,
  ledger, budget, breaker exist as tested components; opt-in auth + SSRF guard
  shipped). *Remaining: secrets manager, signed policy bundles, fail-closed
  server config.*
- **Phase 2 — Provider & workflow layer.** PAL (**done**: `connectors/`),
  **latency-aware routing (done)**, **policy-aware fallback (done)**,
  **Mixture-of-Agents (done)**, durable orchestration (Temporal),
  timeouts/idempotency/rollback/compensation. *The keystone
  integration is **done**: `platform/agent_platform.py` routes the live loop
  (alert → reasoner proposes → enforcement point authorizes/executes/records)
  through the enforcement point — it is now the only path from a model output to
  a side effect, so **10 controls** are graded `enforced` at the side-effect
  boundary (including memory isolation + quarantine-on-ingest, now that evidence
  is grounded in the scoped memory store) and `unsafe_action_rate` is `0.0`
  (`tests/test_platform.py`, `maestro-agent`).
  **Durable orchestration is also built** (`orchestration/`): an offline,
  event-sourced engine giving exactly-once activities across a crash, retries,
  and timeouts (`tests/test_orchestration.py`) — Temporal.io is the production
  backing. Remaining: making durable mode the default runtime, real sandbox/SOAR
  adapters, rollback/compensation.*
- **Phase 3 — Memory & evidence.** Tiered memory, quarantine pipeline,
  provenance/trust labels, promotion controls, evidence graph, decision-trace
  UI. *Tamper-evident ledger done; the **four-tier memory store with
  quarantine-on-ingest, capability-gated promotion, read-only procedural memory,
  and tenant/agent isolation is built and now WIRED into the live loop** —
  `AgentPlatform` grounds every action's evidence in a scoped memory record, so
  the TC2 poisoning defense is enforced on the running agent (10 boundary
  controls, up from 8). Remaining: Postgres RLS, the Working/Session split,
  evidence graph, and decision-trace UI.*
- **Phase 4 — Evaluation, monitoring, multi-agent.** TC3–TC15 adversarial
  corpus (prompt injection, RAG injection, tool-arg smuggling, confused deputy,
  connector compromise, exfiltration, rogue delegation, log tampering, rollback
  attack, cross-tenant leak, unsafe code exec), shadow mode, isolated packet
  capture, OTel/Prometheus/Grafana, and — only after the single-agent baseline
  is safe — narrowly scoped sub-agents.

### 8.2 Critical trade-offs

- **Autonomy vs. latency/cost.** Every critic, reflection, and MoA step adds
  safety and multiplies latency/cost. Find the Pareto frontier per use case;
  reserve MoA and multi-critic pipelines for high-blast-radius actions.
- **Flexibility vs. determinism.** Strict state machines are safe but brittle on
  novel input; pure LLM planning is flexible but unpredictable. The resolution
  is *layering*: deterministic authorization envelope, flexible proposal
  generation inside it.
- **Observability vs. exfiltration surface.** Full logging without redaction is
  itself a breach vector — hence decision cards over raw CoT.

### 8.3 Common practitioner mistakes

1. **Over-engineering multi-agent systems.** A "team" of planner/researcher/
   critic/writer agents where one agent with good tools and a durable workflow
   suffices. Add an agent only for a *distinct authority, data, tool, evaluation,
   or async boundary* that cannot be a deterministic workflow step. Multi-agent
   multiplies debugging and state-management complexity and can manufacture an
   illusion of consensus.
2. **Treating the LLM as a deterministic planner.** It is probabilistic;
   expecting flawless 15-step execution is a design error. Decompose into small,
   independently verifiable sub-goals.
3. **Ignoring state management.** No checkpointing/memory ⇒ failure on
   long-horizon tasks. Durable execution and tiered memory are foundational.
4. **Security as an afterthought.** Guardrails bolted on at the end. Enforcement,
   capabilities, sandboxing, and audit are day-one architecture — which is why
   Phase 0 is a threat model and truth audit, not a dashboard.
5. **Mistaking hashes for authorization**, **trusting an LLM guard as the policy
   authority**, **putting checks only in the planner** (the executor boundary is
   the one that matters), and **equating "tests pass" with "secure"** (controls
   must be tested against *bypass*, not just happy paths).

---

## Key Takeaways

1. **One principle governs everything:** the LLM *proposes*; deterministic
   services *authorize, execute, verify, and record*. Authority never lives in
   the model, a guard model, or a confidence score.
2. **Blast radius is the first design decision**, enforced by capabilities
   (what/where/whom/depth/TTL), autonomy budgets (how much), and risk bands (how
   autonomously) — not by prompt engineering.
3. **Observe decisions, not cognition.** Emit tamper-evident decision cards with
   evidence, policy result, and risk; never make raw chain-of-thought the default
   artifact — it is unreliable as explanation and dangerous as a store.
4. **Confidence must come from independent signals, not model self-report**, and
   may only *raise* scrutiny — a hard rule (capability-required action, risk
   hard-deny) always wins.
5. **Environmental verification beats judge models.** Tests, reconciliations,
   simulations, and postconditions are the truth; a cross-family judge and
   classifiers are advisory signals, never the authorizer.
6. **Memory must be tiered, isolated, provenance-labeled, quarantined by default,
   and — for procedural memory — read-only to agents.** Authenticated integrity
   (HMAC hash-chain) plus semantic trust; a bare hash proves nothing.
7. **Fallback and routing are policy-aware**, preserving tenant, residency,
   retention, and safety tier — transparent failover to a weaker-posture provider
   is a data-governance incident waiting to happen.
8. **Measure the gap, don't hide it.** The truth audit that fails the build when
   a control claims more than its evidence supports is the difference between a
   *demo* and an *enterprise control plane* — the defensible identity of this
   platform is the ability to prove, for every consequential action: which agent
   acted, under whose authority, on what evidence, under which policy, within
   what capability, what actually happened, and whether it was verified or rolled
   back.
