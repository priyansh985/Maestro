"""``maestro-agent`` — a runnable demo of the live enforcement loop.

Feeds a short, deterministic sequence of telemetry alerts through the
:class:`~maestro.platform.AgentPlatform` and prints, for each one, the reasoned
proposal and the enforcement point's decision — then the ledger integrity and
ledger-derived operational metrics.

The point of the demo is to *show*, offline and without an API key, the two
things the truth audit now grades ``enforced``:

* a legitimate reversible mitigation is authorized under a scoped capability and
  actually executed (an adapter effect appears);
* a rogue / out-of-scope proposal is denied or quarantined at the gateway.

Every outcome — allow *and* deny — is recorded in the tamper-evident ledger, so
``unsafe_action_rate`` (executions that never cleared the gateway) is 0 by
construction. That zero is the bypass proof.

Run with: ``python -m maestro.platform.demo``  (or ``maestro-agent``).
"""
from __future__ import annotations

import sys

from ..agent.reasoning import ReasoningResult
from ..security.metrics import compute_metrics
from ..telemetry.detection import Alert, AlertClass
from .agent_platform import AgentPlatform, PlatformResult


class _FixedReasoner:
    """A reasoner that proposes a caller-chosen action (to script the demo)."""

    def __init__(self, action: str) -> None:
        self._action = action

    def reason(self, alert: Alert, ctx: dict | None = None) -> ReasoningResult:
        return ReasoningResult(summary=f"proposing {self._action}",
                               severity=alert.severity, action=self._action)


def _print_outcome(label: str, result: PlatformResult) -> None:
    card = result.decision_card
    mark = "ALLOW " if result.allowed else "DENY  "
    print(f"\n[{label}] alert={result.alert_class}  ->  proposed '{result.proposed_action}'")
    print(f"   {mark} decision={result.decision}  reason={result.reason}")
    print(f"   execution_status={card.get('execution_status')}  "
          f"state={result.enforcement.state.value}")
    effect = (result.enforcement.output or {}).get("effect")
    if effect:
        print(f"   effect={effect!r}")


def main() -> int:
    print("MAESTRO-SecOps — live enforcement loop demo (offline, no API key)")
    print("=" * 66)
    print("An LLM proposes intentions; deterministic services authorize, "
          "execute,\nverify, and record. There is no bypass path to a tool.")

    platform = AgentPlatform()

    # 1) A baseline reading: the stub proposes a no-op, which is allowed.
    _print_outcome(
        "baseline", platform.handle_alert(
            Alert(1000.0, AlertClass.NORMAL, 0.1, "within envelope")))

    # 2) An anomaly: the stub proposes raising detection thresholds — a
    #    reversible mitigation, authorized with safeguards and executed.
    _print_outcome(
        "anomaly", platform.handle_alert(
            Alert(1001.0, AlertClass.ANOMALY, 0.6, "elevated packet rate")))

    # 3) A DoS: throttle the telemetry stream — reversible, executed.
    _print_outcome(
        "dos", platform.handle_alert(
            Alert(1002.0, AlertClass.DOS, 0.95, "packet flood; CPU saturated")))

    # 4) A rogue model proposes an out-of-scope, irreversible action the
    #    platform never provisioned a capability for -> denied at the gateway.
    rogue = AgentPlatform(reasoner=_FixedReasoner("block_source_ip"))
    _print_outcome(
        "rogue", rogue.handle_alert(
            Alert(1003.0, AlertClass.DOS, 0.95, "flood (rogue proposes IP block)")))

    # 5) An unknown intent entirely -> quarantined by the typed schema.
    junk = AgentPlatform(reasoner=_FixedReasoner("exfiltrate_everything"))
    _print_outcome(
        "unknown", junk.handle_alert(
            Alert(1004.0, AlertClass.DOS, 0.95, "flood (rogue proposes junk)")))

    # Ledger integrity + operational metrics for the main platform's 3 actions.
    print("\n" + "-" * 66)
    intact = platform.ledger.verify_chain() == -1
    metrics = compute_metrics(platform.ledger)
    print(f"ledger: {len(platform.ledger)} entries, chain intact = {intact}")
    print(f"metrics: total_actions={metrics['total_actions']}  "
          f"authorized={metrics['authorized']}  denied={metrics['denied']}")
    print(f"         unsafe_action_rate={metrics['unsafe_action_rate']} "
          "(0.0 == no side effect ever bypassed the gateway)")

    # Bypass proof is the invariant the demo asserts before returning success.
    if not intact or metrics["unsafe_action_rate"] != 0.0:
        print("\nDEMO FAILED — ledger tampered or an unsafe action bypassed the gateway.")
        return 1
    print("\nDemo OK — every side effect was authorized; every outcome recorded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
