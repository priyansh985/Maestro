"""Blast-radius descriptor (blueprint §2 — "define and constrain the blast radius").

The blueprint's discipline: *an agent's blast radius must be legible in one
screen* — if you cannot enumerate it, you have not bounded it. This module makes
that enumeration a concrete, testable object built from what the agent actually
holds, not from prose:

* **capabilities** — the ``cap:...`` scopes the agent has been delegated;
* **intent vocabulary** — the allow-listed intents it may even propose;
* **reversible vs. irreversible** split — the reversibility classes it can act in;
* **budget envelope** — the hard ceilings on calls / spend / blast / rate.

An empty ``irreversible`` set is itself a security statement: this agent holds
only reversible capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BlastRadius:
    """A one-screen, machine-checkable enumeration of an agent's bounded reach."""

    agent_id: str
    tenant: str
    capabilities: tuple[str, ...]
    intent_vocabulary: tuple[str, ...]
    reversible_intents: tuple[str, ...]
    irreversible_intents: tuple[str, ...]
    budget: dict[str, object]

    def as_dict(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "tenant": self.tenant,
            "capabilities": list(self.capabilities),
            "intent_vocabulary": list(self.intent_vocabulary),
            "reversible_intents": list(self.reversible_intents),
            "irreversible_intents": list(self.irreversible_intents),
            "budget": self.budget,
        }

    @property
    def holds_irreversible_capability(self) -> bool:
        """True if the agent can act in any irreversible class (elevated risk)."""
        return bool(self.irreversible_intents)

    def summary(self) -> str:
        """A compact, human-readable one-screen rendering."""
        budget = ", ".join(f"{k}={v}" for k, v in self.budget.items() if v is not None) or "unbounded"
        lines = [
            f"blast radius — {self.agent_id} @ tenant {self.tenant!r}",
            f"  capabilities   ({len(self.capabilities)}): {', '.join(self.capabilities)}",
            f"  intents        ({len(self.intent_vocabulary)}): "
            f"{', '.join(self.intent_vocabulary)}",
            f"  reversible     ({len(self.reversible_intents)}): "
            f"{', '.join(self.reversible_intents) or '—'}",
            f"  irreversible   ({len(self.irreversible_intents)}): "
            f"{', '.join(self.irreversible_intents) or '—'}",
            f"  budget         : {budget}",
        ]
        return "\n".join(lines)
