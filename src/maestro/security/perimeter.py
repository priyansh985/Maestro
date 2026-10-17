"""The dual-LLM injection perimeter (blueprint §1 — the L1 input boundary).

The single most important structural defense against prompt injection is *not*
a better classifier — it is an architecture in which **untrusted content can
never reach the privileged execution path as instructions**. This module is the
offline, deterministic realization of the dual-LLM pattern:

* a **quarantined** stage (:class:`InjectionScanner` + variable extraction)
  processes untrusted input. It may only emit *typed symbolic variables* — an
  IP, a port, an integer count, a CVE id — never free-form imperative text. It
  holds no capability and can invoke nothing.
* a **privileged** stage (the rest of the platform: the reasoner, the
  :class:`~maestro.security.enforcement.PolicyEnforcementPoint`) consumes only
  those symbolic variables plus already-trusted content. It never sees raw
  untrusted text *as instructions*.

The perimeter renders a :class:`Disposition` for every piece of external
content:

* ``ADMIT`` — no injection signal; the content is ordinary data. Even so, only
  its extracted variables cross the boundary; the prose does not become a prompt.
* ``QUARANTINE`` — an instruction-shaped or obfuscated payload. The content is
  admissible only as *inert*, :data:`~maestro.memory.TrustLabel.UNTRUSTED` data
  (the same quarantine-on-ingest the memory tier enforces); it can be stored and
  cited as evidence but can never influence the agent.
* ``BLOCK`` — an *active* attempt to invoke tools or exfiltrate secrets. This is
  refused outright: it is not the kind of thing you keep around as data.

Everything here is regex/stdlib and deterministic, so the boundary is unit
testable without a model — which is the point: the security property is
structural, not statistical. The scanner *raises* scrutiny; it can never be the
sole thing that authorizes an action.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from ..memory.records import TrustLabel


class Disposition(str, Enum):
    """What the perimeter decided to do with a piece of external content."""

    ADMIT = "admit"            # clean data; variables cross, prose stays inert
    QUARANTINE = "quarantine"  # instruction-shaped; admit only as UNTRUSTED data
    BLOCK = "block"            # active tool-abuse / exfiltration; refuse entirely


class SignalCategory(str, Enum):
    """The family of injection an :class:`InjectionSignal` belongs to.

    ``TOOL_INVOCATION`` and ``EXFILTRATION`` are *active* — they attempt to make
    something happen — and therefore drive a BLOCK. The rest are *instruction
    shaped* — they try to steer the model — and drive QUARANTINE.
    """

    INSTRUCTION_OVERRIDE = "instruction_override"
    DELIMITER_BREAKOUT = "delimiter_breakout"
    OBFUSCATION = "obfuscation"
    TOOL_INVOCATION = "tool_invocation"
    EXFILTRATION = "exfiltration"


#: Categories that represent an *active* attempt to act, not merely to persuade.
_ACTIVE_CATEGORIES: frozenset[SignalCategory] = frozenset(
    {SignalCategory.TOOL_INVOCATION, SignalCategory.EXFILTRATION})


@dataclass(frozen=True)
class InjectionSignal:
    """One matched injection pattern with a short, redacted excerpt."""

    category: SignalCategory
    pattern: str
    severity: float      # 0..1 contribution to the aggregate injection score
    excerpt: str         # the matched span (already length-bounded)

    def as_dict(self) -> dict[str, object]:
        return {
            "category": self.category.value,
            "pattern": self.pattern,
            "severity": round(self.severity, 3),
            "excerpt": self.excerpt,
        }


@dataclass(frozen=True)
class SymbolicVariable:
    """A typed value extracted from untrusted content.

    This is the *only* thing permitted to cross into the privileged path. It has
    a ``kind`` and a validated ``value`` and carries no imperative content, so a
    downstream consumer treats it as data, never as a prompt.
    """

    name: str
    kind: str            # ip | port | count | cve | sha256 | url_host
    value: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "kind": self.kind, "value": self.value}


@dataclass
class PerimeterResult:
    """The perimeter's ruling on one piece of external content."""

    disposition: Disposition
    trust: TrustLabel
    injection_score: float
    signals: list[InjectionSignal] = field(default_factory=list)
    variables: list[SymbolicVariable] = field(default_factory=list)
    source: str = ""
    reason: str = ""

    @property
    def admitted(self) -> bool:
        """True if any form of the content may enter the system (as data)."""
        return self.disposition is not Disposition.BLOCK

    @property
    def influential(self) -> bool:
        """True only if the content may influence the agent (clean + admitted).

        Quarantined content is admitted but *not* influential — exactly the
        guarantee the memory tier makes about UNTRUSTED records.
        """
        return self.disposition is Disposition.ADMIT

    def as_dict(self) -> dict[str, object]:
        return {
            "disposition": self.disposition.value,
            "trust": self.trust.value,
            "injection_score": round(self.injection_score, 3),
            "influential": self.influential,
            "admitted": self.admitted,
            "signals": [s.as_dict() for s in self.signals],
            "variables": [v.as_dict() for v in self.variables],
            "source": self.source,
            "reason": self.reason,
        }


# --------------------------------------------------------------------------- #
# Detection: deterministic, case-insensitive, category-tagged patterns.
# --------------------------------------------------------------------------- #
#: (compiled pattern, category, per-hit severity). Ordered most-to-least severe
#: within a category for readable reporting; order does not affect the ruling.
_PATTERNS: list[tuple[re.Pattern[str], SignalCategory, float]] = [
    # --- active: attempts to actually do something (→ BLOCK) ----------------- #
    (re.compile(r"\brm\s+-rf\b", re.I), SignalCategory.TOOL_INVOCATION, 0.9),
    (re.compile(r"\b(?:curl|wget)\s+https?://", re.I), SignalCategory.TOOL_INVOCATION, 0.8),
    (re.compile(r";\s*drop\s+table\b", re.I), SignalCategory.TOOL_INVOCATION, 0.9),
    (re.compile(r"\$\([^)]+\)|`[^`]+`"), SignalCategory.TOOL_INVOCATION, 0.7),
    (re.compile(r"<\s*tool_call\b|<\s*function_call\b|\"tool_calls?\"\s*:", re.I),
     SignalCategory.TOOL_INVOCATION, 0.8),
    (re.compile(r"\b(?:invoke|execute|run)\s+the\s+(?:following|command|tool)\b", re.I),
     SignalCategory.TOOL_INVOCATION, 0.6),
    (re.compile(r"\b(?:exfiltrat\w+|send|e-?mail|post|upload|leak)\b[^.\n]{0,40}"
                r"\b(?:system\s+prompt|api[_\s-]?key|secret|credential|password|token)\b", re.I),
     SignalCategory.EXFILTRATION, 0.9),
    (re.compile(r"\b(?:reveal|print|repeat|show|dump)\b[^.\n]{0,30}"
                r"\b(?:system\s+prompt|instructions|api[_\s-]?key|secret)\b", re.I),
     SignalCategory.EXFILTRATION, 0.8),
    # --- instruction-shaped: attempts to steer the model (→ QUARANTINE) ------ #
    (re.compile(r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+"
                r"(?:instructions?|prompts?|messages?|rules?)\b", re.I),
     SignalCategory.INSTRUCTION_OVERRIDE, 0.7),
    (re.compile(r"\bdisregard\b[^.\n]{0,30}\b(?:instructions?|rules?|policy|guidelines?)\b", re.I),
     SignalCategory.INSTRUCTION_OVERRIDE, 0.7),
    (re.compile(r"\bforget\s+(?:everything|all|your\s+(?:instructions?|training))\b", re.I),
     SignalCategory.INSTRUCTION_OVERRIDE, 0.6),
    (re.compile(r"\byou\s+are\s+now\b|\bnew\s+instructions?\s*:|\bfrom\s+now\s+on\b", re.I),
     SignalCategory.INSTRUCTION_OVERRIDE, 0.5),
    (re.compile(r"\b(?:act|behave|respond)\s+as\b[^.\n]{0,30}|\bpretend\s+(?:to\s+be|that|you)\b",
                re.I), SignalCategory.INSTRUCTION_OVERRIDE, 0.4),
    (re.compile(r"\bdeveloper\s+mode\b|\bjailbreak\b|\bDAN\b"),
     SignalCategory.INSTRUCTION_OVERRIDE, 0.5),
    (re.compile(r"</?\s*(?:system|assistant|user|inst)\s*>|\[/?\s*INST\s*\]", re.I),
     SignalCategory.DELIMITER_BREAKOUT, 0.6),
    (re.compile(r"(?m)^\s*(?:system|assistant)\s*:", re.I),
     SignalCategory.DELIMITER_BREAKOUT, 0.5),
    (re.compile(r"```+\s*(?:system|tool|python|bash|sh)\b", re.I),
     SignalCategory.DELIMITER_BREAKOUT, 0.4),
    # --- chain-of-thought / reasoning extraction (→ QUARANTINE) --------------- #
    (re.compile(r"\b(?:show|reveal|display|output|print)\b[^.\n]{0,30}"
                r"\b(?:reasoning|thinking|chain.of.thought|step.by.step|rationale)\b", re.I),
     SignalCategory.INSTRUCTION_OVERRIDE, 0.5),
    (re.compile(r"\b(?:reasoning|thinking|chain.of.thought)\b[^.\n]{0,30}"
                r"\b(?:show|reveal|display|output|print)\b", re.I),
     SignalCategory.INSTRUCTION_OVERRIDE, 0.5),
    # --- SYSTEM OVERRIDE pattern (→ QUARANTINE) ------------------------------- #
    (re.compile(r"\bSYSTEM\s+OVERRIDE\b", re.I),
     SignalCategory.INSTRUCTION_OVERRIDE, 0.8),
    # --- obfuscation: hiding a payload from a naive reader (→ QUARANTINE) ----- #
    (re.compile(r"(?:\\x[0-9a-f]{2}){4,}|(?:\\u[0-9a-f]{4}){3,}", re.I),
     SignalCategory.OBFUSCATION, 0.5),
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), SignalCategory.OBFUSCATION, 0.4),
]

#: Aggregate injection score at/above which instruction-shaped content is
#: quarantined rather than admitted. Any *active* signal blocks regardless.
_QUARANTINE_THRESHOLD = 0.4

#: Cap a single excerpt so reports never echo an entire hostile payload back.
_EXCERPT_MAX = 80


# --------------------------------------------------------------------------- #
# Extraction: the only content permitted to cross into the privileged path.
# --------------------------------------------------------------------------- #
_EXTRACTORS: list[tuple[str, re.Pattern[str]]] = [
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    ("sha256", re.compile(r"\b[0-9a-f]{64}\b", re.I)),
    ("port", re.compile(r"\bport\s+(\d{1,5})\b", re.I)),
    ("count", re.compile(r"\b(\d{1,12})\s*(?:packets?|pps|connections?|requests?)\b", re.I)),
]


def _valid_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _valid_port(value: str) -> bool:
    return value.isdigit() and 0 <= int(value) <= 65535


class InjectionScanner:
    """Deterministic, category-tagged prompt-injection detector.

    Stateless and pure: the same content always yields the same signals, so the
    perimeter's behavior is fully reproducible and testable offline.
    """

    def scan(self, content: str) -> list[InjectionSignal]:
        signals: list[InjectionSignal] = []
        for pattern, category, severity in _PATTERNS:
            match = pattern.search(content)
            if match is not None:
                excerpt = match.group(0).strip()
                if len(excerpt) > _EXCERPT_MAX:
                    excerpt = excerpt[:_EXCERPT_MAX] + "…"
                signals.append(InjectionSignal(category, pattern.pattern, severity, excerpt))
        return signals


def extract_variables(content: str) -> list[SymbolicVariable]:
    """Pull typed, validated values out of untrusted content.

    This is the narrow gate: whatever is returned here — and *only* this — is
    what the privileged path is allowed to consume. Each value is validated for
    its kind (an out-of-range octet is not an IP), de-duplicated, and named
    positionally so a consumer references ``ip_0`` rather than interpolating raw
    text.
    """
    out: list[SymbolicVariable] = []
    seen: set[tuple[str, str]] = set()
    counters: dict[str, int] = {}
    for kind, pattern in _EXTRACTORS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            value = value.strip()
            if kind == "ip" and not _valid_ip(value):
                continue
            if kind == "port" and not _valid_port(value):
                continue
            key = (kind, value.lower())
            if key in seen:
                continue
            seen.add(key)
            idx = counters.get(kind, 0)
            counters[kind] = idx + 1
            out.append(SymbolicVariable(name=f"{kind}_{idx}", kind=kind, value=value))
    return out


class DualLLMPerimeter:
    """The L1 input boundary: quarantine untrusted content, admit only variables.

    Usage::

        perimeter = DualLLMPerimeter()
        result = perimeter.ingest(external_text, source="pcap:comment")
        if result.admitted:
            store.remember(scope, EPISODIC, external_text,
                           source=result.source)   # lands UNTRUSTED
        privileged_inputs = result.variables       # the only thing that crosses
    """

    def __init__(self, scanner: InjectionScanner | None = None,
                 *, quarantine_threshold: float = _QUARANTINE_THRESHOLD) -> None:
        self._scanner = scanner if scanner is not None else InjectionScanner()
        self._threshold = quarantine_threshold

    def ingest(self, content: str, *, source: str = "external") -> PerimeterResult:
        """Rule on one piece of external content. Never raises on hostile input."""
        signals = self._scanner.scan(content)
        variables = extract_variables(content)
        score = min(1.0, sum(s.severity for s in signals))
        active = [s for s in signals if s.category in _ACTIVE_CATEGORIES]

        if active:
            # An active tool/exfiltration attempt is refused, not retained.
            cats = ", ".join(sorted({s.category.value for s in active}))
            return PerimeterResult(
                Disposition.BLOCK, TrustLabel.UNTRUSTED, score, signals, variables,
                source, reason=f"blocked: active attempt ({cats})")

        if score >= self._threshold:
            # Instruction-shaped but inert: keep as quarantined data only.
            return PerimeterResult(
                Disposition.QUARANTINE, TrustLabel.UNTRUSTED, score, signals, variables,
                source, reason="quarantined: instruction-shaped content, admitted "
                               "as inert untrusted data (cannot influence the agent)")

        return PerimeterResult(
            Disposition.ADMIT, TrustLabel.UNTRUSTED, score, signals, variables,
            source, reason="admitted: no injection signal; only extracted "
                           "variables cross into the privileged path")
