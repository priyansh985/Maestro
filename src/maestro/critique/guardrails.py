"""Stage 1 — deterministic guardrails (the dispositive gate).

This stage is the only one that can *hard-fail* a candidate, and it does so with
**no false-negative rate to argue about**: schema/format validity, forbidden
content (secrets, PII, private keys), and emptiness are deterministic facts, not
probabilistic judgments. Nothing that fails here proceeds to the semantic or
judge stages — that ordering is the whole point of HMDC (a fluent, well-liked
answer that leaks a secret is still a reject).
"""
from __future__ import annotations

import json
import re

from .types import Candidate, CritiqueSpec, GuardrailResult

#: Built-in content guardrails — deterministic, high-confidence leak signatures.
DEFAULT_FORBIDDEN_PATTERNS: tuple[str, ...] = (
    r"AKIA[0-9A-Z]{16}",                        # AWS access key id
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",      # PEM private key block
    r"password\s*[:=]\s*\S+",                   # inline password assignment
    r"\b\d{3}-\d{2}-\d{4}\b",                   # US SSN
)


def deterministic_guardrails(
    candidate: Candidate,
    spec: CritiqueSpec,
    *,
    extra_forbidden: tuple[str, ...] = (),
) -> GuardrailResult:
    """Return the hard pass/fail gate result for a candidate."""
    failures: list[str] = []
    text = candidate.text

    if not text.strip():
        failures.append("empty-output")

    if spec.required_format == "json":
        try:
            json.loads(text)
        except (json.JSONDecodeError, ValueError):
            failures.append("format:not-json")

    for pattern in (*extra_forbidden, *spec.forbidden_patterns):
        if re.search(pattern, text, re.IGNORECASE):
            failures.append(f"forbidden-pattern:{pattern}")

    return GuardrailResult(passed=not failures, failures=tuple(failures))
