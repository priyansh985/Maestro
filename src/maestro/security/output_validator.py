"""Deterministic LLM output policy validator (CTRL-L1-01).

The L1 *input* boundary (:mod:`maestro.security.perimeter`) keeps untrusted
content from steering the model. This module is the complementary *output*
boundary: a reasoner's proposed action / summary / metadata is checked against
an explicit, deterministic policy *before* it is allowed to become a typed
proposal on the live loop. No model is involved -- the check is pure stdlib, so
it is reproducible and unit-testable offline, consistent with the rest of the
security plane.

A result is a small record::

    OutputValidationResult(passed=bool, violations=list[str], sanitized=...)

``passed`` is True only when *every* policy check succeeds. ``sanitized`` is a
cleaned copy of the inputs on success (or ``None`` on failure) so a caller can
forward the validated payload rather than the raw model text.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .perimeter import InjectionScanner

# --------------------------------------------------------------------------- #
# Policy defaults
# --------------------------------------------------------------------------- #
DEFAULT_MAX_SUMMARY_LENGTH = 1000
DEFAULT_MAX_ACTION_LENGTH = 128
DEFAULT_MAX_METADATA_BYTES = 8192


_SMUGGLING_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\$\([^)]*\)|`[^`]*`"), "command substitution"),
    (re.compile(r"\s&&\s|\s\|\|\s"), "shell chaining (&&/||)"),
    (re.compile(r";\s*(?:rm|del|curl|wget|nc|bash|sh|python|perl|ruby|powershell|cmd|drop|delete|truncate)\b", re.I),
     "shell/sql chaining"),
    (re.compile(r"\|\s*(?:sh|bash|python|nc|curl|wget|perl|ruby)\b", re.I), "pipe to interpreter"),
    (re.compile(r"\.\./"), "path traversal"),
    (re.compile(r"\bunion\s+select\b", re.I), "sql injection"),
    (re.compile(r"\b(?:drop|delete|truncate)\s+table\b", re.I), "sql destructive"),
    (re.compile(r"<\s*/?\s*(?:script|iframe|img|svg|object)\b", re.I), "html injection"),
]


@dataclass
class OutputValidationResult:
    passed: bool
    violations: list[str] = field(default_factory=list)
    sanitized: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": list(self.violations),
            "sanitized": self.sanitized,
        }


ValidationResult = OutputValidationResult
OutputValidatorResult = OutputValidationResult


def _allowed_intents_default() -> set[str]:
    try:
        from .action import INTENT_REGISTRY

        return set(INTENT_REGISTRY.keys())
    except Exception:
        return set()


def _coerce_inputs(action_or_result, summary, metadata):
    if summary is None and metadata is None:
        obj = action_or_result
        if hasattr(obj, "action"):
            action = getattr(obj, "action", None)
            summary = getattr(obj, "summary", None)
            metadata = getattr(obj, "metadata", None)
            return action, summary, metadata
        if isinstance(obj, Mapping):
            action = obj.get("action", obj.get("intent"))
            summary = obj.get("summary", obj.get("reason", ""))
            metadata = obj.get("metadata", None)
            return action, summary, metadata
        return obj, "", None
    return action_or_result, summary, metadata


def _collect_strings(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, Mapping):
        for v in obj.values():
            out.extend(_collect_strings(v))
    elif isinstance(obj, list | tuple | set):
        for v in obj:
            out.extend(_collect_strings(v))
    return out


class OutputValidator:
    def __init__(
        self,
        *,
        allowed_intents: Iterable[str] | None = None,
        allowed_targets: Iterable[str] | None = None,
        max_summary_length: int = DEFAULT_MAX_SUMMARY_LENGTH,
        max_action_length: int = DEFAULT_MAX_ACTION_LENGTH,
        max_metadata_bytes: int = DEFAULT_MAX_METADATA_BYTES,
    ) -> None:
        if allowed_intents is None:
            self._allowed_intents: set[str] | None = _allowed_intents_default()
        else:
            self._allowed_intents = set(allowed_intents)
        self._allowed_targets: set[str] | None = (
            set(allowed_targets) if allowed_targets is not None else None
        )
        self._max_summary = int(max_summary_length)
        self._max_action = int(max_action_length)
        self._max_metadata = int(max_metadata_bytes)
        self._scanner = InjectionScanner()

    @property
    def allowed_intents(self) -> set[str] | None:
        return self._allowed_intents

    def validate(
        self,
        action_or_result: Any,
        summary: Any = None,
        metadata: Any = None,
    ) -> OutputValidationResult:
        action, summary, metadata = _coerce_inputs(action_or_result, summary, metadata)

        violations: list[str] = []

        action_str = "" if action is None else str(action).strip()
        if not action_str:
            violations.append("empty action")
        if action_str and len(action_str) > self._max_action:
            violations.append(
                f"action exceeds length cap ({len(action_str)} > {self._max_action})"
            )
        if self._allowed_intents is not None and action_str and action_str not in self._allowed_intents:
            violations.append(
                f"action {action_str!r} is not in the allowed intent set"
            )
        for sig in self._scanner.scan(action_str):
            violations.append(f"prompt-injection marker in action: {sig.category.value}")
        for pat, label in _SMUGGLING_PATTERNS:
            if pat.search(action_str):
                violations.append(f"tool-argument smuggling in action ({label})")

        summary_str = "" if summary is None else str(summary)
        if len(summary_str) > self._max_summary:
            violations.append(
                f"summary exceeds length cap ({len(summary_str)} > {self._max_summary})"
            )
        for sig in self._scanner.scan(summary_str):
            violations.append(
                f"prompt-injection marker in summary: {sig.category.value}"
            )
        for pat, label in _SMUGGLING_PATTERNS:
            if pat.search(summary_str):
                violations.append(f"tool-argument smuggling in summary ({label})")

        try:
            serialized = json.dumps(metadata, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            serialized = repr(metadata)
        if len(serialized) > self._max_metadata:
            violations.append(
                f"metadata exceeds size cap ({len(serialized)} > {self._max_metadata})"
            )
        for leaf in _collect_strings(metadata):
            for sig in self._scanner.scan(leaf):
                violations.append(
                    f"prompt-injection marker in metadata: {sig.category.value}"
                )
            for pat, label in _SMUGGLING_PATTERNS:
                if pat.search(leaf):
                    violations.append(f"tool-argument smuggling in metadata ({label})")

        if isinstance(metadata, Mapping):
            target = metadata.get("target")
            if target is not None:
                tstr = str(target)
                if self._allowed_targets is not None and tstr not in self._allowed_targets:
                    violations.append(f"target {tstr!r} is out of scope")
                for pat, label in _SMUGGLING_PATTERNS:
                    if pat.search(tstr):
                        violations.append(f"tool-argument smuggling in target ({label})")
                for sig in self._scanner.scan(tstr):
                    violations.append(f"prompt-injection marker in target: {sig.category.value}")

        seen: set[str] = set()
        deduped: list[str] = []
        for v in violations:
            if v in seen:
                continue
            seen.add(v)
            deduped.append(v)

        passed = not deduped
        sanitized = None
        if passed:
            sanitized = {
                "action": action_str,
                "summary": summary_str,
                "metadata": metadata,
            }
        return OutputValidationResult(passed=passed, violations=deduped, sanitized=sanitized)

    def __call__(self, *args: Any, **kwargs: Any) -> OutputValidationResult:
        return self.validate(*args, **kwargs)


def validate_output(
    action_or_result: Any,
    summary: Any = None,
    metadata: Any = None,
    *,
    allowed_intents: Iterable[str] | None = None,
    allowed_targets: Iterable[str] | None = None,
    max_summary_length: int = DEFAULT_MAX_SUMMARY_LENGTH,
    max_action_length: int = DEFAULT_MAX_ACTION_LENGTH,
    max_metadata_bytes: int = DEFAULT_MAX_METADATA_BYTES,
) -> OutputValidationResult:
    validator = OutputValidator(
        allowed_intents=allowed_intents,
        allowed_targets=allowed_targets,
        max_summary_length=max_summary_length,
        max_action_length=max_action_length,
        max_metadata_bytes=max_metadata_bytes,
    )
    return validator.validate(action_or_result, summary, metadata)