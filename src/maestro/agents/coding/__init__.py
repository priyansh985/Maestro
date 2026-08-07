"""Secure Coding Agent MVP (BP8).

A PR-only agent that opens PRs but cannot merge without approval.
All tool calls are capability-gated through the enforcement plane.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from maestro.agent.reasoning import ReasoningResult
from maestro.platform.agent_platform import AgentPlatform
from maestro.telemetry.detection import Alert


@dataclass(frozen=True)
class CodingAction:
    """A validated coding action proposal."""
    action: str
    path: str
    content: str | None = None
    command: str | None = None
    args: dict[str, Any] | None = None


class CodingReasoner:
    """Reasoner for the coding agent using ReAct pattern with sandbox verification.

    The agent proposes code changes; the TestSuiteVerifier (environmental verifier)
    runs tests as a hard gate before any action is authorized.
    """

    CODING_VOCABULARY = (
        "code_read", "code_write", "code_test", "code_lint",
        "code_git_status", "code_git_diff", "code_git_push", "code_open_pr"
    )

    def __init__(self, repo_root: str, allowed_paths: tuple[str, ...] = ()):
        self.repo_root = repo_root
        self.allowed_paths = allowed_paths or (repo_root,)
        self._step_count = 0
        self._max_steps = 10

    def reason(self, alert: Alert, ctx: dict | None = None) -> ReasoningResult:
        """Analyze the coding task and propose a bounded action."""
        self._step_count += 1

        if self._step_count > self._max_steps:
            return ReasoningResult(
                summary="Max reasoning steps reached. Escalating to human.",
                severity=alert.severity,
                action="noop"
            )

        task = ctx.get("task", "") if ctx else ""
        files = ctx.get("files", []) if ctx else []
        test_results = ctx.get("test_results", {}) if ctx else {}

        # If tests failed previously, propose a fix
        if test_results.get("failed"):
            return self._propose_fix(alert, task, files, test_results)

        # If tests passed and we have files, propose PR
        if files and test_results.get("passed"):
            return ReasoningResult(
                summary="Tests passing. Proposing PR creation.",
                severity=0.1,
                action="code_open_pr",
                metadata={"title": f"Fix: {task[:50]}"}
            )

        # If no files yet, explore
        if not files:
            return ReasoningResult(
                summary="No files in context. Proposing repository exploration.",
                severity=alert.severity,
                action="code_read",
                metadata={"path": self.repo_root}
            )

        # Default: run tests as verification gate
        return ReasoningResult(
            summary="Proposing test run to verify current state.",
            severity=alert.severity,
            action="code_test",
            metadata={"path": self.repo_root}
        )

    def _propose_fix(
        self,
        alert: Alert,
        task: str,
        files: list[str],
        test_results: dict
    ) -> ReasoningResult:
        """Propose a targeted fix based on test failures."""
        failed_tests = test_results.get("failed", [])
        if not failed_tests:
            return ReasoningResult(
                summary="Tests passing. Proposing PR creation.",
                severity=0.1,
                action="code_open_pr",
                metadata={"title": f"Fix: {task[:50]}"}
            )

        # Pick first failed test's file
        target_file = failed_tests[0].get("file", files[0] if files else self.repo_root)

        return ReasoningResult(
            summary=f"Test failure in {target_file}. Proposing code edit.",
            severity=alert.severity,
            action="code_write",
            metadata={
                "path": target_file,
                "intent": f"Fix failing test: {failed_tests[0].get('name', 'unknown')}"
            }
        )


def create_coding_agent(
    tenant: str = "default",
    controller: str = "human:operator",
    repo_root: str = ".",
    allowed_paths: tuple[str, ...] = ()
) -> AgentPlatform:
    """Instantiate the Secure Coding Agent with restricted vocabulary."""
    from maestro.platform.agent_platform import AgentPlatform

    vocabulary = list(CodingReasoner.CODING_VOCABULARY)
    return AgentPlatform(
        reasoner=CodingReasoner(repo_root=repo_root, allowed_paths=allowed_paths),
        tenant=tenant,
        controller=controller,
        agent_id="agent:secure-coding:run",
        allowed_intents=vocabulary,
    )


# Export the vocabulary for capability mapping
CODING_INTENTS = CodingReasoner.CODING_VOCABULARY