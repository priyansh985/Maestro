"""Research Agent MVP (BP9).

A cited-report agent where external content is quarantined by default and
never becomes authority without independent citation verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from maestro.agent.reasoning import ReasoningResult
from maestro.platform.agent_platform import AgentPlatform
from maestro.telemetry.detection import Alert


@dataclass(frozen=True)
class ResearchAction:
    """A validated research action proposal."""
    action: str
    query: str | None = None
    source_id: str | None = None
    content: str | None = None
    args: dict[str, Any] | None = None


class ResearchReasoner:
    """Reasoner for the research agent using strict RAG with citation verification.

    The agent proposes research actions; the CitationVerifier (environmental verifier)
    enforces source grounding as a hard gate — uncited/hallucinated claims hard-fail.
    """

    RESEARCH_VOCABULARY = (
        "research_search", "research_fetch", "research_cite", "research_synthesize"
    )

    def __init__(self, allowed_sources: tuple[str, ...] = ()):
        self.allowed_sources = allowed_sources
        self._step_count = 0
        self._max_steps = 8

    def reason(self, alert: Alert, ctx: dict | None = None) -> ReasoningResult:
        """Analyze the research task and propose a bounded action."""
        self._step_count += 1

        if self._step_count > self._max_steps:
            return ReasoningResult(
                summary="Max reasoning steps reached. Escalating to human.",
                severity=alert.severity,
                action="noop"
            )

        task = ctx.get("task", "") if ctx else ""
        sources = ctx.get("sources", []) if ctx else []
        citations = ctx.get("citations", []) if ctx else []

        # If we have sources but no citations, propose citation verification
        if sources and not citations:
            return ReasoningResult(
                summary="Sources retrieved. Proposing citation verification.",
                severity=alert.severity,
                action="research_cite",
                metadata={"source_count": len(sources)}
            )

        # If citations exist but not all claims cited, request more citations
        if citations and ctx and ctx.get("uncited_claims"):
            return ReasoningResult(
                summary="Uncited claims detected. Requesting additional citations.",
                severity=alert.severity,
                action="research_fetch",
                metadata={"missing_citations": len(ctx.get("uncited_claims", []))}
            )

        # If we have verified citations, synthesize
        if citations and (not ctx or not ctx.get("uncited_claims")):
            return ReasoningResult(
                summary="All claims cited. Proposing report synthesis.",
                severity=0.1,
                action="research_synthesize",
                metadata={"citation_count": len(citations)}
            )

        # Default: search for sources
        if not sources:
            return ReasoningResult(
                summary="No sources in context. Proposing search.",
                severity=alert.severity,
                action="research_search",
                metadata={"query": task[:100]}
            )

        return ReasoningResult(
            summary="Research in progress. Fetching additional sources.",
            severity=alert.severity,
            action="research_fetch",
            metadata={"current_sources": len(sources)}
        )


def create_research_agent(
    tenant: str = "default",
    controller: str = "human:operator",
    allowed_sources: tuple[str, ...] = ()
) -> AgentPlatform:
    """Instantiate the Research Agent with restricted vocabulary."""
    from maestro.platform.agent_platform import AgentPlatform

    vocabulary = list(ResearchReasoner.RESEARCH_VOCABULARY)
    return AgentPlatform(
        reasoner=ResearchReasoner(allowed_sources=allowed_sources),
        tenant=tenant,
        controller=controller,
        agent_id="agent:research:run",
        allowed_intents=vocabulary,
    )


# Export the vocabulary for capability mapping
RESEARCH_INTENTS = ResearchReasoner.RESEARCH_VOCABULARY