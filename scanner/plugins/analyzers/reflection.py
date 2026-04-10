from __future__ import annotations

from scanner.core.models import DiffSignal, Finding, HTTPResult, RiskAssessment
from scanner.core.risk import RiskScoringEngine
from scanner.plugins.base import AnalyzerPlugin


class ReflectionAnalyzer(AnalyzerPlugin):
    name = "analyzer.reflection"

    def __init__(self) -> None:
        self.risk = RiskScoringEngine()

    async def analyze(
        self,
        target: str,
        endpoint: str,
        baseline: HTTPResult,
        mutated: HTTPResult,
        signal: DiffSignal,
        probe_token: str,
        *,
        risk_assessment: RiskAssessment | None = None,
    ) -> list[Finding]:
        if probe_token not in mutated.text:
            return []

        assessment = self.risk.assess(signal, extra_context={"has_reflection": True})
        return [
            Finding(
                plugin=self.name,
                target=target,
                endpoint=endpoint,
                title="Reflected probe token observed",
                description="Probe token appeared in response output (reflective behavior).",
                risk_score=assessment.score,
                evidence={
                    "probe_token": probe_token,
                    "signal_breakdown": signal.as_dict(),
                    "reasoning": assessment.reasoning_factors,
                },
            )
        ]
