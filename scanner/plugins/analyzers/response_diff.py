from __future__ import annotations

from scanner.core.models import DiffSignal, Finding, HTTPResult, RiskAssessment
from scanner.core.risk import RiskScoringEngine
from scanner.plugins.base import AnalyzerPlugin


class ResponseDiffAnalyzer(AnalyzerPlugin):
    name = "analyzer.response_diff"

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
        if not (signal.status_deviation_score > 0 or signal.size_delta_ratio > 0.2 or signal.semantic_divergence_score > 0.25):
            return []

        assessment = risk_assessment or self.risk.assess(signal)
        return [
            Finding(
                plugin=self.name,
                target=target,
                endpoint=endpoint,
                title="Behavioral response anomaly detected",
                description="Baseline and perturbed response diverged beyond soft thresholds.",
                risk_score=assessment.score,
                evidence={
                    "baseline_status": baseline.status_code,
                    "mutated_status": mutated.status_code,
                    "signal_breakdown": signal.as_dict(),
                    "reasoning": assessment.reasoning_factors,
                },
            )
        ]
