from __future__ import annotations

from scanner.core.models import DiffSignal, Finding, HTTPResult, RiskAssessment
from scanner.plugins.base import AnalyzerPlugin


class SimpleExampleAnalyzer(AnalyzerPlugin):
    """Example analyzer: surfaces high-level risk when assessment exceeds a soft threshold."""

    name = "plugin.analyzer.simple_example"

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
        if risk_assessment is None or risk_assessment.score < 0.55:
            return []
        return [
            Finding(
                plugin=self.name,
                target=target,
                endpoint=endpoint,
                title="Elevated behavioral score (example plugin)",
                description="Composite risk from diff engine exceeded the example analyzer threshold.",
                risk_score=risk_assessment.score,
                evidence={"risk": risk_assessment.as_dict(), "signal": signal.as_dict()},
            )
        ]
