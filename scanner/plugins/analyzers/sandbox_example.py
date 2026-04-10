"""
Exemplo SOC v2: analisador executado via `run_analyzer_sandboxed` no pipeline.

Não importa `StateStore` nem módulos internos do motor — apenas modelos públicos
e a interface `AnalyzerPlugin`. O tempo máximo de execução é imposto pelo sandbox.
"""

from __future__ import annotations

from scanner.core.models import DiffSignal, Finding, HTTPResult, RiskAssessment
from scanner.plugins.base import AnalyzerPlugin


class SandboxFriendlyAnalyzer(AnalyzerPlugin):
    """Retorna um finding apenas quando o sinal estrutural é elevado (exemplo didático)."""

    name = "analyzer.sandbox_example"

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
        if signal.structural_diff_score < 0.5:
            return []
        return [
            Finding(
                plugin=self.name,
                target=target,
                endpoint=endpoint,
                title="Structural divergence (sandbox example)",
                description="Exemplo de plugin compatível com execução em sandbox (sem estado interno do core).",
                risk_score=signal.structural_diff_score,
                evidence={"structural_diff_score": signal.structural_diff_score},
            )
        ]
