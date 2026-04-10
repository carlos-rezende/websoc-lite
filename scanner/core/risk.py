from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from scanner.core.models import DiffSignal, RiskAssessment


def _endpoint_sensitivity_score(endpoint: str | None) -> float:
    if not endpoint:
        return 0.0
    path = (urlparse(endpoint).path or "").lower()
    markers = ("/admin", "/api", "/login", "/auth", "/oauth", "/account", "/session", "/graphql", "/.well-known")
    return 0.2 if any(m in path for m in markers) else 0.0


class RiskScoringEngine:
    """Maps behavioral signals to normalized 0.0–1.0 scores with explainable factors (no black-box)."""

    def assess(
        self,
        signal: DiffSignal,
        *,
        extra_context: dict[str, Any] | None = None,
        endpoint: str | None = None,
    ) -> RiskAssessment:
        factors: list[dict[str, Any]] = []
        score = 0.0

        w_status = 0.22
        w_struct = 0.10
        w_sem = 0.10
        w_ent = 0.08
        w_size = 0.09
        w_hash = 0.12
        w_refl = 0.12
        w_html = 0.09
        w_sens = 0.08

        s1 = signal.status_deviation_score * w_status
        score += s1
        if s1 > 0:
            factors.append(
                {
                    "factor": "status_deviation",
                    "weight": w_status,
                    "contribution": round(s1, 4),
                    "detail": "Código HTTP diferente entre baseline e resposta perturbada.",
                }
            )

        s2 = signal.structural_diff_score * w_struct
        score += s2
        if s2 > 0.02:
            factors.append(
                {
                    "factor": "structural_html_text_diff",
                    "weight": w_struct,
                    "contribution": round(s2, 4),
                    "detail": "Estrutura por linhas divergiu (similaridade de sequência).",
                }
            )

        s3 = signal.semantic_divergence_score * w_sem
        score += s3
        if s3 > 0.02:
            factors.append(
                {
                    "factor": "semantic_divergence",
                    "weight": w_sem,
                    "contribution": round(s3, 4),
                    "detail": "Corpo textual divergiu ao nível de caracteres.",
                }
            )

        s4 = signal.entropy_change_ratio * w_ent
        score += s4
        if s4 > 0.02:
            factors.append(
                {
                    "factor": "entropy_shift",
                    "weight": w_ent,
                    "contribution": round(s4, 4),
                    "detail": "Entropia de Shannon do corpo alterada relativamente ao baseline.",
                }
            )

        s5 = signal.size_delta_ratio * w_size
        score += s5
        if s5 > 0.02:
            factors.append(
                {
                    "factor": "size_delta",
                    "weight": w_size,
                    "contribution": round(s5, 4),
                    "detail": "Variação relativa do tamanho da resposta.",
                }
            )

        s6 = signal.content_hash_divergence_score * w_hash
        score += s6
        if s6 > 0.02:
            factors.append(
                {
                    "factor": "content_hash_divergence",
                    "weight": w_hash,
                    "contribution": round(s6, 4),
                    "detail": "Hash do corpo diferente — instabilidade de payload.",
                }
            )

        s7 = signal.reflection_signal_score * w_refl
        score += s7
        if s7 > 0.02:
            factors.append(
                {
                    "factor": "reflection_probability",
                    "weight": w_refl,
                    "contribution": round(s7, 4),
                    "detail": "Probabilidade de reflexão de token de sonda na resposta.",
                }
            )

        s8 = signal.html_structural_change_score * w_html
        score += s8
        if s8 > 0.02:
            factors.append(
                {
                    "factor": "html_structure_change",
                    "weight": w_html,
                    "contribution": round(s8, 4),
                    "detail": "Mudança na contagem aproximada de tags HTML.",
                }
            )

        sens = _endpoint_sensitivity_score(endpoint)
        s9 = sens * w_sens
        score += s9
        if s9 > 0.02:
            factors.append(
                {
                    "factor": "endpoint_sensitivity_heuristic",
                    "weight": w_sens,
                    "contribution": round(s9, 4),
                    "detail": "Caminho sugere superfície sensível (heurística, não confirmação).",
                }
            )

        if extra_context:
            freq = float(extra_context.get("anomaly_frequency") or 0.0)
            if freq > 0:
                bump = min(0.15, freq * 0.1)
                score += bump
                factors.append(
                    {
                        "factor": "anomaly_frequency_prior",
                        "weight": bump,
                        "contribution": round(bump, 4),
                        "detail": "Correlação histórica opcional de frequência de anomalias no endpoint.",
                    }
                )
            hist = float(extra_context.get("historical_correlation_score") or 0.0)
            if hist > 0:
                bump2 = min(0.1, hist)
                score += bump2
                factors.append(
                    {
                        "factor": "historical_correlation_signal",
                        "weight": bump2,
                        "contribution": round(bump2, 4),
                        "detail": "Sinal de correlação armazenado (ex.: estado anterior).",
                    }
                )
            if extra_context.get("response_instability_proxy"):
                inst = float(extra_context["response_instability_proxy"])
                bump3 = min(0.08, inst * 0.08)
                score += bump3
                factors.append(
                    {
                        "factor": "response_instability",
                        "weight": bump3,
                        "contribution": round(bump3, 4),
                        "detail": "Proxy de instabilidade agregada (semântica + estrutura).",
                    }
                )

        score = min(1.0, round(score, 4))
        return RiskAssessment(score=score, reasoning_factors=factors)
