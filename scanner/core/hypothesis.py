"""Hypothesis generation from behavioral signals — structured suggestions for manual validation only."""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

from scanner.core.models import DiffSignal, HTTPResult, Hypothesis, RiskAssessment


def _endpoint_sensitivity_hint(endpoint: str) -> float:
    path = (urlparse(endpoint).path or "").lower()
    sensitive = ("/admin", "/api", "/login", "/auth", "/oauth", "/account", "/session", "/graphql", "/.well-known")
    return 0.25 if any(s in path for s in sensitive) else 0.0


class HypothesisEngine:
    """Produces Hypothesis objects from diff + risk context (no exploit confirmation)."""

    def generate(
        self,
        *,
        target: str,
        endpoint: str,
        baseline: HTTPResult,
        mutated: HTTPResult,
        signal: DiffSignal,
        assessment: RiskAssessment,
        probe_token: str,
    ) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        sens = _endpoint_sensitivity_hint(endpoint)

        if signal.reflection_signal_score > 0 and probe_token:
            out.append(
                Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    statement=(
                        "Este endpoint pode ser sensível a reflexão de entrada devido à propagação "
                        "repetida de um token de sonda benigno na resposta."
                    ),
                    evidence=[
                        {"type": "reflection", "probe_substring_present": True, "endpoint": endpoint},
                        {"type": "risk_context", "score": assessment.score, "sensitivity_hint": sens},
                    ],
                    confidence=min(0.85, 0.45 + 0.35 * signal.reflection_signal_score + sens),
                    affected_endpoints=[endpoint],
                    recommended_verification_steps=[
                        "Revisão manual da origem da reflexão (template, JSON echo, logs de debug).",
                        "Confirmar se o conteúdo reflectido passa por encoding contextual adequado.",
                        "Evitar confirmação automática de vulnerabilidade — apenas observação comportamental.",
                    ],
                )
            )

        if signal.status_deviation_score > 0:
            out.append(
                Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    statement=(
                        "Divergência de estado HTTP entre baseline e pedido perturbado sugere possível "
                        "inconsistência de limite de autenticação ou ramificação de erros no backend."
                    ),
                    evidence=[
                        {"type": "status_pair", "baseline": baseline.status_code, "mutated": mutated.status_code},
                        {"type": "diff_signal", "status_deviation_score": signal.status_deviation_score},
                    ],
                    confidence=min(0.8, 0.4 + 0.35 * signal.status_deviation_score),
                    affected_endpoints=[endpoint],
                    recommended_verification_steps=[
                        "Repetir pedidos manualmente com o mesmo conjunto de parâmetros seguros.",
                        "Mapear políticas de authz documentadas versus comportamento observado.",
                    ],
                )
            )

        if signal.semantic_divergence_score > 0.2 and signal.content_hash_divergence_score > 0:
            out.append(
                Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    statement=(
                        "A variância de resposta e alteração de hash sugerem lógica de ramificação no "
                        "backend possivelmente acionada por tipo ou forma do parâmetro (análise comportamental)."
                    ),
                    evidence=[
                        {"type": "hash_divergence", "score": signal.content_hash_divergence_score},
                        {"type": "semantic_divergence", "score": signal.semantic_divergence_score},
                    ],
                    confidence=min(
                        0.75,
                        0.35 + 0.2 * signal.semantic_divergence_score + 0.15 * signal.content_hash_divergence_score,
                    ),
                    affected_endpoints=[endpoint],
                    recommended_verification_steps=[
                        "Isolar um único parâmetro de cada vez com valores benignos controlados.",
                        "Documentar diferenças de corpo de resposta sem interpretação de exploit.",
                    ],
                )
            )

        if signal.html_structural_change_score > 0.25:
            out.append(
                Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    statement=(
                        "Alteração estrutural HTML (contagem de tags) entre respostas sugere composição "
                        "dinâmica diferente — útil para investigar fluxos de UI ou mensagens de erro."
                    ),
                    evidence=[
                        {"type": "html_structural_change", "score": signal.html_structural_change_score},
                        {"type": "target", "value": target},
                    ],
                    confidence=min(0.65, 0.3 + 0.35 * signal.html_structural_change_score),
                    affected_endpoints=[endpoint],
                    recommended_verification_steps=[
                        "Comparar HTML renderizado manualmente em browser para o mesmo parâmetro.",
                        "Verificar se mudanças correspondem a estados de formulário ou mensagens.",
                    ],
                )
            )

        if not out and assessment.score >= 0.2:
            out.append(
                Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    statement=(
                        "Sinal comportamental agregado elevado sem padrão específico dominante — "
                        "recomenda-se validação manual focada em consistência de resposta."
                    ),
                    evidence=[
                        {"type": "aggregate_risk", "score": assessment.score},
                        {"type": "signal_summary", "value": signal.as_dict()},
                    ],
                    confidence=min(0.5, 0.2 + 0.5 * assessment.score),
                    affected_endpoints=[endpoint],
                    recommended_verification_steps=[
                        "Reexecutar o cenário com registo de telemetria completo (event timeline).",
                    ],
                )
            )

        return out


def rank_investigation_targets(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic ordering for manual investigation (higher anomaly_score first)."""
    ranked = sorted(observations, key=lambda x: float(x.get("anomaly_score") or 0.0), reverse=True)
    return [
        {
            "rank": i + 1,
            "endpoint": r.get("endpoint"),
            "anomaly_score": r.get("anomaly_score"),
            "rationale": "Ordenado por pontuação de anomalia agregada (observabilidade).",
        }
        for i, r in enumerate(ranked)
    ]
