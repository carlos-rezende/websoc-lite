from __future__ import annotations

from typing import Any

from scanner.core.models import DiffSignal, RiskAssessment


class RiskScoringEngine:
    """Maps behavioral signals to normalized 0.0–1.0 scores with explainable factors."""

    def assess(self, signal: DiffSignal, *, extra_context: dict[str, Any] | None = None) -> RiskAssessment:
        factors: list[dict[str, Any]] = []
        score = 0.0

        w_status = 0.35
        w_struct = 0.18
        w_sem = 0.18
        w_ent = 0.12
        w_size = 0.17

        s1 = signal.status_deviation_score * w_status
        score += s1
        if s1 > 0:
            factors.append(
                {
                    "factor": "status_deviation",
                    "weight": w_status,
                    "contribution": round(s1, 4),
                    "detail": "HTTP status differs between baseline and perturbed response.",
                }
            )

        s2 = signal.structural_diff_score * w_struct
        score += s2
        if s2 > 0.02:
            factors.append(
                {
                    "factor": "structural_diff",
                    "weight": w_struct,
                    "contribution": round(s2, 4),
                    "detail": "Line-level structure diverged between responses.",
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
                    "detail": "Character-level content similarity decreased.",
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
                    "detail": "Shannon entropy of body changed relative to baseline.",
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
                    "detail": "Response body size changed versus baseline.",
                }
            )

        if extra_context:
            if extra_context.get("has_reflection"):
                bump = 0.12
                score += bump
                factors.append(
                    {
                        "factor": "reflection_context",
                        "weight": bump,
                        "contribution": round(bump, 4),
                        "detail": "Probe token reflected in output (contextual modifier).",
                    }
                )

        score = min(1.0, round(score, 4))
        return RiskAssessment(score=score, reasoning_factors=factors)
