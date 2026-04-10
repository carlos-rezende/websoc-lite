from __future__ import annotations

import difflib
import math
from collections import Counter

from scanner.core.models import DiffSignal, HTTPResult


def _shannon_entropy(text: str) -> float:
    raw = text.encode("utf-8", errors="ignore")
    if not raw:
        return 0.0
    counts = Counter(raw)
    n = len(raw)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class DiffEngine:
    """Compares baseline vs mutated responses into a structured Signal."""

    def compare(self, baseline: HTTPResult, mutated: HTTPResult) -> DiffSignal:
        base_size = max(1, baseline.size)
        size_delta_ratio = abs(mutated.size - baseline.size) / base_size

        base_lines = baseline.text.splitlines()[:800]
        mut_lines = mutated.text.splitlines()[:800]
        line_matcher = difflib.SequenceMatcher(a=base_lines, b=mut_lines)
        structural_diff_score = 1.0 - line_matcher.ratio()

        char_matcher = difflib.SequenceMatcher(a=baseline.text[:12000], b=mutated.text[:12000])
        semantic_divergence_score = 1.0 - char_matcher.ratio()

        eb = _shannon_entropy(baseline.text[:20000])
        em = _shannon_entropy(mutated.text[:20000])
        denom = max(eb, 0.01)
        entropy_change_ratio = min(1.0, abs(em - eb) / denom)

        status_deviation_score = 0.0 if baseline.status_code == mutated.status_code else 1.0

        return DiffSignal(
            structural_diff_score=min(1.0, structural_diff_score),
            semantic_divergence_score=min(1.0, semantic_divergence_score),
            entropy_change_ratio=min(1.0, entropy_change_ratio),
            status_deviation_score=status_deviation_score,
            size_delta_ratio=min(1.0, size_delta_ratio),
            baseline_size=baseline.size,
            mutated_size=mutated.size,
        )
