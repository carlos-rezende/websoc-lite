from __future__ import annotations

import difflib
import math
import re
from collections import Counter

from scanner.core.models import DiffSignal, HTTPResult

_TAG_RE = re.compile(r"<[a-zA-Z][^>]*>", re.MULTILINE)


def _shannon_entropy(text: str) -> float:
    raw = text.encode("utf-8", errors="ignore")
    if not raw:
        return 0.0
    counts = Counter(raw)
    n = len(raw)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _html_tag_count(text: str) -> int:
    return len(_TAG_RE.findall(text[:200_000]))


class DiffEngine:
    """Compares baseline vs mutated responses into a structured DiffSignal (metadata-centric)."""

    def compare(
        self,
        baseline: HTTPResult,
        mutated: HTTPResult,
        *,
        probe_token: str | None = None,
    ) -> DiffSignal:
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

        bh = (baseline.response_hash or "").strip()
        mh = (mutated.response_hash or "").strip()
        content_hash_divergence_score = 0.0 if bh and mh and bh == mh else (1.0 if bh or mh else 0.0)

        reflection_signal_score = 0.0
        if probe_token and probe_token in mutated.text:
            reflection_signal_score = 1.0

        tb = _html_tag_count(baseline.text)
        tm = _html_tag_count(mutated.text)
        tag_denom = max(tb, tm, 1)
        html_structural_change_score = min(1.0, abs(tm - tb) / tag_denom)

        return DiffSignal(
            structural_diff_score=min(1.0, structural_diff_score),
            semantic_divergence_score=min(1.0, semantic_divergence_score),
            entropy_change_ratio=min(1.0, entropy_change_ratio),
            status_deviation_score=status_deviation_score,
            size_delta_ratio=min(1.0, size_delta_ratio),
            baseline_size=baseline.size,
            mutated_size=mutated.size,
            content_hash_divergence_score=content_hash_divergence_score,
            reflection_signal_score=reflection_signal_score,
            html_structural_change_score=html_structural_change_score,
        )
