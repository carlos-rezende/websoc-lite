from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass(slots=True)
class HTTPResult:
    url: str
    method: str
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    error: str | None = None
    request_fingerprint: str = ""
    response_hash: str = ""
    request_size: int = 0

    @property
    def size(self) -> int:
        return len(self.text.encode("utf-8", errors="ignore"))


@dataclass(slots=True)
class DiffSignal:
    """Structured behavioral signal from baseline vs mutated comparison."""

    structural_diff_score: float
    semantic_divergence_score: float
    entropy_change_ratio: float
    status_deviation_score: float
    size_delta_ratio: float
    baseline_size: int
    mutated_size: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "structural_diff_score": round(self.structural_diff_score, 4),
            "semantic_divergence_score": round(self.semantic_divergence_score, 4),
            "entropy_change_ratio": round(self.entropy_change_ratio, 4),
            "status_deviation_score": round(self.status_deviation_score, 4),
            "size_delta_ratio": round(self.size_delta_ratio, 4),
            "baseline_size": self.baseline_size,
            "mutated_size": self.mutated_size,
        }


@dataclass(slots=True)
class RiskAssessment:
    """Explainable risk: normalized score with human-readable factors."""

    score: float
    reasoning_factors: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "reasoning_factors": list(self.reasoning_factors),
        }


@dataclass(slots=True)
class Finding:
    plugin: str
    target: str
    endpoint: str
    title: str
    description: str
    risk_score: float
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)


@dataclass(slots=True)
class BaselineRecord:
    endpoint_key: str
    status_code: int
    response_size: int
    body_hash: str
    version: int = 1


@dataclass(slots=True)
class EndpointObservation:
    """Per-endpoint observability record for reporting."""

    endpoint: str
    anomaly_score: float
    signal: dict[str, Any]
    risk_reasoning: list[dict[str, Any]]
    probe_token: str | None = None


@dataclass(slots=True)
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    crawled_endpoints: list[str] = field(default_factory=list)
    observations: list[EndpointObservation] = field(default_factory=list)
    event_timeline: list[dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: str | None = None

    def finalize(self) -> None:
        self.finished_at = utc_now_iso()
