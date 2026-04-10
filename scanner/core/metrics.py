"""Métricas leves SOC v2 (contadores em memória + export JSON)."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MetricsRegistry:
    """Registo thread-safe de contadores (adequado a asyncio + workers)."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    requests_total: int = 0
    anomalies_detected: int = 0
    events_emitted: int = 0
    events_dropped: int = 0
    pipeline_latency_ms_sum: float = 0.0
    pipeline_latency_samples: int = 0
    crawl_depth_max: int = 0
    baseline_cache_hits: int = 0
    queue_depth_max: int = 0
    correlation_incidents: int = 0

    def inc(self, name: str, delta: int = 1) -> None:
        with self._lock:
            cur = getattr(self, name, None)
            if isinstance(cur, int):
                setattr(self, name, cur + delta)

    def observe_latency_ms(self, ms: float) -> None:
        with self._lock:
            self.pipeline_latency_ms_sum += ms
            self.pipeline_latency_samples += 1

    def max_queue_depth(self, depth: int) -> None:
        with self._lock:
            if depth > self.queue_depth_max:
                self.queue_depth_max = depth

    def max_crawl_depth(self, depth: int) -> None:
        with self._lock:
            if depth > self.crawl_depth_max:
                self.crawl_depth_max = depth

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            avg_lat = (
                self.pipeline_latency_ms_sum / self.pipeline_latency_samples
                if self.pipeline_latency_samples
                else 0.0
            )
            return {
                "requests_total": self.requests_total,
                "anomalies_detected": self.anomalies_detected,
                "events_emitted": self.events_emitted,
                "events_dropped": self.events_dropped,
                "pipeline_latency_ms_avg": round(avg_lat, 4),
                "pipeline_latency_samples": self.pipeline_latency_samples,
                "crawl_depth_max": self.crawl_depth_max,
                "baseline_cache_hits": self.baseline_cache_hits,
                "queue_depth_max_observed": self.queue_depth_max,
                "correlation_incidents": self.correlation_incidents,
            }

    def dump_json(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


def merge_metrics_json(path: str | Path, extra: dict[str, Any]) -> None:
    p = Path(path)
    base: dict[str, Any] = {}
    if p.exists():
        try:
            base = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            base = {}
    base.update(extra)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(base, indent=2), encoding="utf-8")
