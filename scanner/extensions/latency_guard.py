from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from scanner.extensions.base import ExperimentalExtension


class LatencyGuardExtension(ExperimentalExtension):
    """
    Example experimental extension:
    - listens only to bus events
    - emits isolated artifacts under reports/extensions
    """

    name = "extension.latency_guard"

    def __init__(self) -> None:
        self._slow_hits = 0
        self._total = 0
        self._threshold_ms = 1200.0

    async def on_event(self, event_name: str, payload: dict[str, Any]) -> None:
        if event_name != "response_received":
            return
        telemetry = payload.get("telemetry", {})
        response = telemetry.get("response", {}) if isinstance(telemetry, dict) else {}
        elapsed_ms = float(response.get("elapsed_ms", 0.0) or 0.0)
        endpoint = str(payload.get("endpoint", ""))
        self._total += 1
        if elapsed_ms < self._threshold_ms:
            return
        self._slow_hits += 1
        self._append_alert(
            {
                "event": event_name,
                "endpoint": endpoint,
                "elapsed_ms": elapsed_ms,
                "threshold_ms": self._threshold_ms,
                "slow_hits": self._slow_hits,
                "total_responses": self._total,
            }
        )

    def _append_alert(self, payload: dict[str, Any]) -> None:
        base = os.environ.get("SOC_REPORTS_DIR") or os.environ.get("REPORTS_DIR") or "reports"
        out = Path(base) / "extensions"
        out.mkdir(parents=True, exist_ok=True)
        with (out / "latency_guard.ndjson").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=True) + "\n")
