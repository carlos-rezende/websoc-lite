"""Motor de correlação SOC v2 — padrões temporais e incidentes."""

from __future__ import annotations

import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from scanner.core.events.schema import Severity
from scanner.core.event_bus import INCIDENT_DETECTED, EventBus


@dataclass
class IncidentModel:
    incident_id: str
    correlated_events: list[dict[str, Any]]
    related_event_ids: list[str]
    severity_score: float
    time_window_seconds: float
    timeline_start_iso: str
    timeline_end_iso: str
    affected_endpoints: list[str]
    pattern: str


@dataclass
class _AnomalyRecord:
    ts: datetime
    endpoint: str
    target: str
    score: float
    event_id: str | None = None


class CorrelationEngine:
    """
    Consome eventos de anomalia/risco e emite `incident_detected` quando:
    - ≥N anomalias no mesmo endpoint numa janela temporal, ou
    - pico temporal (≥M anomalias em qualquer endpoint na janela).
    """

    def __init__(
        self,
        bus: EventBus,
        *,
        window_seconds: float = 180.0,
        min_anomalies_same_endpoint: int = 3,
        spike_min_anomalies: int = 5,
        metrics: Any | None = None,
    ) -> None:
        self._bus = bus
        self._window = timedelta(seconds=window_seconds)
        self._min_same = min_anomalies_same_endpoint
        self._spike_min = spike_min_anomalies
        self._metrics = metrics
        self._records: deque[_AnomalyRecord] = deque(maxlen=2000)
        self._emitted_keys: set[str] = set()

    def _prune(self, now: datetime) -> None:
        while self._records and now - self._records[0].ts > self._window:
            self._records.popleft()

    async def handle_anomaly_payload(self, payload: dict[str, Any]) -> None:
        now = datetime.now(tz=timezone.utc)
        endpoint = str(payload.get("endpoint") or "")
        target = str(payload.get("target") or "")
        score = float(payload.get("score") or 0.0)
        eid = str(payload.get("event_id") or "")

        self._prune(now)
        rec = _AnomalyRecord(ts=now, endpoint=endpoint, target=target, score=score, event_id=eid or None)
        self._records.append(rec)

        self._prune(now)
        window_start = now - self._window
        in_win = [r for r in self._records if r.ts >= window_start]

        # Pico global na janela
        if len(in_win) >= self._spike_min:
            key = f"spike:{window_start.isoformat()}"
            if key not in self._emitted_keys:
                self._emitted_keys.add(key)
                await self._emit_incident(
                    pattern="temporal_spike",
                    endpoints=list({r.endpoint for r in in_win if r.endpoint}),
                    records=in_win[-40:],
                    severity_score=min(1.0, len(in_win) / 20.0),
                    window_start=window_start,
                    window_end=now,
                )
            return

        same_ep = [r for r in in_win if r.endpoint == endpoint and endpoint]
        if len(same_ep) >= self._min_same:
            key = f"repeat:{endpoint}:{window_start.isoformat()}"
            if key not in self._emitted_keys:
                self._emitted_keys.add(key)
                await self._emit_incident(
                    pattern="repeated_endpoint_anomalies",
                    endpoints=[endpoint],
                    records=same_ep[-25:],
                    severity_score=min(1.0, max(r.score for r in same_ep)),
                    window_start=window_start,
                    window_end=now,
                )

    async def _emit_incident(
        self,
        *,
        pattern: str,
        endpoints: list[str],
        records: list[_AnomalyRecord],
        severity_score: float,
        window_start: datetime,
        window_end: datetime,
    ) -> None:
        correlated = [
            {
                "event_id": r.event_id,
                "endpoint": r.endpoint,
                "target": r.target,
                "score": r.score,
                "ts": r.ts.isoformat(),
            }
            for r in records
            if r.endpoint or r.target
        ]
        related_ids = [str(x["event_id"]) for x in correlated if x.get("event_id")][-30:]
        inc = IncidentModel(
            incident_id=str(uuid.uuid4()),
            correlated_events=correlated[-40:],
            related_event_ids=related_ids,
            severity_score=round(severity_score, 4),
            time_window_seconds=self._window.total_seconds(),
            timeline_start_iso=window_start.isoformat(),
            timeline_end_iso=window_end.isoformat(),
            affected_endpoints=endpoints,
            pattern=pattern,
        )
        if self._metrics:
            self._metrics.inc("correlation_incidents", 1)
        await self._bus.emit(
            INCIDENT_DETECTED,
            {
                "incident_id": inc.incident_id,
                "correlated_events": inc.correlated_events,
                "related_event_ids": inc.related_event_ids,
                "severity_score": inc.severity_score,
                "time_window_seconds": inc.time_window_seconds,
                "timeline_start_iso": inc.timeline_start_iso,
                "timeline_end_iso": inc.timeline_end_iso,
                "affected_endpoints": inc.affected_endpoints,
                "pattern": inc.pattern,
            },
            source="correlation",
            severity=Severity.HIGH,
        )
